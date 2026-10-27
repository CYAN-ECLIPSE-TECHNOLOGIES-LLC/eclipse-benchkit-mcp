import copy
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import benchkit as B  # noqa: E402
import server  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
FIX = os.path.join(ROOT, "fixtures")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = {k: os.environ.get(k) for k in (
            "BENCHKIT_DATA_DIR", "BENCHKIT_KEYS_DIR",
            "BENCHKIT_VERIFIER_TOKEN", "ECLIPSE_BENCHKIT_SURFACE")}
        os.environ["BENCHKIT_DATA_DIR"] = self.tmp.name
        os.environ["BENCHKIT_KEYS_DIR"] = os.path.join(
            self.tmp.name, "keys")
        os.environ.pop("ECLIPSE_BENCHKIT_SURFACE", None)
        # M4: verifier process holds the fixture token from keys/
        os.environ["BENCHKIT_VERIFIER_TOKEN"] = B.verifier_token()

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def run_battery(self, manifest_name, supersedes=None):
        m = load(manifest_name)
        begin = B.run_begin({"server": m["server"],
                             "supersedes": supersedes})
        sid = begin["scorecard_id"]
        for c in m["checks"]:
            desc = {"server_id": m["server"]["server_id"],
                    "tool": c["tool"], "input": c["input"]}
            genuine = B.output_hash(desc)
            observed = B.sha("fabricated-output-" + c["check_id"]) \
                if c.get("fabricated") else genuine
            # a fabricated record is an internally CONSISTENT lie:
            # expected == observed == the fabricated hash, verdict
            # 'pass' - the spot-check re-run of the descriptor (which
            # yields the genuine hash) is what catches it. Setting
            # expected=genuine / observed=fabricated would be a
            # malformed 'pass' record and is refused (minor m1).
            expected = observed
            hook = None
            if not c.get("hookless"):
                hook = {"hook_version": "1.0",
                        "invocation_descriptor": desc,
                        "input_ref_or_inline_hash":
                        B.sha(B.canonical(c["input"])),
                        "expected_output_hash": expected,
                        "determinism_class":
                        c.get("determinism_class", "deterministic"),
                        "seed_if_seeded": None,
                        "timeout_class": "standard"}
                if c.get("requires_secret"):
                    hook["requires_secret"] = True
            out = B.check_record({
                "scorecard_id": sid, "check_id": c["check_id"],
                "invocation_hash": B.sha(B.canonical(desc)),
                "input_hash": B.sha(B.canonical(c["input"])),
                "expected_output_hash": expected,
                "observed_output_hash": observed,
                "verdict_as_run": "fail" if
                c["input"].get("result") == "fail" else "pass",
                "hook": hook,
                "determinism_class":
                c.get("determinism_class", "deterministic"),
                "env_fingerprint": B.sha(m["server"]["server_id"])})
            self.assertIn("record", out, out)
        seal = B.scorecard_seal({"scorecard_id": sid})
        return sid, seal["seal"]

    def presented(self, sid):
        got = B.scorecard_get({"scorecard_id": sid})
        return {"open_record": got["open_record"],
                "records": got["records"], "seal": got["seal"]}

    def verify_flow(self, sid, seal):
        # v0.1.1: no caller nonce - the verifier generates it
        req = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": self.presented(sid)})
        self.assertIn("manifest", req, req)
        run = B.spotcheck_run(
            {"sample_manifest_id": req["manifest"]["manifest_id"]})
        return req, run

    def recompute(self, sid, req, run):
        return B.spotcheck_recompute({
            "receipt": run["receipt"],
            "scorecard": self.presented(sid),
            "outcomes": run["outcomes"],
            "manifest": req["manifest"],
            "verifier_nonce": req["manifest"]["verifier_nonce"]})


class TestHappy(Base):
    def test_f_b1_full_honest_run(self):  # F-B1
        sid, seal = self.run_battery("battery-good-40.json")
        self.assertEqual(seal["check_count"], 40)
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(req["manifest"]["sample_size_k"], 30)
        receipt = run["receipt"]
        self.assertEqual(receipt["verdict"], "VERIFIED_SAMPLE")
        self.assertIn("harness", receipt["signatures"])
        self.assertIn("vendor", receipt["signatures"])
        self.assertEqual(receipt["counter_signatures"], "complete")
        self.assertAlmostEqual(receipt["detection_probability"],
                               0.957609, places=5)
        rec = self.recompute(sid, req, run)
        self.assertTrue(rec["verified"], rec)

    def test_f_b2_small_battery(self):  # F-B2
        sid, seal = self.run_battery("battery-small-8.json")
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(req["manifest"]["sample_size_k"], 8)
        self.assertEqual(run["receipt"]["sample_size_k"], 8)
        self.assertEqual(run["receipt"]["verdict"], "VERIFIED_SAMPLE")

    def test_f_b3_honest_failures_sealed(self):  # F-B3
        sid, seal = self.run_battery("battery-honest-failures.json")
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(run["receipt"]["verdict"], "VERIFIED_SAMPLE")
        fails = [r for r in self.presented(sid)["records"]
                 if r["verdict_as_run"] == "fail"]
        self.assertEqual(len(fails), 3)

    def test_f_b4_idempotent_verification(self):  # F-B4
        sid, seal = self.run_battery("battery-small-8.json")
        req, run = self.verify_flow(sid, seal)
        again = B.spotcheck_run(
            {"sample_manifest_id": req["manifest"]["manifest_id"]})
        self.assertTrue(again["idempotent"])
        self.assertEqual(again["receipt"]["receipt_id"],
                         run["receipt"]["receipt_id"])
        store = B.load_store()
        self.assertEqual(len(store["metering"]), 1)


class TestProtocol(Base):
    def test_f_b5_post_seal_edit(self):  # F-B5
        sid, seal = self.run_battery("battery-small-8.json")
        presented = self.presented(sid)
        presented["records"][0]["observed_output_hash"] = "0" * 64
        req = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": presented})
        self.assertEqual(req["refusal"], "SEAL_INVALID")
        store = B.load_store()
        store["scorecards"][sid]["records"][0][
            "observed_output_hash"] = "0" * 64
        B.save_store(store)
        exp = B.export_get({"scorecard_id": sid})
        self.assertEqual(exp["export_label"], "DOWNGRADED_EXPORT")
        self.assertEqual(exp["downgrade_reason"], "SEAL_BROKEN")

    def test_f_b6_pre_seal_sample_attempt(self):  # F-B6
        m = load("battery-small-8.json")
        B.run_begin({"server": m["server"]})
        req = B.spotcheck_request({
            "scorecard_hash": "a" * 64,
            "scorecard": {"open_record": None, "records": [],
                          "seal": None}})
        self.assertEqual(req["refusal"], "PRE_SEAL_SAMPLE")
        queue = B.anomaly_queue_read({})
        self.assertTrue(any(a["code"] == "PRE_SEAL_SAMPLE"
                            for a in queue["anomalies"]))

    def test_f_b7_vendor_supplied_nonce(self):  # F-B7
        sid, seal = self.run_battery("battery-small-8.json")
        req = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": self.presented(sid),
            "vendor_nonce": "vendor-chosen"})
        self.assertEqual(req["refusal"], "VENDOR_NONCE_REFUSED")

    def test_f_b8_redraw_replay_and_new_lineage(self):  # F-B8 + m5
        sid, seal = self.run_battery("battery-fabricated-40.json")
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(run["receipt"]["verdict"], "DIVERGENT")
        nonce = req["manifest"]["verifier_nonce"]
        # m5 / spec 3.3: identical (scorecard_hash, verifier_nonce)
        # resubmission RETURNS the recorded receipt - no second
        # sample, no second metering event, no REDRAW_REFUSED
        replay = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": self.presented(sid),
            "verifier_nonce": nonce})
        self.assertTrue(replay["idempotent_replay"], replay)
        self.assertEqual(replay["receipt"]["receipt_id"],
                         run["receipt"]["receipt_id"])
        store = B.load_store()
        self.assertEqual(len(store["manifests"]), 1)
        self.assertEqual(len(store["metering"]), 1)
        # a new verification is a fresh verifier-generated draw;
        # m3: prior_verdict is DERIVED from stored receipts even
        # when the caller lies about it
        req2 = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": self.presented(sid),
            "prior_verdict": "VERIFIED_SAMPLE"})
        self.assertIn("manifest", req2)
        self.assertEqual(req2["manifest"]["prior_verdict"],
                         "DIVERGENT")
        self.assertNotEqual(req2["manifest"]["verifier_nonce"],
                            nonce)


class TestHooks(Base):
    def test_f_b9_hookless_excluded(self):  # F-B9
        sid, seal = self.run_battery("battery-hookless.json")
        self.assertEqual(seal["hookless_count"], 5)
        self.assertEqual(seal["hook_bearing_count"], 7)
        req, run = self.verify_flow(sid, seal)
        sampled = req["manifest"]["sampled_check_ids"]
        self.assertEqual(len(sampled), 7)
        self.assertFalse(any(s.startswith("chk-hook-0") and
                             int(s[-2:]) <= 5 for s in sampled))

    def test_f_b10_nondeterministic_unverifiable(self):  # F-B10
        sid, seal = self.run_battery("battery-flaky.json")
        req, run = self.verify_flow(sid, seal)
        self.assertIn("chk-flaky-03",
                      req["manifest"]["sampled_check_ids"])
        self.assertEqual(run["receipt"]["verdict"], "UNVERIFIABLE")
        self.assertIn("chk-flaky-03",
                      run["receipt"]["unverifiable_check_ids"])

    def test_f_b11_unrunnable_hook(self):  # F-B11
        sid, seal = self.run_battery("battery-secret-hook.json")
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(run["receipt"]["verdict"], "UNVERIFIABLE")
        self.assertIn("chk-secret-04",
                      run["receipt"]["unverifiable_check_ids"])


class TestDecisive(Base):
    def test_f_b12_fabricated_caught(self):  # F-B12 decisive
        sid, seal = self.run_battery("battery-fabricated-40.json")
        req, run = self.verify_flow(sid, seal)
        receipt = run["receipt"]
        self.assertEqual(receipt["verdict"], "DIVERGENT")
        self.assertGreaterEqual(len(receipt["mismatched_check_ids"]), 1)
        fabricated = {f"chk-fab-{i:02d}" for i in range(1, 13)}
        self.assertTrue(set(receipt["mismatched_check_ids"]) <=
                        fabricated)
        rec = self.recompute(sid, req, run)
        self.assertTrue(rec["verified"], rec)
        self.assertAlmostEqual(1 - 0.7 ** 30, 0.999975, places=5)

    def test_f_b13_downgrade_terminal_new_lineage(self):  # F-B13
        sid, seal = self.run_battery("battery-small-8.json")
        store = B.load_store()
        store["scorecards"][sid]["records"][0][
            "observed_output_hash"] = "0" * 64
        B.save_store(store)
        exp = B.export_get({"scorecard_id": sid})
        self.assertEqual(exp["export_label"], "DOWNGRADED_EXPORT")
        req = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": exp})
        self.assertIn("refusal", req)
        sid2, seal2 = self.run_battery("battery-small-8.json",
                                       supersedes=sid)
        req2, run2 = self.verify_flow(sid2, seal2)
        self.assertEqual(run2["receipt"]["verdict"],
                         "VERIFIED_SAMPLE")


class TestFixRegressions(Base):
    """One regression test per Verity probe (bench-benchkit.md)."""

    def test_d1_sample_not_precomputable(self):
        # Verity probe: auto nonce was sha256(hash+counter=1) and
        # the exact sample was predicted before reveal. Post-fix
        # that precomputation must FAIL.
        sid, seal = self.run_battery("battery-good-40.json")
        h = seal["scorecard_hash"]
        predicted_nonce = B.sha("verifier-nonce" + h + "1")[:32]
        predicted_seed = B.sha(h + "|" + predicted_nonce)
        records = self.presented(sid)["records"]
        predicted_sample = B._sample_ids(records, predicted_seed,
                                         B.DEFAULT_K)
        req, run = self.verify_flow(sid, seal)
        self.assertNotEqual(req["manifest"]["verifier_nonce"],
                            predicted_nonce)
        self.assertNotEqual(req["manifest"]["sampled_check_ids"],
                            predicted_sample)
        # a second draw uses fresh entropy: nonces differ
        req2 = B.spotcheck_request({
            "scorecard_hash": h, "scorecard": self.presented(sid)})
        self.assertNotEqual(req2["manifest"]["verifier_nonce"],
                            req["manifest"]["verifier_nonce"])
        self.assertIn("verifier_seed_commitment",
                      req["manifest"])

    def test_d1_supplied_nonce_cannot_draw_or_grind(self):
        sid, seal = self.run_battery("battery-small-8.json")
        for chosen in ("attacker-chosen", "0" * 32, "nonce-fixture-1"):
            req = B.spotcheck_request({
                "scorecard_hash": seal["scorecard_hash"],
                "scorecard": self.presented(sid),
                "verifier_nonce": chosen})
            self.assertEqual(req["refusal"],
                             "VERIFIER_NONCE_REFUSED", req)
        self.assertEqual(len(B.load_store()["manifests"]), 0)

    def test_d2_f_b14_fence_battery(self):  # F-B14
        cases = [
            ({"endpoint": "https://vendor.example.com/mcp"},
             "non-local-endpoint"),
            ({"live_key": "plain-live-secret"}, "live-key"),
            ({"api_key": "sk-live-abcdef"}, "live-key"),
            ({"vendor_nonce": "vendor-chosen"}, "vendor-nonce"),
            ({"value_class": "production"}, "value-class"),
            ({"note": "Assay price $500 with checkout"},
             "assay-cupel-price-or-checkout"),
            ({"note": "Cupel licence for sale"},
             "assay-cupel-price-or-checkout"),
        ]
        for cfg, cls in cases:
            self.assertEqual(B.check_config(cfg),
                             "CONFIG_FENCE_REFUSED:" + cls, cfg)
        self.assertIsNone(B.check_config(
            {"server_id": "good", "value_class": "test"}))
        # live-URL descriptor refused at run_begin
        out = B.run_begin({"server": {
            "server_id": "evil",
            "url": "https://vendor.example.com/mcp"}})
        self.assertEqual(out["refusal"],
                         "CONFIG_FENCE_REFUSED:non-local-endpoint")
        # startup fence: fresh process hard-exits, class named
        triggers = [
            ({"BENCHKIT_ENDPOINT":
              "https://vendor.example.com/mcp"},
             "CONFIG_FENCE_REFUSED:non-local-endpoint"),
            ({"BENCHKIT_API_KEY": "sk-live-abcdef"},
             "CONFIG_FENCE_REFUSED:live-key"),
            ({"BENCHKIT_VENDOR_NONCE": "vendor-chosen"},
             "CONFIG_FENCE_REFUSED:vendor-nonce"),
            ({"BENCHKIT_ASSAY_PRICE": "$500"},
             "CONFIG_FENCE_REFUSED:assay-cupel-price-or-checkout"),
        ]
        srv = os.path.join(ROOT, "server.py")
        for extra, code in triggers:
            env = {"PATH": os.environ.get("PATH", ""),
                   "BENCHKIT_DATA_DIR": self.tmp.name,
                   "BENCHKIT_KEYS_DIR": os.path.join(
                       self.tmp.name, "keys"), **extra}
            p = subprocess.run([sys.executable, srv], input="",
                               capture_output=True, text=True,
                               env=env, timeout=30)
            self.assertNotEqual(p.returncode, 0, (extra, p.stdout))
            self.assertIn(code, p.stderr, (extra, p.stderr))

    def test_m1_tampered_seal_counts_no_manifest(self):
        sid, seal = self.run_battery("battery-small-8.json")
        presented = self.presented(sid)
        presented["seal"] = {**presented["seal"],
                             "check_count": 999,
                             "hook_bearing_count": 999,
                             "hookless_count": 0,
                             "format_version": "9.9"}
        req = B.spotcheck_request({
            "scorecard_hash": seal["scorecard_hash"],
            "scorecard": presented})
        self.assertEqual(req["refusal"], "SEAL_INVALID")
        self.assertEqual(len(B.load_store()["manifests"]), 0)
        # recompute also rejects the tampered seal at step 1
        rec = B.spotcheck_recompute({
            "receipt": {"scorecard_hash": seal["scorecard_hash"]},
            "scorecard": presented, "outcomes": [],
            "verifier_nonce": "x"})
        self.assertFalse(rec["verified"])
        self.assertEqual(rec["error"], "BENCHKIT_VERIFY_FAIL:1")

    def test_m2_forged_receipt_outcomes_pair_fails(self):
        sid, seal = self.run_battery("battery-fabricated-40.json")
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(run["receipt"]["verdict"], "DIVERGENT")
        # genuine artefacts verify first (control)
        self.assertTrue(self.recompute(sid, req, run)["verified"])
        # forge a consistent pair: outcomes rewritten to all-MATCH
        # with a correctly re-computed chain, receipt rewritten to
        # VERIFIED_SAMPLE with the forged rerun head - but neither
        # can be re-signed without the keys in keys/
        by_id = {r["check_id"]: r
                 for r in self.presented(sid)["records"]}
        forged_outcomes, prev = [], seal["scorecard_hash"]
        for out in run["outcomes"]:
            o = {k: v for k, v in out.items()
                 if k != "record_hash"}
            o["rerun_output_hash"] = by_id[o["check_id"]][
                "observed_output_hash"]
            o["match"] = True
            o["outcome"] = "MATCH"
            o["prev_hash"] = prev
            o["record_hash"] = B.sha(B.canonical(o) + "|" + prev)
            prev = o["record_hash"]
            forged_outcomes.append(o)
        forged_receipt = copy.deepcopy(run["receipt"])
        forged_receipt["verdict"] = "VERIFIED_SAMPLE"
        forged_receipt["mismatched_check_ids"] = []
        forged_receipt["rerun_chain_head_hash"] = prev
        rec = B.spotcheck_recompute({
            "receipt": forged_receipt,
            "scorecard": self.presented(sid),
            "outcomes": forged_outcomes,
            "manifest": req["manifest"],
            "verifier_nonce": req["manifest"]["verifier_nonce"]})
        self.assertFalse(rec["verified"], rec)
        self.assertTrue(rec["error"].startswith(
            "BENCHKIT_VERIFY_FAIL"), rec)

    def test_m2_broken_chain_and_extra_outcome_fail(self):
        sid, seal = self.run_battery("battery-good-40.json")
        req, run = self.verify_flow(sid, seal)
        broken = copy.deepcopy(run["outcomes"])
        broken[3]["record_hash"] = "f" * 64
        rec = B.spotcheck_recompute({
            "receipt": run["receipt"],
            "scorecard": self.presented(sid), "outcomes": broken,
            "manifest": req["manifest"],
            "verifier_nonce": req["manifest"]["verifier_nonce"]})
        self.assertFalse(rec["verified"])
        self.assertEqual(rec["step"], 3)
        extra = copy.deepcopy(run["outcomes"])
        extra.append(dict(extra[0]))
        rec2 = B.spotcheck_recompute({
            "receipt": run["receipt"],
            "scorecard": self.presented(sid), "outcomes": extra,
            "manifest": req["manifest"],
            "verifier_nonce": req["manifest"]["verifier_nonce"]})
        self.assertFalse(rec2["verified"])
        self.assertEqual(rec2["step"], 3)
        # tampered rerun head alone also fails
        bad_receipt = copy.deepcopy(run["receipt"])
        bad_receipt["rerun_chain_head_hash"] = "e" * 64
        rec3 = B.spotcheck_recompute({
            "receipt": bad_receipt,
            "scorecard": self.presented(sid),
            "outcomes": run["outcomes"],
            "manifest": req["manifest"],
            "verifier_nonce": req["manifest"]["verifier_nonce"]})
        self.assertFalse(rec3["verified"])

    def test_m3_key_custody(self):
        with open(os.path.join(ROOT, "benchkit.py"),
                  encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn("fixture-secret-" + "benchkit", src)
        self.assertNotIn("FIXTURE_KEYS", src)
        # keys are generated files in keys/, chmod 600
        B.verifier_token()
        B.sign(B.sha("probe"), B.VENDOR_KEY_REF)
        B.sign(B.sha("probe"), B.HARNESS_KEY_REF)
        kdir = os.environ["BENCHKIT_KEYS_DIR"]
        for name in ("vendor.fixture.key", "harness.fixture.key",
                     "verifier-token.fixture.key"):
            p = os.path.join(kdir, name)
            self.assertTrue(os.path.exists(p), p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode),
                             0o600, p)
        with open(os.path.join(ROOT, ".gitignore"),
                  encoding="utf-8") as f:
            self.assertIn("keys/", f.read())

    def test_m4_verifier_token_required(self):
        sid, seal = self.run_battery("battery-small-8.json")
        token = os.environ.pop("BENCHKIT_VERIFIER_TOKEN")
        try:
            bare = B.spotcheck_request({
                "scorecard_hash": seal["scorecard_hash"],
                "scorecard": self.presented(sid)})
            self.assertEqual(bare["refusal"],
                             "VERIFIER_TOKEN_REQUIRED")
            wrong = B.spotcheck_request({
                "scorecard_hash": seal["scorecard_hash"],
                "scorecard": self.presented(sid),
                "verifier_token": "wrong-token"})
            self.assertEqual(wrong["refusal"],
                             "VERIFIER_TOKEN_REQUIRED")
            self.assertEqual(B.anomaly_queue_read({})["refusal"],
                             "VERIFIER_TOKEN_REQUIRED")
            ok = B.spotcheck_request({
                "scorecard_hash": seal["scorecard_hash"],
                "scorecard": self.presented(sid),
                "verifier_token": token})
            self.assertIn("manifest", ok)
        finally:
            os.environ["BENCHKIT_VERIFIER_TOKEN"] = token

    def test_m1_minor_nonhex_hash_and_pass_mismatch(self):
        m = load("battery-small-8.json")
        sid = B.run_begin({"server": m["server"]})["scorecard_id"]
        desc = {"server_id": "good", "tool": "check_tool",
                "input": {"n": 1}}
        genuine = B.output_hash(desc)
        hook = {"hook_version": "1.0", "invocation_descriptor": desc,
                "input_ref_or_inline_hash": B.sha("x"),
                "expected_output_hash": genuine,
                "determinism_class": "deterministic",
                "seed_if_seeded": None, "timeout_class": "standard"}
        base_args = {"scorecard_id": sid, "check_id": "chk-x-01",
                     "invocation_hash": B.sha("a"),
                     "input_hash": B.sha("b"),
                     "expected_output_hash": genuine,
                     "observed_output_hash": genuine,
                     "verdict_as_run": "pass", "hook": hook}
        bad = B.check_record({**base_args,
                              "invocation_hash": "z" * 64})
        self.assertEqual(bad["refusal"], "MALFORMED_HASH")
        bad2 = B.check_record({**base_args,
                               "observed_output_hash": "a" * 64})
        self.assertEqual(bad2["refusal"], "VERDICT_HASH_MISMATCH")

    def test_m2_minor_hook_contents_validated(self):
        m = load("battery-small-8.json")
        sid = B.run_begin({"server": m["server"]})["scorecard_id"]
        genuine = B.sha("g")
        base_args = {"scorecard_id": sid, "check_id": "chk-h-01",
                     "invocation_hash": B.sha("a"),
                     "input_hash": B.sha("b"),
                     "expected_output_hash": genuine,
                     "observed_output_hash": genuine,
                     "verdict_as_run": "pass"}
        for hook in ({}, {"hook_version": "1.0"},
                     {"hook_version": "1.0",
                      "invocation_descriptor": {},
                      "input_ref_or_inline_hash": B.sha("x"),
                      "expected_output_hash": genuine,
                      "determinism_class": "deterministic",
                      "timeout_class": "standard"}):
            out = B.check_record({**base_args, "hook": hook})
            self.assertEqual(out["refusal"], "MALFORMED_HOOK",
                             hook)

    def test_m4_minor_counter_signatures_computed(self):
        sid, seal = self.run_battery("battery-small-8.json")
        req, run = self.verify_flow(sid, seal)
        self.assertEqual(run["receipt"]["counter_signatures"],
                         "complete")
        payload = B.sha(B.canonical(
            B._receipt_signable(run["receipt"])))
        self.assertEqual(B._counter_status(payload, {}), "partial")
        self.assertEqual(B._counter_status(
            payload, {"harness": run["receipt"]["signatures"]
                      ["harness"]}), "partial")
        # a receipt claiming 'complete' with the vendor signature
        # stripped must not recompute as verified
        stripped = copy.deepcopy(run["receipt"])
        stripped["signatures"] = {
            "harness": stripped["signatures"]["harness"]}
        rec = B.spotcheck_recompute({
            "receipt": stripped, "scorecard": self.presented(sid),
            "outcomes": run["outcomes"],
            "verifier_nonce": req["manifest"]["verifier_nonce"]})
        self.assertFalse(rec["verified"])


class TestSurface(Base):
    def test_vendor_tools_and_no_buy_path(self):
        resp = server.handle({"method": "tools/list", "id": 1})
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(names, ["benchkit_run_begin",
                                 "benchkit_check_record",
                                 "benchkit_scorecard_seal",
                                 "benchkit_scorecard_get",
                                 "benchkit_export_get"])
        for forbidden in ("assay_buy", "cupel_license",
                          "bench_checkout", "certify_server"):
            r = server.handle({"method": "tools/call", "id": 2,
                               "params": {"name": forbidden,
                                          "arguments": {}}})
            body = json.loads(r["result"]["content"][0]["text"])
            self.assertEqual(body["refusal"], "NO_SUCH_TOOL")

    def test_verifier_surface_disjoint(self):
        os.environ["ECLIPSE_BENCHKIT_SURFACE"] = "verifier"
        resp = server.handle({"method": "tools/list", "id": 1})
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(names, ["spotcheck_request", "spotcheck_run",
                                 "spotcheck_receipt_get",
                                 "spotcheck_recompute",
                                 "anomaly_queue_read"])
        r = server.handle({"method": "tools/call", "id": 2, "params": {
            "name": "benchkit_run_begin", "arguments": {}}})
        body = json.loads(r["result"]["content"][0]["text"])
        self.assertEqual(body["refusal"], "NO_SUCH_TOOL")

    def test_initialize(self):
        resp = server.handle({"method": "initialize", "id": 3})
        self.assertEqual(
            resp["result"]["serverInfo"]["name"],
            "io.github.CYAN-ECLIPSE-TECHNOLOGIES-LLC/"
            "eclipse-benchkit-mcp")


if __name__ == "__main__":
    unittest.main()
