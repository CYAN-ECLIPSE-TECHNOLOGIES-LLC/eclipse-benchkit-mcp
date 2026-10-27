#!/usr/bin/env python3
# Eclipse Benchkit core. Copyright 2026 Cyan Eclipse Technologies LLC.
"""Vendor self-bench SDK + spot-check harness (spec SPEC.md).

Vendor-run scorecards embed spot-check hooks; the house bench re-runs
a random sample, so a fabricated self-bench is statistically
detectable (spec 2.1).

HARD CONSTRAINT (spec 0.2, owner ruling 2026-10-27): Eclipse Assay and
Eclipse Cupel are internal tools, never products. Benchkit ships the
Assay scorecard FORMAT + spot-check hooks only. No Assay/Cupel product
surface, price, licence, or buy path for them exists here. The paid
bench is a service engagement reached through existing intake,
external to this product - stated as fact only, no intake form, no
service pricing, no entitlement in this code.

v0.1.1 fix loop (Verity bench FAIL 11/16, bench-benchkit.md):
 D1 sample unpredictability: the verifier nonce is generated
    verifier-side from a secret seed held in keys/ plus fresh CSPRNG
    entropy. It is never a caller input for a new draw and never
    derivable from scorecard_hash or any public store state. A nonce
    supplied by a caller is accepted ONLY as an idempotent replay key
    for an already-issued (scorecard_hash, verifier_nonce) pair
    (spec 3.3); a novel supplied nonce is refused by name.
 D2 F-B14 startup/descriptor fence implemented (section 7.3).
 M1 seal signature binds the whole seal record (counts, format
    version, head hash) and presented seals are re-verified against
    the presented records' recomputed counts.
 M2 spotcheck_recompute authenticates receipt signatures, the
    outcome record chain, and the rerun chain head, and rejects
    extra / out-of-sample outcomes.
 M3 keys live in keys/ (generated locally, chmod 600, gitignored,
    fixture-labelled) - no key material in source.
 M4 verifier verbs require the verifier token (spec section 5).

All artifacts value_class "test". Local/fixture only; no network
code exists in this tree.
"""
import hashlib
import hmac
import json
import os
import random
import re
import secrets

PRODUCT = "eclipse-benchkit"
TOOL_VERSION = "0.1.1"
SCOPE = "LOCAL/fixture"
VALUE_CLASS = "test"
FORMAT_VERSION = "assay-scorecard/1.0"
DEFAULT_K = 30
POWERED_F = 0.10
GENESIS = "0" * 64
VENDOR_KEY_REF = "vendor-fixture"
HARNESS_KEY_REF = "harness-fixture"
VERIFIER_SEED_REF = "verifier-seed"
VERIFIER_TOKEN_REF = "verifier-token"

_KEY_FILES = {VENDOR_KEY_REF: "vendor.fixture.key",
              HARNESS_KEY_REF: "harness.fixture.key",
              VERIFIER_SEED_REF: "verifier-seed.fixture.key",
              VERIFIER_TOKEN_REF: "verifier-token.fixture.key"}


class ToolError(Exception):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_hex64(v):
    return isinstance(v, str) and len(v) == 64 and \
        all(c in "0123456789abcdefABCDEF" for c in v)


# ---------- key custody (M3, spec 7.4) ----------

def keys_dir():
    return os.environ.get(
        "BENCHKIT_KEYS_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "keys"))


def _load_or_create_key(key_ref):
    path = os.path.join(keys_dir(), _KEY_FILES[key_ref])
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    os.makedirs(keys_dir(), exist_ok=True)
    if key_ref == VERIFIER_TOKEN_REF:
        value = "fixture-verifier-token-" + secrets.token_hex(16)
    else:
        value = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (value + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)
    return value


def sign(payload_hash, key_ref):
    key = _load_or_create_key(key_ref)
    return hmac.new(key.encode(), payload_hash.encode(),
                    hashlib.sha256).hexdigest()


def _sig_ok(payload_hash, key_ref, presented):
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(sign(payload_hash, key_ref), presented)


def verifier_token():
    """The fixture verifier token (keys/, chmod 600). Verifier-side
    operators read it from the key file and present it per-call as
    `verifier_token` or via the BENCHKIT_VERIFIER_TOKEN env var of
    the verifier process. It is never a vendor-surface input."""
    return _load_or_create_key(VERIFIER_TOKEN_REF)


def _require_verifier_token(args):
    expected = _load_or_create_key(VERIFIER_TOKEN_REF)
    supplied = (args or {}).get("verifier_token") or \
        os.environ.get("BENCHKIT_VERIFIER_TOKEN") or \
        os.environ.get("ECLIPSE_BENCHKIT_VERIFIER_TOKEN")
    if not supplied or not hmac.compare_digest(str(supplied),
                                               expected):
        return _refusal(
            "VERIFIER_TOKEN_REQUIRED",
            "verifier verbs require the verifier token (spec 5): "
            "pass verifier_token or set BENCHKIT_VERIFIER_TOKEN in "
            "the verifier process to the keys/ fixture token")
    return None


def _counter_status(payload_hash, signatures):
    """Computed, never asserted: 'complete' only when both the
    harness and vendor signatures verify over payload_hash."""
    sigs = signatures or {}
    if _sig_ok(payload_hash, HARNESS_KEY_REF, sigs.get("harness")) \
            and _sig_ok(payload_hash, VENDOR_KEY_REF,
                        sigs.get("vendor")):
        return "complete"
    return "partial"


# ---------- config fence (D2 / F-B14, spec 7.3) ----------

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
_URL_RE = re.compile(r"https?://([^\s/\"']+)")
_LIVE_KEY_RE = re.compile(
    r"(sk-live|pk_live|rk_live|live[-_]?key|-----BEGIN)", re.I)
_NONCE_KEYS = {"vendor_nonce", "sample_seed", "verifier_nonce",
               "nonce", "seed", "sample_nonce"}
_BUY_WORDS = ("price", "licen", "checkout", "buy", "purchase",
              "subscribe", "$")


def _fence_scan(obj):
    """Return the fence class for the first violation found, else
    None. Scans keys and string values recursively."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if kl == "value_class" and v != VALUE_CLASS:
                return "value-class"
            if kl in _NONCE_KEYS and v is not None:
                return "vendor-nonce"
            if ("live" in kl and "key" in kl) or \
                    kl in ("api_key", "apikey", "secret_key") and \
                    isinstance(v, str) and v and \
                    not v.startswith(("test", "fixture", "fake")):
                return "live-key"
            text = kl + "=" + (v if isinstance(v, str) else "")
            low = text.lower()
            if ("assay" in low or "cupel" in low) and \
                    any(w in low for w in _BUY_WORDS):
                return "assay-cupel-price-or-checkout"
            r = _fence_scan(v)
            if r:
                return r
        return None
    if isinstance(obj, (list, tuple)):
        for v in obj:
            r = _fence_scan(v)
            if r:
                return r
        return None
    if isinstance(obj, str):
        if _LIVE_KEY_RE.search(obj):
            return "live-key"
        for m in _URL_RE.finditer(obj):
            host = m.group(1).split(":")[0].lower()
            if host not in _LOCAL_HOSTS:
                return "non-local-endpoint"
        low = obj.lower()
        if ("assay" in low or "cupel" in low) and \
                any(w in low for w in _BUY_WORDS):
            return "assay-cupel-price-or-checkout"
    return None


def check_config(cfg):
    """Fence a config/descriptor object. Returns the full refusal
    code 'CONFIG_FENCE_REFUSED:<class>' or None."""
    cls = _fence_scan(cfg)
    return "CONFIG_FENCE_REFUSED:" + cls if cls else None


def startup_fence(env=None):
    """Startup fence over process config env (spec 7.3). Returns
    the refusal code or None. Only Benchkit/config-shaped variables
    are treated as config."""
    env = os.environ if env is None else env
    for k, v in env.items():
        kl = k.lower()
        if kl in ("benchkit_value_class",
                  "eclipse_benchkit_value_class") and \
                v != VALUE_CLASS:
            return "CONFIG_FENCE_REFUSED:value-class"
        if "vendor_nonce" in kl or "sample_seed" in kl:
            return "CONFIG_FENCE_REFUSED:vendor-nonce"
        if not (k.startswith(("BENCHKIT_", "ECLIPSE_BENCHKIT_",
                              "ASSAY_", "CUPEL_", "VENDOR_"))):
            continue
        r = check_config({k: v})
        if r:
            return r
    return None


# ---------- store ----------

def data_dir():
    return os.environ.get(
        "BENCHKIT_DATA_DIR",
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "data"))


def _store_path():
    return os.path.join(data_dir(), "store.json")


def load_store():
    p = _store_path()
    if not os.path.exists(p):
        return {"scorecards": {}, "manifests": {}, "receipts": {},
                "anomalies": [], "metering": [], "nonce_counter": 0}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_store(store):
    os.makedirs(data_dir(), exist_ok=True)
    with open(_store_path(), "w", encoding="utf-8") as f:
        f.write(json.dumps(store, sort_keys=True))


def _refusal(code, detail=""):
    return {"refusal": code, "detail": detail, "product": PRODUCT,
            "tool_version": TOOL_VERSION, "scope": SCOPE,
            "value_class": VALUE_CLASS}


# ---------- fixture vendor servers ----------

def fixture_execute(descriptor):
    """Deterministic fixture vendor server execution. Returns the
    output string a genuine run produces for this invocation."""
    server = descriptor.get("server_id", "")
    tool = descriptor.get("tool", "")
    inp = descriptor.get("input") or {}
    base = canonical({"server": server, "tool": tool, "input": inp})
    if isinstance(inp, dict) and inp.get("result") == "fail":
        return base + ":fail"
    return base + ":pass"


def output_hash(descriptor):
    return sha(fixture_execute(descriptor))


# ---------- vendor surface ----------

def _record_hash(rec, prev):
    body = {k: v for k, v in rec.items()
            if k not in ("record_hash", "signature")}
    return sha(canonical(body) + "|" + prev)


def run_begin(args):
    server = args.get("server") or {}
    fence = check_config(server)
    if fence is None and args.get("config") is not None:
        fence = check_config(args.get("config"))
    if fence:
        return _refusal(fence,
                        "descriptor/config refused by the section "
                        "7.3 fence at run_begin (F-B14)")
    store = load_store()
    sid = "sc_" + sha(canonical(server) +
                      str(len(store["scorecards"])))[:16]
    open_rec = {"record_type": "benchkit_scorecard_open",
                "scorecard_id": sid, "server": server,
                "format_version": FORMAT_VERSION,
                "value_class": VALUE_CLASS,
                "supersedes": args.get("supersedes"),
                "label": "vendor-run / self-bench"}
    open_rec["record_hash"] = _record_hash(open_rec, GENESIS)
    store["scorecards"][sid] = {
        "scorecard_id": sid, "open_record": open_rec, "records": [],
        "sealed": None, "head": open_rec["record_hash"]}
    save_store(store)
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "scorecard_id": sid,
            "open_record": open_rec, "value_class": VALUE_CLASS}


def _validate_hook(hook, args, det):
    """m2: hook contents are validated at record time. Returns a
    refusal dict or None."""
    if not isinstance(hook, dict) or not hook:
        return _refusal("MALFORMED_HOOK", "hook must be a non-empty "
                        "object or null")
    for field in ("hook_version", "invocation_descriptor",
                  "input_ref_or_inline_hash", "expected_output_hash",
                  "determinism_class", "timeout_class"):
        if field not in hook:
            return _refusal("MALFORMED_HOOK", "missing " + field)
    if not isinstance(hook["hook_version"], str) or \
            not hook["hook_version"]:
        return _refusal("MALFORMED_HOOK", "hook_version")
    if not is_hex64(hook["input_ref_or_inline_hash"]):
        return _refusal("MALFORMED_HOOK",
                        "input_ref_or_inline_hash not a hex hash")
    if not is_hex64(hook["expected_output_hash"]):
        return _refusal("MALFORMED_HOOK",
                        "expected_output_hash not a hex hash")
    if hook["expected_output_hash"] != args.get(
            "expected_output_hash"):
        return _refusal("MALFORMED_HOOK",
                        "hook expected_output_hash differs from "
                        "the record's")
    if hook["determinism_class"] not in (
            "deterministic", "seeded", "non-deterministic"):
        return _refusal("MALFORMED_HOOK", "determinism_class")
    if hook["determinism_class"] != det:
        return _refusal("MALFORMED_HOOK",
                        "hook determinism_class differs from the "
                        "record's")
    if det == "seeded" and not hook.get("seed_if_seeded"):
        return _refusal("MALFORMED_HOOK",
                        "seeded check requires seed_if_seeded")
    desc = hook["invocation_descriptor"]
    if not isinstance(desc, dict) or \
            not isinstance(desc.get("server_id"), str) or \
            not desc.get("server_id") or \
            not isinstance(desc.get("tool"), str) or \
            not desc.get("tool") or "input" not in desc:
        return _refusal("MALFORMED_HOOK",
                        "invocation_descriptor needs server_id, "
                        "tool and input")
    if not isinstance(hook["timeout_class"], str) or \
            not hook["timeout_class"]:
        return _refusal("MALFORMED_HOOK", "timeout_class")
    return None


def check_record(args):
    store = load_store()
    sc = store["scorecards"].get(args.get("scorecard_id"))
    if sc is None:
        return _refusal("SCORECARD_NOT_FOUND")
    if sc["sealed"] is not None:
        return _refusal("ALREADY_SEALED",
                        "hooks and records cannot be added post-seal")
    check_id = args.get("check_id")
    if not check_id or any(r["check_id"] == check_id
                           for r in sc["records"]):
        return _refusal("DUPLICATE_CHECK_ID")
    # m1: hashes must be 64-char HEX, not merely 64 chars
    for field in ("invocation_hash", "input_hash",
                  "expected_output_hash", "observed_output_hash"):
        if not is_hex64(args.get(field)):
            return _refusal("MALFORMED_HASH", field)
    if args.get("verdict_as_run") not in ("pass", "fail"):
        return _refusal("MALFORMED_VERDICT")
    # m1: a 'pass' verdict cannot stand over differing hashes
    if args["verdict_as_run"] == "pass" and \
            args["expected_output_hash"] != \
            args["observed_output_hash"]:
        return _refusal("VERDICT_HASH_MISMATCH",
                        "verdict_as_run 'pass' with expected != "
                        "observed output hash")
    hook = args.get("hook")
    det = args.get("determinism_class", "deterministic")
    if det not in ("deterministic", "seeded", "non-deterministic"):
        return _refusal("MALFORMED_DETERMINISM_CLASS")
    if hook is not None:
        bad = _validate_hook(hook, args, det)
        if bad:
            return bad
    prev = sc["head"]
    rec = {"record_id": "chk_" + sha(prev + check_id)[:16],
           "record_type": "benchkit_check_run",
           "scorecard_id": sc["scorecard_id"], "check_id": check_id,
           "seq": len(sc["records"]) + 1, "prev_hash": prev,
           "invocation_hash": args["invocation_hash"],
           "input_hash": args["input_hash"],
           "expected_output_hash": args["expected_output_hash"],
           "observed_output_hash": args["observed_output_hash"],
           "verdict_as_run": args["verdict_as_run"],
           "hook": hook, "hookless": hook is None,
           "determinism_class": det,
           "env_fingerprint": args.get("env_fingerprint"),
           "ts": args.get("ts", "2026-10-27T00:00:00Z"),
           "value_class": VALUE_CLASS}
    rec["record_hash"] = _record_hash(rec, prev)
    rec["signature"] = sign(rec["record_hash"], VENDOR_KEY_REF)
    sc["records"].append(rec)
    sc["head"] = rec["record_hash"]
    save_store(store)
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "record": rec, "value_class": VALUE_CLASS}


def _seal_signable(seal):
    return {k: v for k, v in seal.items() if k != "signature"}


def scorecard_seal(args):
    store = load_store()
    sc = store["scorecards"].get(args.get("scorecard_id"))
    if sc is None:
        return _refusal("SCORECARD_NOT_FOUND")
    if sc["sealed"] is not None:
        return sc["sealed"]
    hook_bearing = [r for r in sc["records"] if not r["hookless"]]
    seal = {"record_type": "benchkit_scorecard_seal",
            "scorecard_id": sc["scorecard_id"],
            "scorecard_hash": sc["head"],
            "check_count": len(sc["records"]),
            "hook_bearing_count": len(hook_bearing),
            "hookless_count": len(sc["records"]) - len(hook_bearing),
            "format_version": FORMAT_VERSION,
            "label": "vendor-run / self-bench",
            "value_class": VALUE_CLASS}
    # M1: the vendor signature binds the WHOLE seal record - head
    # hash, all counts and format_version - not the head hash alone
    seal["signature"] = sign(sha(canonical(_seal_signable(seal))),
                             VENDOR_KEY_REF)
    sc["sealed"] = seal
    save_store(store)
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "seal": seal, "value_class": VALUE_CLASS}


def _verify_presented(records, open_record, seal):
    """Recompute the run chain + seal. Returns (ok, head).

    M1: seal counts and format_version are recomputed from the
    presented records and the seal signature is verified over the
    canonical seal record, so tampered counts cannot verify."""
    if open_record is None or seal is None:
        return False, None
    if _record_hash(open_record, GENESIS) != open_record.get(
            "record_hash"):
        return False, None
    prev = open_record["record_hash"]
    for i, rec in enumerate(records):
        if rec.get("seq") != i + 1 or rec.get("prev_hash") != prev:
            return False, None
        if _record_hash(rec, prev) != rec.get("record_hash"):
            return False, None
        if rec.get("signature") != sign(rec["record_hash"],
                                        VENDOR_KEY_REF):
            return False, None
        prev = rec["record_hash"]
    if seal.get("scorecard_hash") != prev:
        return False, None
    hook_bearing = sum(1 for r in records if not r.get("hookless"))
    if seal.get("check_count") != len(records) or \
            seal.get("hook_bearing_count") != hook_bearing or \
            seal.get("hookless_count") != len(records) - \
            hook_bearing:
        return False, None
    if seal.get("format_version") != FORMAT_VERSION or \
            seal.get("value_class") != VALUE_CLASS:
        return False, None
    if seal.get("signature") != sign(
            sha(canonical(_seal_signable(seal))), VENDOR_KEY_REF):
        return False, None
    return True, prev


def scorecard_get(args):
    store = load_store()
    sc = store["scorecards"].get(args.get("scorecard_id"))
    if sc is None:
        return _refusal("SCORECARD_NOT_FOUND")
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "scorecard_id": sc["scorecard_id"],
            "open_record": sc["open_record"], "records": sc["records"],
            "seal": sc["sealed"], "label": "vendor-run / self-bench",
            "value_class": VALUE_CLASS}


def export_get(args):
    store = load_store()
    sc = store["scorecards"].get(args.get("scorecard_id"))
    if sc is None:
        return _refusal("SCORECARD_NOT_FOUND")
    if sc["sealed"] is None:
        return _refusal("NOT_SEALED")
    ok, _ = _verify_presented(sc["records"], sc["open_record"],
                              sc["sealed"])
    base = {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "scorecard_id": sc["scorecard_id"],
            "label": "vendor-run / self-bench",
            "value_class": VALUE_CLASS}
    if not ok:
        return {**base, "export_label": "DOWNGRADED_EXPORT",
                "verified": False, "downgrade_reason": "SEAL_BROKEN",
                "seal": None, "records": sc["records"]}
    return {**base, "export_label": "EXPORTED_SELF_BENCH",
            "verification": "none", "seal": sc["sealed"],
            "open_record": sc["open_record"], "records": sc["records"]}


# ---------- verifier surface ----------

def _sample_ids(records, seed_hex, k):
    # Hook-bearing checks only (hookless excluded from samples and
    # verified claims). A sampled non-deterministic check resolves
    # UNVERIFIABLE at re-run: per the Verity ruling on F-B10 vs
    # section 4.2 (2026-10-27), non-deterministic checks are
    # sample-eligible but excluded from verified claims.
    eligible = [r for r in records if not r["hookless"]]
    rng = random.Random(int(seed_hex[:16], 16))
    ids = [r["check_id"] for r in eligible]
    if len(ids) <= k:
        return ids
    return rng.sample(ids, k)


def detection_probability(k, f=POWERED_F):
    return round(1 - (1 - f) ** k, 6)


def _generate_verifier_nonce(scorecard_hash):
    """D1: verifier-side only. The nonce is HMAC over the scorecard
    hash and fresh CSPRNG bytes, keyed by the verifier secret seed
    held in keys/ (chmod 600, never in source, never revealed). The
    seed's commitment (sha256 of the seed, below) predates any
    vendor submission in verifier custody; the nonce itself is
    revealed only in the manifest, after the seal is verified.
    Nothing a vendor can know or supply at submission time -
    scorecard_hash, store counters, public state - predicts it."""
    seed_secret = _load_or_create_key(VERIFIER_SEED_REF)
    fresh = secrets.token_bytes(16)
    nonce = hmac.new(seed_secret.encode(),
                     scorecard_hash.encode() + b"|" + fresh,
                     hashlib.sha256).hexdigest()[:32]
    commitment = sha("benchkit-verifier-seed-commit-v1|" +
                     seed_secret)
    return nonce, commitment


def _manifest_signable(m):
    return {k: v for k, v in m.items()
            if k not in ("signature", "vendor_counter_signature",
                         "counter_signatures", "records", "seal",
                         "open_record", "outcomes")}


def _manifest_public(entry):
    return _manifest_signable(entry) | {
        "signature": entry.get("signature"),
        "vendor_counter_signature": entry.get(
            "vendor_counter_signature"),
        "counter_signatures": entry.get("counter_signatures")}


def _manifest_hash(entry):
    return sha(canonical(_manifest_signable(entry)))


def _manifest_counter_status(m):
    payload = sha(canonical(_manifest_signable(m)))
    sigs = {"harness": m.get("signature"),
            "vendor": m.get("vendor_counter_signature")}
    return _counter_status(payload, sigs)


def _derived_prior_verdict(store, scorecard_hash):
    """m3: lineage prior verdict is DERIVED from stored receipts
    for this scorecard, never caller-supplied."""
    prior = None
    for receipt in store["receipts"].values():
        if receipt.get("scorecard_hash") == scorecard_hash:
            prior = receipt.get("verdict")
    return prior


def spotcheck_request(args):
    bad = _require_verifier_token(args)
    if bad:
        return bad
    store = load_store()
    if args.get("vendor_nonce") is not None:
        store["anomalies"].append(
            {"kind": "violation", "code": "VENDOR_NONCE_REFUSED",
             "detail": "nonce is verifier-generated only",
             "value_class": VALUE_CLASS})
        save_store(store)
        return _refusal("VENDOR_NONCE_REFUSED",
                        "CONFIG_FENCE_REFUSED:vendor-nonce")
    presented = args.get("scorecard") or {}
    records = presented.get("records") or []
    seal = presented.get("seal")
    open_record = presented.get("open_record")
    scorecard_hash = args.get("scorecard_hash")
    ok, head = _verify_presented(records, open_record, seal)
    if seal is None or not ok or head != scorecard_hash:
        code = "PRE_SEAL_SAMPLE" if seal is None else "SEAL_INVALID"
        store["anomalies"].append(
            {"kind": "violation", "code": code,
             "scorecard_hash": scorecard_hash,
             "value_class": VALUE_CLASS})
        save_store(store)
        return _refusal(code)
    # D1 + m5 (spec 3.3): a caller-supplied verifier_nonce is NEVER
    # an input to a new draw. It is honoured only as the replay key
    # of an already-issued (scorecard_hash, verifier_nonce) pair,
    # which returns the recorded manifest/receipt; a novel supplied
    # nonce is refused by name and draws nothing.
    supplied = args.get("verifier_nonce")
    if supplied is not None:
        for m in store["manifests"].values():
            if m["scorecard_hash"] == scorecard_hash and \
                    m["verifier_nonce"] == supplied:
                receipt = store["receipts"].get(m["manifest_id"])
                return {"product": PRODUCT,
                        "tool_version": TOOL_VERSION,
                        "scope": SCOPE,
                        "manifest": _manifest_public(m),
                        "verifier_nonce": supplied,
                        "idempotent_replay": True,
                        "receipt": receipt,
                        "value_class": VALUE_CLASS}
        store["anomalies"].append(
            {"kind": "violation", "code": "VERIFIER_NONCE_REFUSED",
             "detail": "supplied nonce matches no issued pair; "
                       "nonces are verifier-generated only",
             "value_class": VALUE_CLASS})
        save_store(store)
        return _refusal("VERIFIER_NONCE_REFUSED",
                        "nonce is verifier-generated (CSPRNG + "
                        "verifier secret seed); a supplied nonce is "
                        "accepted only as a section 3.3 replay key")
    nonce, seed_commitment = _generate_verifier_nonce(scorecard_hash)
    seed = sha(scorecard_hash + "|" + nonce)
    sampled = _sample_ids(records, seed, DEFAULT_K)
    k = len(sampled)
    manifest = {"manifest_id": "smf_" + sha(seed)[:16],
                "scorecard_hash": scorecard_hash,
                "verifier_nonce": nonce,
                "verifier_seed_commitment": seed_commitment,
                "nonce_commitment": sha(
                    "benchkit-nonce-commit-v1|" + nonce + "|" +
                    scorecard_hash),
                "seed_derivation":
                "sha256(scorecard_hash|verifier_nonce)",
                "seed": seed,
                "sample_size_k": k, "powered_fraction_f": POWERED_F,
                "detection_probability": detection_probability(k),
                "sampled_check_ids": sampled,
                "prior_verdict": _derived_prior_verdict(
                    store, scorecard_hash),
                "value_class": VALUE_CLASS}
    payload = sha(canonical(_manifest_signable(manifest)))
    manifest["signature"] = sign(payload, HARNESS_KEY_REF)
    manifest["vendor_counter_signature"] = sign(payload,
                                                VENDOR_KEY_REF)
    # m4: computed from the actual signatures, never asserted
    manifest["counter_signatures"] = _manifest_counter_status(
        manifest)
    store["manifests"][manifest["manifest_id"]] = {
        **manifest, "records": records, "seal": seal,
        "open_record": open_record, "outcomes": None}
    save_store(store)
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "manifest": manifest,
            "verifier_nonce": nonce, "value_class": VALUE_CLASS}


def _receipt_signable(receipt):
    return {k: v for k, v in receipt.items()
            if k not in ("signatures", "counter_signatures")}


def spotcheck_run(args):
    bad = _require_verifier_token(args)
    if bad:
        return bad
    store = load_store()
    entry = store["manifests"].get(args.get("sample_manifest_id"))
    if entry is None:
        return _refusal("MANIFEST_NOT_FOUND")
    if entry["manifest_id"] in store["receipts"]:
        return {"product": PRODUCT, "tool_version": TOOL_VERSION,
                "scope": SCOPE, "idempotent": True,
                "receipt": store["receipts"][entry["manifest_id"]]}
    by_id = {r["check_id"]: r for r in entry["records"]}
    outcomes, mismatched, unverifiable = [], [], []
    prev = entry["scorecard_hash"]
    for cid in entry["sampled_check_ids"]:
        rec = by_id[cid]
        hook = rec.get("hook") or {}
        out = {"check_id": cid, "prev_hash": prev,
               "rerun_count": 1, "value_class": VALUE_CLASS}
        if rec["determinism_class"] == "non-deterministic" or \
                hook.get("requires_secret"):
            out["match"] = None
            out["outcome"] = "UNVERIFIABLE"
            unverifiable.append(cid)
        else:
            rerun_hash = output_hash(
                hook.get("invocation_descriptor") or {})
            out["rerun_output_hash"] = rerun_hash
            out["match"] = rerun_hash == rec["observed_output_hash"]
            out["outcome"] = "MATCH" if out["match"] else "MISMATCH"
            if not out["match"]:
                mismatched.append(cid)
        out["record_hash"] = sha(canonical(out) + "|" + prev)
        prev = out["record_hash"]
        outcomes.append(out)
    if unverifiable:
        verdict = "UNVERIFIABLE"
    elif mismatched:
        verdict = "DIVERGENT"
    else:
        verdict = "VERIFIED_SAMPLE"
    k = entry["sample_size_k"]
    receipt = {"receipt_id": "src_" + sha(
        entry["manifest_id"] + verdict)[:16],
        "scorecard_hash": entry["scorecard_hash"],
        "sample_manifest_hash": _manifest_hash(entry),
        "rerun_chain_head_hash": prev, "verdict": verdict,
        "sample_size_k": k, "powered_fraction_f": POWERED_F,
        "detection_probability": detection_probability(k),
        "mismatched_check_ids": mismatched,
        "unverifiable_check_ids": unverifiable,
        "issued_at": "2026-10-27T00:00:00Z",
        "label": "spot-check of a vendor-run self-bench sample; "
                 "not a house bench verdict, not a certification",
        "value_class": VALUE_CLASS}
    payload = sha(canonical(_receipt_signable(receipt)))
    receipt["signatures"] = {
        "harness": sign(payload, HARNESS_KEY_REF),
        "vendor": sign(payload, VENDOR_KEY_REF)}
    # m4: the face label is computed by verifying both signatures
    receipt["counter_signatures"] = _counter_status(
        payload, receipt["signatures"])
    entry["outcomes"] = outcomes
    store["receipts"][entry["manifest_id"]] = receipt
    store["metering"].append({
        "event": "spotcheck_verification_completed",
        "key": [entry["scorecard_hash"], entry["verifier_nonce"]],
        "verdict": verdict,
        "price_shape": "$10/verification - Benchkit spot-check only "
                       "(metering point only, no charge path)",
        "value_class": VALUE_CLASS})
    save_store(store)
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "idempotent": False, "receipt": receipt,
            "outcomes": outcomes, "value_class": VALUE_CLASS}


def spotcheck_receipt_get(args):
    bad = _require_verifier_token(args)
    if bad:
        return bad
    store = load_store()
    receipt = store["receipts"].get(args.get("sample_manifest_id"))
    if receipt is None:
        return _refusal("RECEIPT_NOT_FOUND")
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "receipt": receipt,
            "value_class": VALUE_CLASS}


def spotcheck_recompute(args):
    """Pure recompute over receipt + scorecard + outcomes (spec
    6.2), extended per M2: receipt signatures are verified (step 1),
    the sample manifest is authenticated when presented (step 2),
    the outcome record chain and rerun head are verified and extra
    outcomes rejected (step 3), and the counter-signature label is
    recomputed, not trusted (step 4)."""
    bad = _require_verifier_token(args)
    if bad:
        return bad
    receipt = args.get("receipt") or {}
    presented = args.get("scorecard") or {}
    outcomes = args.get("outcomes") or []
    base = {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "value_class": VALUE_CLASS}

    def fail(step):
        return {**base, "verified": False,
                "error": "BENCHKIT_VERIFY_FAIL:%s" % step,
                "step": step}
    records = presented.get("records") or []
    # step 1: run chain + seal (counts/format/signature bound, M1)
    ok, head = _verify_presented(records, presented.get("open_record"),
                                  presented.get("seal"))
    if not ok or head != receipt.get("scorecard_hash"):
        return fail(1)
    # step 1 (cont.): receipt signatures must verify over the
    # canonical receipt payload - a forged receipt fails here
    payload = sha(canonical(_receipt_signable(receipt)))
    sigs = receipt.get("signatures") or {}
    if not _sig_ok(payload, HARNESS_KEY_REF, sigs.get("harness")) \
            or not _sig_ok(payload, VENDOR_KEY_REF,
                           sigs.get("vendor")):
        return fail(1)
    # step 2: seed re-derivation + sample; manifest authenticated
    # when presented (signature, counter-signature, hash binding)
    nonce = args.get("verifier_nonce")
    if nonce is None:
        return fail(2)
    seed = sha(receipt["scorecard_hash"] + "|" + nonce)
    sampled = _sample_ids(records, seed, DEFAULT_K)
    manifest = args.get("manifest")
    if manifest is not None:
        mpayload = sha(canonical(_manifest_signable(manifest)))
        if not _sig_ok(mpayload, HARNESS_KEY_REF,
                       manifest.get("signature")) or \
                not _sig_ok(mpayload, VENDOR_KEY_REF,
                            manifest.get(
                                "vendor_counter_signature")):
            return fail(2)
        if manifest.get("counter_signatures") != \
                _manifest_counter_status(manifest):
            return fail(2)
        if _manifest_hash(manifest) != receipt.get(
                "sample_manifest_hash"):
            return fail(2)
        if manifest.get("verifier_nonce") != nonce or \
                manifest.get("scorecard_hash") != \
                receipt.get("scorecard_hash") or \
                manifest.get("sampled_check_ids") != sampled:
            return fail(2)
    # step 3: outcomes - exactly the sample, in draw order, chain
    # hashes recomputed, head bound to the receipt, match recomputed
    if [o.get("check_id") for o in outcomes] != sampled:
        return fail(3)
    by_id = {r["check_id"]: r for r in records}
    mismatched, unverifiable = [], []
    prev = receipt["scorecard_hash"]
    for out in outcomes:
        cid = out.get("check_id")
        rec = by_id[cid]
        if out.get("prev_hash") != prev:
            return fail(3)
        body = {k: v for k, v in out.items() if k != "record_hash"}
        if sha(canonical(body) + "|" + prev) != out.get(
                "record_hash"):
            return fail(3)
        prev = out["record_hash"]
        if out.get("outcome") == "UNVERIFIABLE":
            hook = rec.get("hook") or {}
            if rec["determinism_class"] != "non-deterministic" \
                    and not hook.get("requires_secret"):
                return fail(3)
            if out.get("match") is not None:
                return fail(3)
            unverifiable.append(cid)
        elif out.get("outcome") in ("MATCH", "MISMATCH"):
            if not is_hex64(out.get("rerun_output_hash")):
                return fail(3)
            expect = out["rerun_output_hash"] == \
                rec["observed_output_hash"]
            if expect != out.get("match") or \
                    (out["outcome"] == "MATCH") != expect:
                return fail(3)
            if not out.get("match"):
                mismatched.append(cid)
        else:
            return fail(3)
    if prev != receipt.get("rerun_chain_head_hash"):
        return fail(3)
    # step 4: verdict + statistic + face lists + counter label
    verdict = "UNVERIFIABLE" if unverifiable else \
        ("DIVERGENT" if mismatched else "VERIFIED_SAMPLE")
    if verdict != receipt.get("verdict"):
        return fail(4)
    if receipt.get("mismatched_check_ids") != mismatched or \
            receipt.get("unverifiable_check_ids") != unverifiable:
        return fail(4)
    if receipt.get("sample_size_k") != len(sampled):
        return fail(4)
    if receipt.get("detection_probability") != detection_probability(
            receipt.get("sample_size_k", 0)):
        return fail(4)
    if receipt.get("counter_signatures") != _counter_status(
            payload, sigs):
        return fail(4)
    return {**base, "verified": True, "verdict": verdict,
            "sampled_check_ids": sampled,
            "detection_probability": receipt["detection_probability"]}


def anomaly_queue_read(args):
    bad = _require_verifier_token(args)
    if bad:
        return bad
    store = load_store()
    return {"product": PRODUCT, "tool_version": TOOL_VERSION,
            "scope": SCOPE, "anomalies": store["anomalies"],
            "count": len(store["anomalies"]),
            "value_class": VALUE_CLASS}


VENDOR_TOOLS = {"benchkit_run_begin": run_begin,
                "benchkit_check_record": check_record,
                "benchkit_scorecard_seal": scorecard_seal,
                "benchkit_scorecard_get": scorecard_get,
                "benchkit_export_get": export_get}
VERIFIER_TOOLS = {"spotcheck_request": spotcheck_request,
                  "spotcheck_run": spotcheck_run,
                  "spotcheck_receipt_get": spotcheck_receipt_get,
                  "spotcheck_recompute": spotcheck_recompute,
                  "anomaly_queue_read": anomaly_queue_read}
