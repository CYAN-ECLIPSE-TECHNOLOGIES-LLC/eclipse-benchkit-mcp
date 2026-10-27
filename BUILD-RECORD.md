# BUILD RECORD — Eclipse Benchkit v0.1.0 (2026-10-27)

---

# FIX ADDENDUM — v0.1.1 (2026-10-27)

**Status: BUILT, pre-bench. STOP — Verity re-benches next; no
self-certification.** Scope label: **LOCAL / fixture**

Fix loop against Verity bench FAIL 11/16 (`bench-benchkit.md`).
Every defect below: defect → fix → regression test. Suite
**27/27** fresh-process (16 prior + F-B14 + 10 fix regressions).
HARD RULE re-verified after the fixes: no Assay/Cupel product
surface, price, licence, or buy path introduced anywhere (grep
clean); the only Assay/Cupel strings added are fence-table /
negating text.

## Spec amendment (ruling applied)

- Verity ruled **F-B10 governs over §4.2's parenthetical**:
  non-deterministic checks ARE sample-eligible, resolve
  UNVERIFIABLE, never count toward verified claims. SPEC.md §4.2
  amended to "excluded from verified claims (§11.5)"; ruling +
  date recorded in the new AMENDMENTS section at the top of
  SPEC.md, which also records the §2.2.2 / §4.4 / §6.2
  tightenings for D1/M1/M2 below.

## Blockers

- **D1 — sample vendor-predictable (§2.2.2).** Was: auto nonce
  `sha256(hash+counter=1)` precomputable; `verifier_nonce`
  caller-supplied. Fix: nonce = HMAC under a **verifier-side
  secret seed** (in `keys/`, chmod 600; its sha256 commitment is
  carried in the manifest and predates any submission in verifier
  custody) over the scorecard hash + **fresh CSPRNG bytes**,
  revealed only in the manifest after the seal verifies. A
  caller-supplied nonce is **never** a draw input: it is honoured
  only as the §3.3 replay key of an already-issued pair (see m5);
  a novel supplied nonce → `VERIFIER_NONCE_REFUSED`, nothing
  drawn. → Tests: `test_d1_sample_not_precomputable` (old-formula
  nonce + exact sample predicted pre-reveal; post-fix both
  differ; second draw differs again),
  `test_d1_supplied_nonce_cannot_draw_or_grind` (3 chosen nonces
  refused, 0 manifests). Independent probe on the 40-check
  battery confirmed: nonce ≠ prediction, sample ≠ prediction.
- **D2 — F-B14 fence absent (§7.3).** Fix: `check_config` /
  `startup_fence` in benchkit.py scanning descriptors + config
  env, classes `non-local-endpoint`, `live-key`, `vendor-nonce`,
  `value-class`, `assay-cupel-price-or-checkout`, all named
  `CONFIG_FENCE_REFUSED:<class>`; `server.py main()` hard-exits
  (code 2, class on stderr) at startup; `run_begin` refuses
  live-URL descriptors with the same code. → Test:
  `test_d2_f_b14_fence_battery` (7 config cases, run_begin live
  URL, 4 fresh-process startup refusals).

## Majors

- **M1 — seal counts unsigned/unverified (§4.4/§6.2).** Fix: seal
  signature now over the **canonical seal record** (head hash +
  check/hook-bearing/hookless counts + format version);
  `_verify_presented` recomputes counts + format from presented
  records and verifies that signature. Tampered 999-count seal →
  `SEAL_INVALID`, no manifest; recompute fails step 1. → Test:
  `test_m1_tampered_seal_counts_no_manifest`.
- **M2 — recompute did not authenticate evidence (§6.2).** Fix:
  recompute verifies (1) seal + **receipt harness/vendor
  signatures**, (2) seed/sample + presented-manifest signatures,
  counter-label, and manifest-hash binding to the receipt,
  (3) outcome chain hashes, exact sample order/coverage (extra
  outcomes rejected), and `rerun_chain_head_hash`, (4) verdict,
  face lists, statistic, and recomputed counter-signature label.
  → Tests: `test_m2_forged_receipt_outcomes_pair_fails` (forged
  consistent pair with correctly re-chained outcomes →
  `BENCHKIT_VERIFY_FAIL:1`, signature), `test_m2_broken_chain_and_extra_outcome_fail`
  (broken chain hash, extra outcome, tampered rerun head);
  genuine artefacts + manifest still verify (F-B1/F-B12 control).
  Independent divergent-battery probe: forged pair →
  `verified:false, BENCHKIT_VERIFY_FAIL:1`.
- **M3 — keys hardcoded in source (§7.4).** Fix: all key material
  removed from benchkit.py; keys generated on first use with
  CSPRNG entropy into `keys/` (`vendor.fixture.key`,
  `harness.fixture.key`, `verifier-seed.fixture.key`,
  `verifier-token.fixture.key`), `os.open` chmod **600**,
  gitignored via new `.gitignore`, fixture-labelled via
  `keys/FIXTURE-KEYS.txt`. Verified in the real tree: 4 key files,
  mode 600. → Test: `test_m3_key_custody` (no literal in source,
  files exist, modes 0600, .gitignore covers keys/).
- **M4 — verifier token missing (§5).** Fix: every verifier verb
  enforces `_require_verifier_token` — per-call `verifier_token`
  or `BENCHKIT_VERIFIER_TOKEN` env of the verifier process,
  compared (constant-time) to the `keys/` fixture token; bare or
  wrong token → `VERIFIER_TOKEN_REQUIRED`, no state touched.
  Stdio probe: bare verifier call refused; token-bearing process
  completes the full flow. → Test:
  `test_m4_verifier_token_required`.

## Minors

- **m1 — non-hex 64-char hashes accepted; `pass` over differing
  hashes accepted.** Fix: `is_hex64` on all four hash fields
  (`MALFORMED_HASH`); `verdict_as_run: pass` with expected ≠
  observed → `VERDICT_HASH_MISMATCH`. Note: fabricated fixture
  records were re-pinned as internally consistent lies
  (expected == observed == fabricated hash) — the re-run of the
  hook descriptor is what catches them, F-B12 unchanged. → Test:
  `test_m1_minor_nonhex_hash_and_pass_mismatch`.
- **m2 — hook contents unvalidated.** Fix: `_validate_hook` at
  record time — required fields, hex hashes, hook/record
  expected-hash + determinism agreement, seeded ⇒ seed present,
  descriptor needs server_id/tool/input, non-empty timeout class;
  violations → `MALFORMED_HOOK`. → Test:
  `test_m2_minor_hook_contents_validated`.
- **m3 — `prior_verdict` caller-supplied.** Fix: caller value
  ignored entirely; manifest `prior_verdict` is **derived** from
  stored receipts for the scorecard. → Test: F-B8 rewritten —
  caller lies `VERIFIED_SAMPLE`, manifest still derives
  `DIVERGENT`.
- **m4 — `counter_signatures: "complete"` hardwired.** Fix:
  computed by verifying both signatures over the canonical
  payload (`_counter_status`), for receipts and manifests; a
  receipt stripped of its vendor signature recomputes as
  unverified. → Test: `test_m4_minor_counter_signatures_computed`.
- **m5 — §3.3 return-receipt vs REDRAW_REFUSED wording.** Fix:
  implementation now follows §3.3 literally — resubmitting an
  issued `(scorecard_hash, verifier_nonce)` pair **returns the
  recorded manifest + receipt** (`idempotent_replay: true`), no
  second sample, no second metering event; `REDRAW_REFUSED`
  removed. Anti-shopping intent preserved by D1: no caller nonce
  can start a new draw at all. → Test: F-B8 rewritten
  (`test_f_b8_redraw_replay_and_new_lineage`).

## Verification at fix

- Suite: **27/27 fresh-process OK** (F-B1…F-B14 all enumerated
  now, incl. the previously missing F-B14; disjoint-surface +
  initialize tests; 11 fix regressions).
- Independent probes (stdio, both surfaces, /tmp): vendor tools
  exactly 5, verifier exactly 5; bare verifier call →
  `VERIFIER_TOKEN_REQUIRED`; supplied-nonce grinds (×3) →
  `VERIFIER_NONCE_REFUSED`; old-formula prediction fails on the
  40-check battery; forged divergent pair →
  `BENCHKIT_VERIFY_FAIL:1`; genuine recompute `verified: true`.
- Greps: no network client; no key literal in source; forbidden
  claim strings absent; no Assay/Cupel buy path (HARD RULE).
- Versions bumped to 0.1.1 (benchkit.py, server.json, README).
- No git / catalog / registry actions taken.

**Status: BUILT, pre-bench. STOP — Verity benches next; no self-certification.**
Scope label: **LOCAL / fixture**

## HARD RULE honored (task + spec §0.2, owner ruling 2026-10-27)

Benchkit ships the Assay scorecard FORMAT + spot-check hooks only.
Eclipse Assay and Eclipse Cupel are internal tools: no product
surface, no price, licence, or buy path for them (or for the bench
service) exists in the tool surface, code, README, or server.json —
grep-verified below. The paid bench is stated only as a service
engagement reached through existing intake; no intake form, service
pricing, or entitlement is built. Benchkit's own $10/verification
figure appears solely as the §9.2 metering-point shape for its
spot-check verification (metering record only, no charge path).

## What was built

Python 3 stdlib only, MCP over stdio JSON-RPC. Disjoint surfaces via
`ECLIPSE_BENCHKIT_SURFACE`.

Vendor surface (5 tools):
- `benchkit_run_begin` — opens a scorecard run (open record, chained).
- `benchkit_check_record` — chains one §4.2 check-run record as the
  check runs, hook embedded or `HOOKLESS` on its face; duplicate
  check ids, malformed hashes, post-seal additions refused by name.
- `benchkit_scorecard_seal` — §4.4 seal: head hash, check /
  hook-bearing / hookless counts, format version, vendor signature.
- `benchkit_scorecard_get`, `benchkit_export_get` —
  EXPORTED_SELF_BENCH (`verification: none`) or DOWNGRADED_EXPORT
  (SEAL_BROKEN) after chain recompute; downgrade is terminal.

Verifier surface (5 tools):
- `spotcheck_request` — verifies the presented seal first
  (SEAL_INVALID / PRE_SEAL_SAMPLE receipted as anomalies), refuses
  vendor-supplied nonces by name, generates the verifier nonce,
  derives the seed `sha256(scorecard_hash|verifier_nonce)`, draws the
  sample (k = 30 or all hook-bearing), issues the counter-signed §4.5
  manifest; same-nonce re-draw after a receipt → REDRAW_REFUSED, a
  new nonce records the prior verdict in its lineage.
- `spotcheck_run` — re-runs sampled checks against the fixture vendor
  server from the hooks alone; idempotent per (scorecard_hash,
  nonce); verdict VERIFIED_SAMPLE / DIVERGENT (ids named) /
  UNVERIFIABLE (non-deterministic or secret-requiring hooks);
  counter-signed receipt stating k, f = 0.10, and the recomputed
  detection probability 1 − (1−f)^k; exactly one metering event.
- `spotcheck_receipt_get`, `spotcheck_recompute` (pure §6.2 recompute,
  failures named `BENCHKIT_VERIFY_FAIL:<step>`),
  `anomaly_queue_read`.

Fixtures (7 batteries): battery-good-40, battery-small-8,
battery-honest-failures, battery-hookless, battery-flaky,
battery-secret-hook, battery-fabricated-40 (12 of 40 fabricated over
the fabricated-source server — the decisive F-B12 battery; with
k = 30 over 28 honest checks a catch is arithmetically forced, and
the fixture asserts the named fabricated ids).

## Verification at build

- Suite: **16/16** — F-B1 full honest run (k=30, detection 0.957609,
  §6.2 recompute passes), F-B2 small battery (k=8 stated), F-B3
  honest failures seal + verify as matches, F-B4 idempotent
  verification (1 metering event), F-B5 post-seal edit → SEAL_INVALID
  + DOWNGRADED_EXPORT, F-B6 pre-seal sample refused + queued, F-B7
  vendor nonce refused, F-B8 re-draw refused / new nonce lineage,
  F-B9 hookless excluded from every sample, F-B10 non-deterministic
  sampled → UNVERIFIABLE named, F-B11 secret hook → UNVERIFIABLE,
  F-B12 fabricated scorecard → DIVERGENT with fabricated ids named +
  arithmetic recomputed, F-B13 downgrade terminal + fresh lineage
  with supersedes verifies, surface disjointness + no buy-path verbs,
  initialize name.
- Smoke over stdio: initialize correct, vendor tools = 5.
- Internal-tools grep: no buy/licence/checkout language for Assay or
  Cupel in code/README/server.json (SPEC.md excluded as governing
  text); forbidden claim strings (§11/B-B8) absent.
- No network client in the tree (grep clean).
- SPEC.md byte-identical to
  `argus101-specs-20261027/benchkit-spec.md`.

## Gates honored

- Pre-public counsel gate (§10: name screen + statistical-claims
  review + §0.2 confirmation) is a review of language before any
  public listing — nothing public is made here; working name only.

## Walls / build pins for Verity

- Spec tension flagged: §4.2 calls non-deterministic checks
  "excluded from samples", while F-B10 requires a sampled
  non-deterministic check to resolve UNVERIFIABLE. Build follows
  F-B10 (the enumerated fixture): hook-bearing non-deterministic
  checks are sample-eligible and resolve UNVERIFIABLE at re-run —
  they never count toward a verified claim, which is §4.2's intent.
- Sample-size pin (Q-B1): fixed k = 30 or all hook-bearing checks if
  fewer; receipts state the k actually used.
- Vendor counter-signature pin (Q-B4): at manifest draw + receipt
  issuance; a receipt's face carries `counter_signatures: complete`
  only when both signatures are present.
