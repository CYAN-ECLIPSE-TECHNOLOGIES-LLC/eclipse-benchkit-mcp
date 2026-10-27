# Eclipse Benchkit

A free, local SDK a vendor runs against their own MCP server to
execute their declared check battery and emit a scorecard in the
Assay scorecard format — check ids, verdicts, evidence hashes,
environment fingerprint — with a spot-check hook embedded in every
check entry as it runs. A separate local harness draws a random
sample from the sealed scorecard and re-runs those checks, issuing a
counter-signed verification receipt.

**Scope label: LOCAL / fixture.** v0.1 is exercised only against
fixture vendor servers. No live vendor server, no network call, no
registry.

**Status: v0.1.1 — CERTIFIED (local/fixture). Verity re-bench
2026-10-27: all v0.1.0 FAIL defects (D1/D2 blockers, M1–M4 majors,
m1–m5 minors) closed and independently verified; builder suite
27/27. Two new minors (N1 fence-encoding edges, N2 seed-commitment
provenance) are recorded for the next fix loop and do not gate this
scope. The certification binds exactly this scope: the SDK, emitter,
and spot-check harness against fixture vendor servers only. A
spot-check receipt is a statement about a sample of one sealed
scorecard — not a house bench verdict and not a certification of any
vendor server.**

## v0.1.1 protocol notes

- **Commit-then-sample, unpredictable (D1).** The verifier nonce is
  generated verifier-side from a secret seed held in `keys/` plus
  fresh CSPRNG entropy, and revealed only in the sample manifest
  after the seal is verified. It is never a caller input for a new
  draw and cannot be precomputed from the scorecard hash or any
  public state. A supplied nonce is honoured only as a replay key
  for an already-issued `(scorecard_hash, verifier_nonce)` pair,
  which returns the recorded receipt (§3.3); a novel supplied nonce
  is refused by name.
- **Verifier token (§5, M4).** Verifier verbs require the verifier
  token: the fixture token in `keys/verifier-token.fixture.key`
  (chmod 600, gitignored), presented per call as `verifier_token`
  or via `BENCHKIT_VERIFIER_TOKEN` in the verifier process.
- **Config fence (§7.3, F-B14).** Startup hard-exits with
  `CONFIG_FENCE_REFUSED:<class>` on a non-local endpoint, a live-key
  string, a vendor-nonce config, a non-`test` value_class, or an
  Assay/Cupel price-or-checkout config; live-URL server descriptors
  are refused at `benchkit_run_begin` with the same named code.
- **Authenticated artefacts (M1/M2).** The seal signature binds the
  head hash, all counts, and the format version; recompute verifies
  receipt signatures, the outcome record chain, and the rerun chain
  head, and rejects extra outcomes.
- **Keys (§7.4, M3).** All fixture keys are locally generated in
  `keys/` (chmod 600, gitignored, fixture-labelled). No key material
  exists in source.

## Novel mechanism

Vendor-run scorecards embed spot-check hooks; the house bench re-runs
a random sample, so a fabricated self-bench is statistically
detectable. The protocol is commit-then-sample: the scorecard is
sealed (hash-chained, vendor-signed) before any sample exists, and the
sample seed derives from `scorecard_hash ‖ verifier_nonce`, the nonce
revealed only after the seal is presented. The receipt states the
arithmetic on its face: at sample size `k` and fabricated fraction
`f`, detection probability is `1 − (1−f)^k` — default `k = 30` (or all
hook-bearing checks if fewer), powered at `f ≥ 0.10` → detection
≥ 95%. A check without a hook is labelled `HOOKLESS` on the
scorecard's face and is outside every sample and every verified
claim; a sampled non-deterministic or secret-requiring check resolves
to `UNVERIFIABLE`, never to a silent pass. Receipt verdicts:
`VERIFIED_SAMPLE` · `DIVERGENT` (mismatched check ids named) ·
`UNVERIFIABLE`.

Every vendor scorecard is labelled **vendor-run / self-bench** on its
face. A spot-check receipt says only that a random sample of `k` of
`N` hook-bearing checks was re-run and matched (or diverged — verdict
as issued), powered to detect fabrication at fraction ≥ `f` with
probability `p`. It is not a house bench verdict and not a
certification of the vendor's server, and it never upgrades a
self-bench into one. Unverifiable scorecards export only as
`DOWNGRADED_EXPORT`, never upgraded post-hoc.

Format attribution, exact and minimal: scorecard emitted in the
Assay scorecard format. Eclipse Assay and Eclipse Cupel are internal
tools; Benchkit consumes their scorecard format as a specification
only and contains no product surface, price, licence, or buy path for
them. The full bench is a paid service engagement; intake via the
existing route — Benchkit contains no intake form, no engagement
checkout, and no service pricing. Benchkit's own metering point is
one `spotcheck_verification_completed` event per completed
verification ($10/verification shape, metering record only, no charge
path in this build), keyed to `(scorecard_hash, verifier_nonce)` so
idempotent returns do not double-meter.

## Tools

Vendor surface (default, `ECLIPSE_BENCHKIT_SURFACE=vendor`):
`benchkit_run_begin`, `benchkit_check_record`,
`benchkit_scorecard_seal`, `benchkit_scorecard_get`,
`benchkit_export_get`.

Verifier surface (`ECLIPSE_BENCHKIT_SURFACE=verifier`):
`spotcheck_request`, `spotcheck_run`, `spotcheck_receipt_get`,
`spotcheck_recompute`, `anomaly_queue_read`.

Surfaces are disjoint; cross-surface calls return the identical
unknown-tool refusal as a nonsense name. Pre-seal sample attempts,
vendor-supplied nonces, and same-nonce re-draws after a verdict are
refused by name and receipted in the anomaly queue.

## Fixtures

`fixtures/battery-*.json` — deterministic fixture batteries over
fixture vendor servers: good (40 checks), small (8), honest failures
(3 genuinely failing checks sealed as failures), hookless (5 of 12),
flaky (one non-deterministic check), secret-hook (one un-runnable
hook), fabricated (40 claimed checks, 12 fabricated, over the
`fabricated-source` server — the decisive fixture: the seeded
spot-check must catch at least one).

## Run

```
python3 server.py            # MCP over stdio JSON-RPC
python3 -m unittest discover -s tests -v
```

State lives in `data/` or `BENCHKIT_DATA_DIR`. Python 3, standard
library only.

Powered by Cyan Eclipse Technologies — https://cetech.ai

MIT License · Copyright © 2026 Cyan Eclipse Technologies LLC · cetech.ai
