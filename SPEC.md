# Eclipse Benchkit — Spec

Name is a placeholder pending trademark screen.

## AMENDMENTS

- **2026-10-27 (Verity bench ruling, bench-benchkit.md — F-B10 governs over §4.2):** hook-bearing non-deterministic checks are sample-eligible; if sampled they resolve `UNVERIFIABLE`, are named, and never count toward any verified claim in any aggregate. §4.2's parenthetical is amended from "excluded from samples; counts against verified claims" to "excluded from verified claims (§11.5)". Build behaviour already followed F-B10; the defective text was §4.2's.
- **2026-10-27 (v0.1.1 fix loop, defects D1/M1/M2 in bench-benchkit.md):** §2.2.2/§4.4/§6.2 tightened to the fixed implementation — the verifier nonce is verifier-generated from a verifier-side secret seed plus fresh CSPRNG entropy, is never a caller input for a new draw (a supplied nonce is honoured only as the §3.3 replay key of an already-issued pair), and the seal signature binds the canonical seal record (head hash + counts + format version); §6.2 recompute additionally verifies receipt signatures, the outcome record chain, and the rerun chain head.

**Powered by Cyan Eclipse Technologies** — https://cetech.ai
**Working name:** Eclipse Benchkit (Argus 101 #69). Public use is hard-gated on the house name screen (brand + trademark/confusion screen) — the working name is not a public claim.
**Stage:** SPEC (Silas) · **Date:** 2026-10-27 · **Status:** buildable, bench-pending, no certification claimed
**Size:** M · **Buyer:** MCP vendors (funnel to the paid bench service)
**Governing inputs:** `argus-101-20261027.md` #69 · `mpp-session-witness-spec-20261026.md` (§0–§2, §8 house pattern) · owner ruling 2026-10-27 (Assay/Cupel internal-tools constraint, §0.2)

## 0. Scope + cert-scope target + laws binding

- **0.1 Scope (v0.1, local only).** A local SDK + Assay-scorecard-format emitter + spot-check re-run harness, exercised only against fixture vendor servers. The SDK runs a vendor's own checks locally, emits a sealed scorecard with embedded spot-check hooks (§4), and the harness re-runs a random sample of those checks (§3, §5). No live vendor server, no network call, no registry, no production environment exists in v0.1.
- **0.2 HARD CONSTRAINT — Assay / Cupel are internal tools, not products (owner ruling 2026-10-27, load-bearing).** Benchkit emits the **Assay scorecard format** for vendor self-benching **only**. Eclipse Assay and Eclipse Cupel are **internal tools**. This spec does **not** present them as products, and specs **no** buy path, price, licence, or checkout for them — in the tool surface (§5), pricing (§9), exports (§6), labels (§11), or anywhere else. Any Benchkit text implying Assay or Cupel can be bought, licensed, subscribed to, or checked out is a spec defect and a bench failure (§13, B-B7).
- **0.3 The paid bench is a service, not a Benchkit feature.** The paid bench is a **service engagement reached through existing intake**, external to this product. Benchkit may state that fact and point to the existing intake route; it contains no intake form, no engagement checkout, no service pricing, and no entitlement created by SDK use or by a spot-check verification (§12.1).
- **0.4 Cert-scope target.** `Benchkit — <VERDICT>(local/fixture)` at most: the bench verdict covers the SDK, emitter, and harness against fixture vendor servers in §8 only. A spot-check verification is a statement about a **sample of one sealed scorecard** (§11) — it is not a house bench verdict, not a certification of the vendor's server, and never upgrades a self-bench into one.
- **0.5 Downgrade law.** Unverifiable scorecards export as **downgraded, never upgraded post-hoc** (§6.3). No tool, receipt, or operator act converts a downgraded export into a verified one; the only path is a new sealed scorecard and a new sample.
- **0.6 Pay-for-evaluation, never outcome.** The §9 metering point attaches to a spot-check verification **being run and receipted**, whatever its verdict. No surface sells a passing verdict, a better sample, or a re-draw.
- **0.7 Novelty law.** The product is its §2 mechanism. A scorecard emitter without sealed spot-check hooks and post-seal sample re-runs is a test-report formatter and fails this spec, however polished.

## 1. Product definition

- **1.1 What it is.** A free, local, stdio/Python-stdlib-pattern SDK a vendor runs against their own MCP server to (a) execute their declared check battery, (b) emit a scorecard **in the Assay scorecard format** — check ids, verdicts, evidence hashes, environment fingerprint, in the format's field order and verdict vocabulary — and (c) embed in every check entry a **spot-check hook**: a deterministic re-run recipe (§4.2) by which a re-runner can re-execute that check later and compare results. A separate local harness (the verifier side, §5) draws a random sample from a **sealed** scorecard and re-runs those checks against the vendor server, issuing a counter-signed verification receipt (§6).
- **1.2 The hole it fills.** Vendor self-benches are currently self-attested prose or CI screenshots: a registry or buyer cannot distinguish a real run from a written-up one without paying for a full independent bench. Benchkit makes the self-bench itself evidentiary — cheap to produce honestly, statistically dangerous to fabricate (§2) — and funnels vendors who need the full verdict to the paid bench **service** via existing intake (§0.3).
- **1.3 What it is not.** Not the house bench. Not a certification issuer. Not a registry. Not a test runner of record for anyone's CI. Not a distribution channel, licence server, or storefront for any internal tool (§0.2).
- **1.4 Components.** (1) SDK library + CLI (vendor side). (2) Scorecard emitter (canonical form, hash chain, vendor signature). (3) Hook registry (per-check re-run recipes). (4) Spot-check harness (verifier side: sample draw, re-run, compare, receipt). (5) Fixture vendor servers (good / flaky / fabricated) for the bench (§7, §8).

## 2. Novel mechanism (verbatim) + N-check

- **2.1 Novel mechanism (one sentence, the bench's subject).** **vendor-run scorecards embed spot-check hooks; the house bench re-runs a random sample, so a fabricated self-bench is statistically detectable.**
- **2.2 The three parts (one chain).**
  1. **Hooks embedded at run time.** Each check entry carries its re-run recipe — invocation descriptor, input/fixture hash, expected-output hash, determinism class (§4.2) — written by the SDK **as the check runs**, not authored afterwards. A check without a hook is labelled `HOOKLESS` on the scorecard's face and is outside every sample and every verified claim.
  2. **Commit-then-sample.** The scorecard is sealed (hash-chained, vendor-signed, §4) **before** any sample exists. The sample seed derives from `scorecard_hash ‖ verifier_nonce`, the nonce revealed only after the seal is presented — the vendor cannot know which checks will be re-run when fabricating, and cannot edit the scorecard after seeing the sample without breaking the seal. The nonce is **verifier-generated only** (amended 2026-10-27, D1): derived under a verifier-side secret seed (held in `keys/`, §7.4, its commitment predating any vendor submission in verifier custody) plus fresh CSPRNG entropy; it is never a caller input for a new draw and never derivable from `scorecard_hash` or any public state. A caller-supplied nonce is honoured only as the §3.3 replay key of an already-issued `(scorecard_hash, verifier_nonce)` pair; a novel supplied nonce is refused by name.
  3. **Sample re-run + statistics on the receipt.** The harness re-runs the sampled checks and the receipt (§6) states `sample_size`, the fabrication fraction the sample was powered to detect, and the detection probability — the claim is the arithmetic, recomputable by anyone: at sample size `k` and fabricated fraction `f`, detection probability is `1 − (1−f)^k`. **Default:** `k = 30` (or all hook-bearing checks if fewer than 30), powered at `f ≥ 0.10` → detection ≥ 95% (1 − 0.9³⁰ ≈ 0.958); at `f = 0.25`, ≥ 99.9%.
- **2.3 N-check — nearest incumbents and the defining test they fail.**
  - **Vendor self-reported results** (READMEs, badges, listing claims): no hooks, no seal, no sample — nothing to re-run and nothing binding the claim to a run.
  - **Generic test runners / CI output** (pytest-style logs, CI artefacts): prove a suite ran in the vendor's own pipeline; ship no per-check re-run recipe addressed to an outside verifier, no commit-then-sample protocol, and no detection statistic.
  - **Registry install/handshake checks:** verify a server installs and speaks MCP; they do not re-run the vendor's claimed bench checks at all.
  - **Defining test (the bench runs it as F-B12, §8):** *given a deliberately fabricated sealed self-bench scorecard, the spot-check sampling catches the fabrication at the stated rate, from the scorecard + hooks alone.* Each incumbent above fails it for the stated reason; an emitter without §2.2 parts 2–3 fails it by construction.

## 3. Lifecycle / state machine

```
  (no scorecard) ──run──► RUNNING ──all checks executed──► SEALED
  SEALED ──verifier nonce presented──► SAMPLE_DRAWN ──re-run──► RE_RUNNING
  RE_RUNNING ──► VERIFIED_SAMPLE | DIVERGENT | UNVERIFIABLE   (receipt issued, §6)
  SEALED ──export without verification──► EXPORTED_SELF_BENCH
  any post-seal state ──hook/seal defect──► DOWNGRADED_EXPORT (terminal for that scorecard, §6.3)
```

- **3.1 No state is reachable by skipping a predecessor.** `SAMPLE_DRAWN` without `SEALED` does not exist (a sample drawn before the seal is protocol-invalid and receipted as a violation, §5); `VERIFIED_SAMPLE` without a completed re-run does not exist. State changes only via the transitions above; each appends to the scorecard's hash-chained record stream (§4).
- **3.2 Verdicts (enum, on the receipt's face).** `VERIFIED_SAMPLE` (every sampled re-run matched) · `DIVERGENT` (≥1 sampled re-run mismatched — the mismatched check ids are named) · `UNVERIFIABLE` (hooks missing, non-deterministic, or un-runnable for ≥1 sampled check). No free-text verdicts in signed objects.
- **3.3 Idempotency / replay posture.** A spot-check request is keyed to `(scorecard_hash, verifier_nonce)`: resubmission with both identical returns the recorded receipt (no second sample, no second metering event, §9); the same `scorecard_hash` with a different nonce is a **new** verification; a scorecard hash that does not match its presented records is a seal defect → `DOWNGRADED_EXPORT`.

## 4. Data model + record formats

- **4.1 Canonical form + chain (house pattern).** Every record is canonical JSON (sorted keys, no floats for amounts/counts); `record_hash = sha256(canonical(record minus hash/signature fields) ‖ prev_hash)`. Seq is 1-based and gapless per scorecard.
- **4.2 Check-run record (one per executed check, vendor-signed).**

  | Field | Rule |
  |---|---|
  | `record_id` | `chk_` + 16 hex |
  | `record_type` | `"benchkit_check_run"` |
  | `value_class` | `"test"` in v0.1 (§7) |
  | `scorecard_id` | the scorecard this run belongs to |
  | `check_id` | vendor-declared id, unique per scorecard, in Assay scorecard format vocabulary |
  | `seq` / `prev_hash` / `record_hash` | per §4.1; seq 1's `prev_hash` = the scorecard-open record hash |
  | `invocation_hash` | hash of the exact tool/resource invocation the check performed |
  | `input_hash` | hash of the check's input/fixture as run |
  | `expected_output_hash` / `observed_output_hash` | as run; equality is the check's own verdict input, not the verifier's |
  | `verdict_as_run` | `pass` / `fail` in scorecard-format vocabulary — a vendor may seal failing checks; sealing is about evidence, not success |
  | `hook` | the spot-check hook (§4.3), or `null` → entry is `HOOKLESS` (§2.2.1) |
  | `determinism_class` | `deterministic` / `seeded` (seed inside the hook) / `non-deterministic` (excluded from verified claims, §11.5; sample-eligible per the 2026-10-27 Verity F-B10 ruling in AMENDMENTS — if sampled it resolves `UNVERIFIABLE` and is named, §3.2/F-B10) |
  | `env_fingerprint` | hash of server version + config descriptor as presented at run time |
  | `ts` | RFC 3339 UTC, SDK-stamped at run time |
  | `signature` | vendor key over `record_hash` (fixture key in v0.1, §7.4) |

- **4.3 Spot-check hook (the §2 object).** `{ hook_version, invocation_descriptor, input_ref_or_inline_hash, expected_output_hash, determinism_class, seed_if_seeded, timeout_class }`. The descriptor must be sufficient for the harness to re-execute the check **without vendor cooperation beyond the server itself**; a hook that requires vendor-side secrets or manual steps is `UNVERIFIABLE` by definition.
- **4.4 Scorecard seal record.** Terminal record of the run stream: `scorecard_hash` (head hash of the chain), `check_count`, `hook_bearing_count`, `hookless_count`, `format_version` (Assay scorecard format version emitted), vendor signature over the **canonical seal record** — head hash, all counts, and format version bound together (amended 2026-10-27, M1; verification also recomputes the counts from the presented records, §6.2 step 1). The seal is what §3 commit-then-sample binds to.
- **4.5 Sample manifest record (verifier-side, counter-signed).** `{ scorecard_hash, verifier_nonce, seed_derivation, sample_size_k, powered_fraction_f, detection_probability, sampled_check_ids (in draw order) }`, signed by the harness key at draw time and **counter-signed by the vendor key** on receipt presentation (the vendor attests the sample was drawn from their sealed scorecard — they do not choose it). Re-run outcome records chain off the manifest in the same §4.1 form, each carrying `rerun_output_hash` + `match: true|false`.

## 5. MCP tool surface

Selected by `ECLIPSE_BENCHKIT_SURFACE` (`vendor` default, `verifier`). Tables are **disjoint**: a verifier verb called on the vendor surface returns the identical unknown-tool refusal as a nonsense name (no oracle), and vice versa. Verifier verbs require the verifier token.

**Vendor surface:**

| Tool | Inputs → outputs |
|---|---|
| `benchkit_run_begin` | server descriptor + check battery manifest → `scorecard_id`, open record |
| `benchkit_check_record` | one executed check's §4.2 fields → chained run record (or named refusal: malformed hash, duplicate `check_id`, non-integer field) |
| `benchkit_scorecard_seal` | `scorecard_id` → §4.4 seal record + `scorecard_hash` |
| `benchkit_scorecard_get` | `scorecard_id` → sealed scorecard + all run records |
| `benchkit_export_get` | `scorecard_id` → export (§6): `EXPORTED_SELF_BENCH` or `DOWNGRADED_EXPORT` |

**Verifier surface:**

| Tool | Inputs → outputs |
|---|---|
| `spotcheck_request` | `scorecard_hash` + presented scorecard → verifier nonce + §4.5 sample manifest (refused by name if the seal does not verify: `SEAL_INVALID`) |
| `spotcheck_run` | `sample_manifest_id` → re-run outcome records against the fixture vendor server |
| `spotcheck_receipt_get` | `sample_manifest_id` → §6 verification receipt (counter-signed) |
| `spotcheck_recompute` | receipt + scorecard + outcome records → pure recompute of verdict + detection statistic (no state, no harness) |
| `anomaly_queue_read` | pre-seal sample attempts, seal defects, replay attempts, receipted as violations |

**Forbidden on both surfaces (do not exist):** any verb that buys, licenses, subscribes to, activates, or checks out Eclipse Assay or Eclipse Cupel (§0.2); any verb issuing a house bench verdict or certification; any verb that re-draws a sample after a `DIVERGENT` verdict under the same nonce, edits a sealed record, adds a hook post-seal, or upgrades a downgraded export. Absence is bench-checked by dispatch-table enumeration (§13, B-B6).

## 6. Receipts / exports + downgrade semantics

- **6.1 Verification receipt (signed object).** `{ receipt_id, scorecard_hash, sample_manifest_hash, rerun_chain_head_hash, verdict (§3.2), sample_size_k, powered_fraction_f, detection_probability, mismatched_check_ids (if DIVERGENT), unverifiable_check_ids (if UNVERIFIABLE), value_class: "test", issued_at }`, carrying **two signatures**: harness (always) + vendor (counter-signature attesting the sealed scorecard was theirs; §4.5 pattern). A receipt with the vendor counter-signature outstanding is labelled `counter_signatures: partial` on its face.
- **6.2 Offline verification (normative; artefacts + public keys only).** (1) Recompute the run chain and require head = receipt `scorecard_hash`, the seal signature valid over the canonical seal record with counts/format recomputed from the presented records (§4.4), **and the receipt's harness + vendor signatures valid over the canonical receipt payload** (amended 2026-10-27, M1/M2). (2) Re-derive the seed from `scorecard_hash ‖ verifier_nonce` and require the sampled ids = the manifest's, in order; when a manifest is presented, its signatures, counter-signature label, and hash binding to the receipt are verified. (3) For each sampled check, recompute `match` from `rerun_output_hash` vs the sealed `observed_output_hash`, **verify the outcome record chain and require its head = receipt `rerun_chain_head_hash`, and reject any extra or out-of-sample outcome** (amended 2026-10-27, M2). (4) Recompute the verdict and the detection statistic from `k` and `f`, and recompute the receipt's `counter_signatures` label from its signatures (§6.1) rather than trusting the face value. Any step failing names its step; the verifier returns `BENCHKIT_VERIFY_FAIL:<step>` with no partial "mostly valid" verdict.
- **6.3 Downgrade semantics (the §0.5 law, operational).** A scorecard with a broken seal, a post-seal edit, missing/non-runnable hooks on sampled checks beyond the `UNVERIFIABLE` verdict's own record, or a sample drawn pre-seal exports **only** as `DOWNGRADED_EXPORT`: unsigned summary, `verified: false`, downgrade reason from the enum (`SEAL_BROKEN` / `HOOK_MISSING` / `HOOK_UNRUNNABLE` / `SAMPLE_PROTOCOL_VIOLATION`) on its face. **Never upgraded post-hoc:** no receipt can be issued over a downgraded export; remediation is a new run, a new seal, a new sample — a new lineage, linked by `supersedes` at most.
- **6.4 Self-bench export.** An unverified sealed scorecard exports as `EXPORTED_SELF_BENCH` with `verification: none` on its face. It is evidence of a run, labelled vendor-run everywhere it appears (§11) — never rendered as house-verified.

## 7. Fixture discipline + config fence

- **7.1 Fixture vendor servers.** Three deterministic local fixtures: `good` (all checks genuinely pass), `flaky` (seeded non-determinism in named checks), `fabricated-source` (a real server whose genuine results differ from the fabricated scorecard built over it, §8 F-B12). Fixture ids deterministic under a seed; all runs socket-denied.
- **7.2 value_class.** Every artefact — run record, seal, manifest, outcome, receipt, export — carries `value_class: "test"`.
- **7.3 Fail-closed fence.** Startup refuses (hard exit, `CONFIG_FENCE_REFUSED:<class>`) on: any non-local endpoint or live vendor-server URL; any live-key string; `value_class ≠ "test"`; a sample seed or nonce supplied by the vendor side (the nonce is verifier-generated, §2.2.2); any config naming a price, licence, or checkout for Assay or Cupel (§0.2 — the fence treats their presence as a defect, not a feature). No network client exists in v0.1 code — absence is bench-grepped (§13, B-B5).
- **7.4 Keys.** Vendor + harness keys are locally generated fixture keys (`keys/`, chmod 600, gitignored). The harness key signs manifests, outcomes, and receipts only; it is not a bench key and its signature asserts a sample re-run, never a house verdict (§11).

## 8. Bench fixtures enumerated

House style (unittest, deterministic, socket-denied). All artefacts `value_class: "test"`.

**Happy path**
- **F-B1 Full honest run:** `good` fixture, 40 deterministic checks → seal → sample `k=30` → all re-runs match → `VERIFIED_SAMPLE` receipt, 2 signatures → §6.2 verify **passes**.
- **F-B2 Small battery:** 8 hook-bearing checks (< `k`) → sample = all 8; statistic recomputed for `k=8` and stated as such on the receipt (no borrowed power from the default).
- **F-B3 Honest failures sealed:** battery with 3 genuinely failing checks seals normally; sampled failures re-run as failures and **match** — verdict `VERIFIED_SAMPLE` (the mechanism verifies honesty, not success).
- **F-B4 Idempotent verification:** identical `(scorecard_hash, verifier_nonce)` resubmitted → recorded receipt returned; no second sample, no second §9 metering event.

**Seal + sample protocol**
- **F-B5 Post-seal edit:** flip one `observed_output_hash` after sealing → chain recompute fails; `spotcheck_request` → `SEAL_INVALID`; only `DOWNGRADED_EXPORT` (reason `SEAL_BROKEN`) issuable.
- **F-B6 Pre-seal sample attempt:** sample requested before a seal exists → refused by name and receipted in the anomaly queue; no manifest issued.
- **F-B7 Vendor-supplied nonce:** config/request carrying a vendor-chosen nonce → refused; fence class named. Seed re-derivation from a substituted nonce fails §6.2 step 2.
- **F-B8 Re-draw shopping:** after a `DIVERGENT` verdict, same-nonce re-draw request → refused; a new nonce produces a new manifest whose lineage names the prior verdict.

**Hook battery**
- **F-B9 Hookless checks:** battery with 5 `HOOKLESS` entries → sealed with `hookless_count: 5` on the face; hookless ids never appear in any sample; verified claims in exports exclude them.
- **F-B10 Non-deterministic check sampled:** `flaky` fixture check drawn in the sample → outcome `UNVERIFIABLE` for that check, verdict `UNVERIFIABLE`, check named; no silent re-run-until-match (re-run count is itself a chained record).
- **F-B11 Un-runnable hook:** hook descriptor requiring a vendor secret → `UNVERIFIABLE` by definition (§4.3); export of any verified claim over that scorecard refused.

**Decisive + downgrade**
- **F-B12 THE decisive fixture (N-check, §2.3):** a **deliberately fabricated** sealed self-bench scorecard — 40 claimed checks over the `fabricated-source` server, **12 fabricated (f = 0.30)** with plausible hooks and outputs — is sealed **before** the nonce is revealed; the seeded spot-check (`k = 30`) re-runs the sample and **must catch ≥1 fabricated check**, verdict `DIVERGENT`, fabricated ids named. Detection arithmetic on the receipt recomputes (§6.2 step 4): at `f = 0.30, k = 30`, detection probability ≈ 99.998% — and the deterministic fixture seed makes the catch actual, not merely probable. A harness that passes this scorecard has not benched this product.
- **F-B13 Downgrade is terminal:** take the F-B5 downgraded export; attempt every tool path to verify or upgrade it → all refused; a fresh honest run over the same server produces a **new** scorecard lineage that verifies normally (`supersedes` link only).
- **F-B14 Fence battery:** non-local endpoint, live-key string, vendor nonce config, and an Assay/Cupel price-or-checkout config string → startup refused with the named fence class in each case; tree grep finds no network client and no Assay/Cupel buy-path string outside the fence table + negating docs.

## 9. Pricing hooks

- **9.1 Metering points only.** This spec defines **metering events**, not charge paths: no checkout, no payment collection, no entitlement logic is built under this spec; any charging rides existing house gates and the existing price book.
- **9.2 Events.** (a) `sdk_distribution` — **FREE** (funnel; counted, never metered for charge). (b) `spotcheck_verification_completed` — metered at the **$10/verification** Benchkit pattern: one event per completed verification (receipt issued, any §3.2 verdict), keyed to `(scorecard_hash, verifier_nonce)` so F-B4 idempotent returns do not double-meter.
- **9.3 What the $10 is not.** It prices **Benchkit's own spot-check verification hook only**. It is not a price for Eclipse Assay, Eclipse Cupel, or the paid bench service (§0.2, §0.3) — the paid bench service's terms live in its service engagement via existing intake and appear nowhere in this product, its receipts, or its listings.

## 10. Counsel gate

- **10.1 One gate, pre-public.** Before any public listing, paid verification, or marketing claim: (a) trademark/name screen for the working name (header line); (b) claims review of the statistical language (§2.2.3, §11) — detection probability must be reviewed as a sampling statement, never a guarantee that a given scorecard is honest; (c) confirmation that no surface implies Assay/Cupel availability (§0.2). The gate is a review of language and labels; it does not convert the internal tools into products and must not be recorded as doing so.
- **10.2 No live gate in v0.1.** v0.1 is local/fixture (§0.1); there is no live mode to clear. Any future live-server scope is a post-gate, re-benched code change, not a config flip (§7.3 fence has no live path to enable).

## 11. Honest-label rules

- **11.1** Claims are **verdict + scope only**: `Benchkit — <VERDICT>(local/fixture)` once benched; before the bench: "bench pending — no certification is claimed."
- **11.2** Every vendor scorecard is labelled **vendor-run / self-bench** on its face and in every listing. A spot-check receipt may be described only as: "a random sample of `k` of `N` hook-bearing checks was re-run and matched (or diverged — verdict as issued), powered to detect fabrication at fraction ≥ `f` with probability `p`." Never "verified server," never "house-benched," never "certified."
- **11.3** Format attribution is exact and minimal: "scorecard emitted in the Assay scorecard format." Never "powered by Assay," never "Assay-verified," never "Cupel-tested," and no wording presenting Assay or Cupel as obtainable products or services (§0.2).
- **11.4** The funnel statement, where used, is factual only: "The full bench is a paid service engagement; intake via the existing route." No price, licence, checkout, or entitlement language for that service appears in Benchkit surfaces (§0.3, §9.3).
- **11.5** `HOOKLESS` and `non-deterministic` checks are visibly excluded from verified claims wherever counts appear; a listing may not quote a check count that silently includes them.

## 12. Boundaries + dependencies

- **12.1 Assay / Cupel (internal tools).** Dependency is **format-only**: Benchkit consumes the Assay scorecard format (field order, verdict vocabulary, format version) as a specification. Eclipse Assay and Eclipse Cupel remain internal tools — Benchkit does not invoke them as a service, embed them, license them, resell them, or expose their surfaces. The **paid bench is a service engagement reached through existing intake, not a Benchkit feature** (§0.3).
- **12.2 Fixture vendor servers (§7.1).** v0.1's only re-run targets. Live vendor servers are out of scope and fenced (§7.3), not merely unimplemented.
- **12.3 Signing / Herald pattern.** Vendor + harness signatures follow the house counter-signed record pattern by re-implementation; no internal tool's key, code, or verdict is reused. Fixture keys only (§7.4).
- **12.4 Meter.** §9 metering events are emitted in Meter's record grammar for later ingest; v0.1 does not modify or call Meter and claims no live ingest. Meter reports; Benchkit does not block on it.
- **12.5 Bazaar / registries.** A listing may carry a §6.4 self-bench export or a §6.1 receipt as vendor-supplied evidence, labelled per §11. No registry surface is extended by this spec, and no listing state changes on a Benchkit verdict alone.
- **12.6 Own repo.** Build lands in its own repo (PRIVATE default, secret sweep + `.gitignore` before first commit) per standing house rule; this spec creates no repo.

## 13. Bench criteria

- **B-B1** §8 fixtures F-B1…F-B14 pass as enumerated, deterministically, socket-denied, on a clean checkout.
- **B-B2 The novel mechanism is what is verified (§2.1):** F-B12 passes — the fabricated scorecard is caught at the stated rate with the catch recomputable from the receipt (§6.2). A bench that only checks scorecard formatting has not benched this product.
- **B-B3** State machine (§3): no transition skips a predecessor — fuzzed call sequences produce only legal transitions or named refusals; commit-then-sample ordering is enforced under adversarial call order (F-B6, F-B7, F-B8).
- **B-B4** Refusal completeness: every named refusal in §5/§7 is reachable by its fixture and mutates no state (chain/total/sample diffed before/after).
- **B-B5** Fence + absence greps (§7.3, F-B14) clean; `value_class: "test"` on 100% of emitted artefacts.
- **B-B6** Surface disjointness (§5): dispatch tables enumerated; forbidden verbs absent from both surfaces; cross-surface calls return the unknown-tool refusal identically.
- **B-B7 Internal-tools constraint (§0.2):** tree-wide grep finds **no** buy path, price, licence, or checkout language for Eclipse Assay or Eclipse Cupel outside negating text (this spec's prohibitions, the fence table); any listing/README copy presenting either as a product fails the bench outright.
- **B-B8** Honest labels (§11) verbatim in README/manifest; forbidden claim strings ("house-benched", "Assay-verified", "certified server") absent tree-wide.
- **B-B9** Downgrade terminality (F-B13): no tool path, including operator-side sequences, upgrades a downgraded export.

## 14. Open questions for build stage

- **Q-B1** Sample size for very large batteries: fixed `k = 30` (assumed) vs tiered `k` by battery size — build pins one rule; receipts must state the `k` actually used and its powered fraction either way (F-B2 pattern).
- **Q-B2** Seeded determinism: which fixture-server classes can honestly claim `seeded` (§4.2) — build enumerates them; anything outside the enumeration defaults to `non-deterministic` and is sample-excluded.
- **Q-B3** Format versioning: when the Assay scorecard format version moves, do old sealed scorecards remain verifiable under their stated `format_version` (assumed yes, verifier carries per-version canonicalisation) — build confirms before any format bump.
- **Q-B4** Vendor counter-signature timing (§6.1): at receipt issuance (assumed) vs on first export — build picks one; a `partial` receipt must never render as complete in any surface either way.
- **Q-B5** SDK language scope: Python only in v0.1 (assumed, house pattern) — a second-language SDK is a new spec amendment, not a build-stage addition, because hook semantics must stay identical across languages.
