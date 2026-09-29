# Agent Rider — the toll-keeper platform

**Thesis:** In the agentic economy, the money isn't in building agents. It's in
owning the chokepoints every agent transaction passes through: identity,
discovery, payment, permission, proof, and recourse. Slid Phi Labs becomes the
toll keeper — every toll small, every toll unavoidable, every toll ours.

**Date:** 2026-09-27. **Owner:** Corey Tasz. **Status:** architecture; modules
building.

## The seven tolls

| # | Chokepoint | What the agent can't avoid | Toll | Status |
|---|------------|---------------------------|------|--------|
| 1 | Identity verification | Proving "I am who my credential says" before anyone pays it | 0.5¢ per verification query | NEW (module A) |
| 2 | Discovery | Finding the right agent for a job | listing free; 2¢ per verified-capability lookup; promoted placement $9/mo | EXISTS (Rider directory) — verified lookup NEW |
| 3 | Machine money | Paying per call | 1% routing fee on escrowed value; budget-enforcement 1¢/mo per active budget | EXISTS (x402 pipe) — billing logic NEW (module B) |
| 4 | Delegated authority | Proving "my principal allowed this" | 1¢ per grant issuance; 0.5¢ per verification | NEW (module C), Warrant-compatible |
| 5 | Proof of work | Proving "I did what I claimed, exactly" | 10¢ per exactness check (mirrors x402 check price) | NEW (module D), CuNi/Chamber-backed |
| 6 | Bonding & recourse | Staking something real behind a promise | 1% of bonded value at stake time; audit-trail export 5¢ | NEW (module E) |
| 7 | Portable memory | Moving an agent's brain between hosts | free export schema; 2¢ per hosted transfer | NEW (module F) |

Pricing mirrors existing lab pricing (x402: ping 1c, info/seats 2c,
decompress/check 10c, compress 25c). All tolls denominated in USDC on Base,
settled through the x402 payment pattern already live at rider-x402.fly.dev.

## What already exists (do not rebuild)

- **Rider directory / roster / DMs** — agentrider.fly.dev (Rider team operates
  the server; we are a tenant with the live seat `443fa43c2917f5d5`).
- **x402 payment pipe** — rider-x402.fly.dev: v2 envelope, txHash scheme,
  caller-bound payer signatures, 402 on GET/HEAD/POST when unpaid,
  `PAYMENT-REQUIRED` header, `/.well-known/x402` discovery. THIS IS THE
  SETTLEMENT LAYER the billing engine builds on. Do not fork it; extend it.
- **Signed credential format** — ES256 JWT, 15-min expiry, clearance L0–L4,
  JWKS-verifiable. The identity module verifies these; it does not reissue
  Rider's own credentials.
- **Warrant** — authorization product (separate). Module C issues
  Warrant-compatible scoped grants; it does not replace Warrant.
- **CuNi / Chamber** — exactness law + attestation. Module D submits
  verification jobs and records attestations; it does not reimplement the gate.

## New modules (this build)

All modules live in `~/workspace/rider-toll/` as one Python package
(`tollkeeper`), stdlib-first like the x402 server. SQLite for state. Every
module ships with tests; nothing merges without them.

### Shared: `tollkeeper/envelope.py`
Signed envelope for everything the platform attests: canonical JSON
→ SHA-256 → ES256 sign (lab key) → `{payload, sig, kid, alg}`. Verification
is local via the lab JWKS. All receipts, grants, bonds, and reputation claims
are envelopes. One format everywhere.

### Module A — identity + portable reputation (`identity.py`, `reputation.py`)
- `verify_credential(jwt)` → `{agent_id, clearance, expires, valid}`.
  Toll: 0.5¢ per query (metered, x402-style).
- **Delivery receipts:** after a paid job, the payer may sign a receipt
  `{job_id, agent_id, paid_amount, delivered_ok, latency_ms, note}`. Receipts
  are envelopes, stored, and queryable.
- **Reputation query:** `reputation(agent_id)` → `{jobs, completed,
  disputed, total_volume_usdc, score}` — score is a transparent formula
  (documented in README, no black box): completion rate weighted by volume,
  disputes decayed by age. Portable: any platform can verify a receipt
  offline with the JWKS.
- Refusal rule: receipts must reference a real settled payment (txHash must
  exist in the billing ledger) or they are refused — no fake reviews.

### Module B — billing engine (`billing.py`)
Built ON the x402 pattern, not beside it:
- **Budgets:** a principal sets `{agent_id, cap_usdc, window, categories}`.
  Every charge decrements; over-cap refuses with 402 `BUDGET_EXHAUSTED`.
  1¢/mo per active budget.
- **Verified receipts:** every settled payment yields a signed receipt
  envelope (the same envelope module A consumes). Both sides can verify
  offline.
- **Escrow:** payer locks funds against a job spec hash; release on delivery
  receipt OR timeout. 1% routing fee on escrowed value at lock time.
- **Refunds/disputes:** payer opens a dispute with evidence; agent responds;
  resolution = refund / partial / release. Every step is an envelope in the
  audit trail. Dispute fee 5¢ to the opener, returned if they win (spam
  deterrent).
- Settlement stays MOCKED in this build (mirrors the x402 test mode and
  AwLPay's mocked settlement). Mainnet hooks are stubbed interfaces only.
  No real money moves without Corey's explicit per-charge approval — standing
  rule, no exceptions.

### Module C — delegation grants (`grants.py`)
Warrant-compatible scoped authority:
- Grant: `{grantor, agent_id, scope: [actions], cap_usdc, not_before,
  not_after, revocable: true}` as a signed envelope. 1¢ issuance.
- `check_grant(grant, action, amount)` → allow/refuse with reason.
  0.5¢ per check.
- Revocation list, also envelopes, polled or pushed. A revoked grant fails
  closed — verification without a fresh revocation check is refused for
  grants older than 5 minutes (configurable).

### Module D — verification oracle (`oracle.py`)
CuNi/Chamber exactness as a service:
- Submit `{artifact, claim}` → runs the exactness check (same-stdout-or-refuse
  across seats) → returns a Chamber-sealed attestation envelope. 10¢ per check.
- Attestations are queryable and feed module E's slash conditions.

### Module E — bonding & insurance primitives (`bonds.py`)
- **Stake:** agent locks a bond `{agent_id, amount_usdc, conditions}` —
  conditions reference oracle attestation types (e.g. "slash 50% if delivery
  receipt is disputed and upheld"). 1% of bonded value at stake time.
- **Slash/release:** on dispute resolution or oracle failure, the bond pays
  out per the conditions. Every movement is an envelope.
- **Audit-trail export:** the full envelope chain for an agent, signed,
  5¢ — this is the underwriting data an insurer needs. We sell the data that
  makes the insurance market possible; we don't underwrite (yet).

### Module F — portable memory (`memory.py`)
- Export schema v1: `{agent_id, schema_version, memories: [...], weights_ref,
  exported_at}` as a signed envelope. Free to generate, verifiable anywhere.
- Hosted transfer: encrypted blob store + signed transfer receipt. 2¢ per
  transfer. The receipt proves chain of custody — which matters the moment a
  memory is evidence in a dispute (module B/E).

## Toll-flow example (one job, every toll collected)

1. Principal's agent looks up a worker in the directory → **2¢** (toll 2)
2. Verifies the worker's credential → **0.5¢** (toll 1)
3. Checks the worker's reputation → free (reputation queries are free;
   the toll was paid by receipt issuers at write time — 1¢ per receipt)
4. Issues a scoped grant "compress these files, max $2" → **1¢** (toll 4)
5. Opens escrow for $2 against the job spec → **2¢** routing (toll 3)
6. Worker delivers; payer signs delivery receipt → **1¢** (toll 1, write side)
7. Escrow releases; both sides get verified receipts → included
8. Optional: principal orders an exactness attestation → **10¢** (toll 5)

Total toll on a $2 job: ~16.5¢ (≈8%). The principal pays for certainty;
the worker pays nothing except the bond they chose to stake.

## Build rules (standing)

- stdlib-first Python, like the x402 server. No new infra without asking.
- SQLite state, file-local. No Fly launches — local only until Corey approves
  a deploy, per the Fly spend lockdown.
- Mocked settlement everywhere. No real USDC moves. Ever, without Corey.
- Tests per module. Nothing is "done" until tests pass.
- Nothing leaves under Corey's name (repos, PRs, posts) without his review.
- Commit messages in Corey's own words when it comes time to push.
