# tollkeeper — shared envelope + Modules A & B

Toll-keeper platform core: one signed envelope format, identity verification
+ portable reputation (Module A), and the billing engine (Module B).
See `ARCHITECTURE.md` (parent dir) for the full seven-toll design.

## Money

Integer **micro-USDC** (`uusdc`) everywhere: 1 USDC = 1,000,000 uusdc.
Floats are refused at envelope canonicalization — exactness or refuse.

## Modules

| File | What |
|---|---|
| `envelope.py` | Canonical JSON → SHA-256 → ES256 (pure-stdlib P-256) → `{payload, sig, kid, alg}`. Lab JWKS. Dev keypair (test-only, in-memory, never persisted). |
| `store.py` | One file-local SQLite DB (`tollkeeper.db`, or `TOLLKEEPER_DB` env). |
| `identity.py` | `verify_credential(jwt)` → `{agent_id, clearance, expires, valid}`. Accepts the Rider ES256 JWT shape (15-min, L0–L4). Queries metered (toll accounting), never charged here. |
| `reputation.py` | Signed delivery receipts; refused unless the txHash is in the billing ledger (no fake reviews). `reputation(agent_id)` → jobs/completed/disputed/volume/score. Receipts verify offline via JWKS. |
| `billing.py` | Mocked USDC ledger, budgets with 402 `BUDGET_EXHAUSTED`, signed payment receipts, escrow (1% routing fee at lock), disputes (5¢ opener fee, returned on win). Settlement MOCKED — `settle_onchain` is a stub that raises. |

Sibling-built: `grants.py` (C), `oracle.py` (D).

## Reputation score (transparent formula, no black box)

```
jobs == 0            → score None  ("insufficient data")
volume_completion    = completed_volume_uusdc / total_volume_uusdc
w(dispute)           = 0.5 ** (age_days / 180)      # half-life decay
dispute_factor       = 1 - min(1, sum(w) / max(1, jobs))
score                = round(100 * volume_completion * dispute_factor, 2)
```

"Disputed" = open disputes + resolved disputes the opener won, on the
agent's escrows. Reputation *queries* are free; the toll (1¢) is metered at
receipt issuance.

## Escrow / dispute rules

- Lock: 1% routing fee accounted at lock time (mock transfer to `lab:fees`).
- Release: only on a valid lab-sealed `delivery_receipt` envelope whose
  `job_id` + `agent_id` match the escrow and `delivered_ok` is true.
- Timeout: `sweep_timeouts()` refunds the payer the net amount; lab keeps
  the lock-time fee.
- Disputes: opener (payer or agent) pays 5¢; resolve = `refund` (payer gets
  net, fee returned), `release` (agent gets net, lab keeps fee), or
  `partial:N` (split, fee returned). Every step emits a sealed envelope.

## Tests

```sh
cd ~/workspace/rider-toll
python3 tollkeeper/test_envelope.py            # 12 tests
python3 tollkeeper/test_billing.py             # 15 tests
python3 tollkeeper/test_identity_reputation.py # 17 tests
```

## Spec gaps filled (explicit)

1. **Envelope API**: kept the existing `sign(payload, keypair)` /
   `verify(envelope, jwks)` / `canonical` / `EnvelopeError` names the
   sibling modules (C, D) already import; added `dev_lab_keypair()`,
   `lab_jwks()`, `seal_with_lab()`, `verify_ok()`.
2. **P-256 curve-order constant was wrong** (`…F3B6CAC2…` vs true
   `…F3B9CAC2…`) — signatures were self-consistent but would never verify
   against real P-256. Fixed and cross-checked both directions against the
   independent `cryptography` implementation.
3. **Rider JWT claim shape**: `agent_id` (fallback `sub`), `clearance`
   (default `L0`, must be L0–L4), `iss` allow-list
   `("agentrider.dev", "tollkeeper.dev")`, 60s `iat` leeway (mirrors the
   live verifier's clock-skew handling).
4. **Receipt anti-fake rule**: tx must exist in the ledger AND ledger
   amount ≥ receipt `paid_amount` (spec said "exists"; the amount check
   closes over-claiming).
5. **Budget windows**: `daily`/`weekly`/`monthly` reset on a fixed
   second-count (30d month); `job` never resets (per-budget lifetime cap).
6. **Escrow timeout**: payer refunded net, lab keeps the 1% lock-time fee
   (spec: "release on delivery receipt OR timeout" — the timeout leg is a
   refund, not a release to the agent).
7. **Dispute fee winner**: returned on `refund` and `partial`, kept by the
   lab on `release`.
8. **Tolls are metered, not charged**: `verify_queries`, `receipt_count`,
   budget rows are the accounting surface; no charging path exists in this
   build (nothing to charge against — settlement is mocked).
9. **`mint_test_credential`** signs with the dev lab key / `tollkeeper.dev`
   issuer — clearly test-only, never presented as a real Rider credential.
