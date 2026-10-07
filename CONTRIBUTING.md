# Contributing to rider-toll

Thanks for helping build the toll-keeper platform.

## Ground rules

- All money math is integer micro-USDC (`uusdc`; 1 USDC = 1,000,000 uusdc).
  No floats, ever — floats are refused at envelope canonicalization.
- The HTTP service is stdlib-only. Keep it that way.
- Nothing in this repo flips a toll gate live or charges anything. Gates go
  live only with the Rider-team smoke run plus Corey's explicit go.
- The dev keypair (`tollkeeper/devkey.py`) is test-only, in-memory, never
  persisted — it must never sign anything production-facing.

## Quick checks (no install needed)

```sh
for t in test_billing test_bonds test_envelope test_identity_reputation \
         test_memory test_server test_stripe_config test_stripe_metering \
         test_stripe_webhook; do
  python3 "tollkeeper/$t.py"
done
python3 -m unittest tollkeeper.test_grants tollkeeper.test_oracle
```

CI runs all of these plus a live API smoke test
(`GET /`, `GET /health`, `GET /v1/tolls/status`) on every pull request.

## Local server

```sh
PORT=8080 python3 -m tollkeeper.server
curl localhost:8080/              # service, about, endpoints
curl localhost:8080/v1/tolls/status
```

## Adding or changing a module

1. Implement in `tollkeeper/<module>.py`.
2. Add tests in `tollkeeper/test_<module>.py` following the file's own
   runner style (direct runner or unittest).
3. Update `ARCHITECTURE.md` if the toll design changes.
4. Open a pull request using the template.
