# rider-toll

[![Audited checks](https://github.com/ceedot-rock/rider-toll/actions/workflows/audited-checks.yml/badge.svg)](https://github.com/ceedot-rock/rider-toll/actions/workflows/audited-checks.yml)

Agent Rider **toll-keeper** platform: one signed envelope format, identity
verification + portable reputation, and the billing engine — plus the Stripe
metered billing rail and webhook service for toll gates 1, 2, 4, 5, 7.
(Slid Phi Labs)

- `ARCHITECTURE.md` — the seven-toll design
- `tollkeeper/README.md` — module reference (envelope, identity, reputation,
  billing, grants, oracle, bonds, memory)
- `CONTRIBUTING.md` — ground rules and test commands
- `SECURITY.md` — private vulnerability reporting

## Run the tests

```sh
for t in test_billing test_bonds test_envelope test_identity_reputation \
         test_memory test_server test_stripe_config test_stripe_metering \
         test_stripe_webhook; do
  python3 "tollkeeper/$t.py"
done
python3 -m unittest tollkeeper.test_grants tollkeeper.test_oracle
```

## Run the server

```sh
PORT=8080 python3 -m tollkeeper.server
curl localhost:8080/                 # service, about, endpoints
curl localhost:8080/health           # liveness probe
curl localhost:8080/v1/tolls/status  # gate flags, pricing, Stripe mode (read-only)
```

Deploys to Fly.io (`fly.toml`, `Dockerfile`); the Stripe webhook secret is
set at deploy time via `fly secrets`.

## Money rule

Integer **micro-USDC** (`uusdc`) everywhere: 1 USDC = 1,000,000 uusdc.
Floats are refused. Nothing here flips a gate live or charges anything —
gates go live only with the Rider-team smoke run plus Corey's explicit go.
