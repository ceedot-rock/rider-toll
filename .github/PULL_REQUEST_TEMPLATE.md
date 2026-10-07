## What changed

<!-- One or two sentences. -->

## Modules touched

<!-- e.g. tollkeeper/billing.py, tollkeeper/server.py, or "none" -->

## Checks

- [ ] Every `tollkeeper/test_*.py` direct runner passes (`python3 tollkeeper/test_<name>.py`)
- [ ] `python3 -m unittest tollkeeper.test_grants tollkeeper.test_oracle` passes
- [ ] Money math stays in integer micro-USDC (uusdc) — no floats
- [ ] Stripe webhook signature verification path untouched, or new tests cover the change
- [ ] Nothing here flips a gate or charges anything
