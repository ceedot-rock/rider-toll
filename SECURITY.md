# Security Policy

rider-toll sits on money paths: signed attestation envelopes, metering,
budgets, escrow, and a live Stripe webhook receiver. A bug that lets an
attacker forge an envelope, bypass webhook signature verification, or
manipulate toll accounting is a security issue, not a normal bug.

## Reporting a vulnerability

Please do not open a public issue for security problems.

- Use GitHub's private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability")
- Or email corey@slidphilabs.com with the subject line `rider-toll security`

Include the affected file or endpoint, steps or inputs to reproduce, and
what you expected versus what happened.

You can expect an acknowledgement within 3 business days. We will keep you
updated while we investigate and credit you in the changelog unless you
prefer to stay anonymous.

## In scope

- Envelope signature bypass: a tampered payload that still verifies, or a
  forged ES256 signature accepted by `tollkeeper.envelope`
- Stripe webhook signature bypass: a delivery accepted without a valid
  `Stripe-Signature` for the configured secret
- Toll-accounting manipulation: metering under-counts, forged payment
  receipts, escrow release without a matching delivery receipt, budget
  enforcement bypass
- Identity credential forgery accepted by `tollkeeper.identity`

## Out of scope

- Operator deployments we do not run
- Social engineering, spam, or denial-of-service against hosted demos
- On-chain settlement paths: `settle_onchain` is a stub that raises —
  there is nothing live to attack there
