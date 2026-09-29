#!/usr/bin/env python3
"""tollkeeper.stripe_config — Stripe wiring for the toll gates.

CONFIG ONLY. Importing this module changes nothing and charges nothing.
Every gate stays DARK until CoS smoke + Corey's explicit go flips it live.

Built 2026-09-29. All pricing PROPOSED until Corey locks it.
Objects were created with the lab's connected Stripe key, which is
LIVE-mode (test mode would need a separate test key — see STRIPE_MODE).

Per-gate mapping (toll-gate-map.md):
  Gate 1 Identity      $0.005/query, 100 free then metered
  Gate 2 Discovery     $0.02/lookup; promoted placement $9/mo
  Gate 4 Grants        $0.01/issue, $0.005/check
  Gate 5 CuNi verify   $0.10/check
  Gate 7 Memory        $0.02/hosted transfer
Gates 3 and 6 are NOT here — full mock mode per Corey's standing order.

How the Stripe side works when a gate flips live:
  1. Customer subscribes to the gate's metered price (Stripe Checkout or
     dashboard). The subscription carries the billing meter.
  2. Each paid toll reports a meter event:
       POST /v1/billing/meter_events
       {event_name, payload: {stripe_customer_id, value: <count>},
        identifier: <dedup id>}
     Meter events aggregate (sum) per billing period; Stripe invoices.
  3. The 100-free-queries rule (gate 1) is enforced in LAB CODE before any
     meter event is reported — Stripe only ever sees billable usage.
  4. Webhook endpoint (STILL NEEDED — requires a deploy): listen for
     checkout.session.completed, customer.subscription.created/updated/
     deleted, invoice.paid, invoice.payment_failed to keep local
     subscription state. See STRIPE_WEBHOOK_TODO below.

Do NOT flip GATES_LIVE without CoS smoke + Corey's explicit go.
"""

STRIPE_MODE = "live"          # connected key is live-mode; test needs a separate key
PRICING_STATUS = "proposed"   # all pricing PROPOSED until Corey locks

# Master kill-switch per gate. ALL False = all dark. Flip only with
# CoS smoke + Corey's explicit go. Nothing in this package reads these yet;
# they are the single source of truth for the flip when it happens.
GATES_LIVE = {
    1: False,
    2: False,          # discovery lookups
    "2_promote": False,  # promoted placement subscription
    4: False,
    5: False,
    7: False,
}

# meter_id / price_id / product_id as created 2026-09-29.
GATE_STRIPE = {
    1: {
        "product_id": "prod_VLkE5hG95MITZa",
        "meter_id": "mtr_61VUQgnC40ioRkkcG41K8JsmXFzvIUvw",
        "meter_event": "toll_gate1_identity_query",
        "price_id": "price_1UL2jgK8JsmXFzvI1T6J2fqG",
        "unit": "$0.005/query",
        "free_allotment": 100,  # enforced in lab code, not Stripe
    },
    2: {
        "product_id": "prod_VLkERVdaNFVCaH",
        "meter_id": "mtr_61VUQgo1E5M4QDMe341K8JsmXFzvITnU",
        "meter_event": "toll_gate2_discovery_lookup",
        "price_id": "price_1UL2jhK8JsmXFzvIt0YvwjyG",
        "unit": "$0.02/lookup",
    },
    "2_promote": {
        "product_id": "prod_VLkERVdaNFVCaH",
        "price_id": "price_1UL2jkK8JsmXFzvIfeBilVXb",
        "unit": "$9/mo",
        "payment_link": "https://buy.stripe.com/dRm8wQaZveFOfxP1S86wE0M",
        "payment_link_id": "plink_1UL2k4K8JsmXFzvIYOmTk0mZ",
    },
    4: {
        "product_id": "prod_VLkEuQcFFNSk3B",
        "unit_issue": "$0.01/issue",
        "issue": {
            "meter_id": "mtr_61VUQgpUpAA8F1wsC41K8JsmXFzvI5M0",
            "meter_event": "toll_gate4_grant_issue",
            "price_id": "price_1UL2jhK8JsmXFzvIGcW4zauZ",
        },
        "unit_check": "$0.005/check",
        "check": {
            "meter_id": "mtr_61VUQgqgLSvnaQ5Sq41K8JsmXFzvIUKW",
            "meter_event": "toll_gate4_grant_check",
            "price_id": "price_1UL2jiK8JsmXFzvI0GFtW4tq",
        },
    },
    5: {
        "product_id": "prod_VLkEC9lpgfXHNn",
        "meter_id": "mtr_61VUQgrspjQwjCb6K41K8JsmXFzvIFp2",
        "meter_event": "toll_gate5_cuni_check",
        "price_id": "price_1UL2jjK8JsmXFzvIExhFk58C",
        "unit": "$0.10/check",
    },
    7: {
        "product_id": "prod_VLkEWvoR111he2",
        "meter_id": "mtr_61VUQgrM8JjMnkJen41K8JsmXFzvIJk0",
        "meter_event": "toll_gate7_memory_transfer",
        "price_id": "price_1UL2jkK8JsmXFzvIk2WYTUA5",
        "unit": "$0.02/hosted transfer",
    },
}

# STILL NEEDED before any gate flips live (2026-09-29: code built, deploy pending):
#   - Webhook endpoint: tollkeeper/stripe_webhook.py is written and tested
#     (10/10). Ship needs to deploy it behind an HTTPS POST route with
#     STRIPE_WEBHOOK_SECRET set (generate in Stripe dashboard > webhooks).
#   - Meter-event reporter: tollkeeper/stripe_metering.py is written and
#     tested (5/5). Lab code calls report_toll() after each paid toll;
#     STRIPE_SECRET_KEY must be set where it runs. Dark gates no-op.
#   - CoS smoke per gate, then Corey's explicit go per gate.
STRIPE_WEBHOOK_TODO = True  # True until Ship confirms the webhook route is live


def meter_event_shape(meter_event, stripe_customer_id, value=1,
                      identifier=None):
    """Shape of the POST /v1/billing/meter_events body for one toll.

    Pure documentation helper — performs no IO, holds no keys.
    """
    return {
        "event_name": meter_event,
        "payload": {"stripe_customer_id": stripe_customer_id,
                    "value": value},
        "identifier": identifier or "",
    }
