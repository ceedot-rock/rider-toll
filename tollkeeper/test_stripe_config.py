#!/usr/bin/env python3
"""Tests for tollkeeper.stripe_config — config shape only, no network."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from tollkeeper import stripe_config as sc


def test_all_dark():
    assert all(v is False for v in sc.GATES_LIVE.values()), \
        "no gate may flip live from config alone"


def test_pricing_proposed():
    assert sc.PRICING_STATUS == "proposed"
    assert sc.STRIPE_MODE == "live"  # documents which key built the objects


def test_gate_ids_wellformed():
    for gate in (1, 2, 5, 7):
        g = sc.GATE_STRIPE[gate]
        assert g["meter_id"].startswith("mtr_")
        assert g["price_id"].startswith("price_")
        assert g["product_id"].startswith("prod_")
        assert g["meter_event"].startswith("toll_gate")
    issue, check = sc.GATE_STRIPE[4]["issue"], sc.GATE_STRIPE[4]["check"]
    for half in (issue, check):
        assert half["meter_id"].startswith("mtr_")
        assert half["price_id"].startswith("price_")
    promo = sc.GATE_STRIPE["2_promote"]
    assert promo["price_id"].startswith("price_")
    assert promo["payment_link"].startswith("https://buy.stripe.com/")


def test_meter_event_shape():
    body = sc.meter_event_shape("toll_gate1_identity_query",
                                "cus_123", value=3, identifier="evt-1")
    assert body["event_name"] == "toll_gate1_identity_query"
    assert body["payload"] == {"stripe_customer_id": "cus_123", "value": 3}
    assert body["identifier"] == "evt-1"


def test_no_mock_gates_present():
    assert 3 not in sc.GATE_STRIPE and 6 not in sc.GATE_STRIPE, \
        "gates 3+6 stay in full mock mode, no Stripe objects"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as e:  # noqa: BLE001
            failed += 1
            print("FAIL", fn.__name__, "->", e)
    print("%d/%d passed" % (len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
