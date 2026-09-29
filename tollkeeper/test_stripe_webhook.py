#!/usr/bin/env python3
"""Tests for tollkeeper.stripe_webhook — run: python3 test_stripe_webhook.py

No network. Signatures are HMAC'd locally with a test secret.
"""
import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TOLLKEEPER_DB"] = "/tmp/tollkeeper-test-webhook.db"
if os.path.exists(os.environ["TOLLKEEPER_DB"]):
    os.remove(os.environ["TOLLKEEPER_DB"])

from tollkeeper import stripe_webhook as sw

SECRET = "whsec_test_123"


def sign(body: bytes, secret=SECRET, ts=None):
    ts = int(time.time()) if ts is None else ts
    digest = hmac.new(secret.encode(), str(ts).encode() + b"." + body,
                      hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (ts, digest), ts


def event_body(etype, obj):
    return json.dumps({"id": "evt_1", "type": etype,
                       "data": {"object": obj}}).encode()


def test_verify_good_signature():
    body = b'{"hello":1}'
    header, _ = sign(body)
    assert sw.verify_signature(body, header, SECRET) is True


def test_verify_bad_signature():
    body = b'{"hello":1}'
    header, _ = sign(body)
    assert sw.verify_signature(body, header, "whsec_wrong") is False
    assert sw.verify_signature(b'{"hello":2}', header, SECRET) is False
    assert sw.verify_signature(body, "", SECRET) is False


def test_verify_stale_timestamp():
    body = b'{"hello":1}'
    header, _ = sign(body, ts=int(time.time()) - 3600)
    assert sw.verify_signature(body, header, SECRET) is False


def test_checkout_completed_records_customer():
    body = event_body("checkout.session.completed", {
        "id": "cs_1", "customer": "cus_abc",
        "client_reference_id": "ar_payer_1",
        "subscription": "sub_1"})
    header, _ = sign(body)
    code, resp = sw.handle_webhook(body, header, SECRET)
    assert code == 200 and resp["received"] is True, resp
    row = sw.get_customer("cus_abc")
    assert row is not None and row["payer_key"] == "ar_payer_1", row
    assert row["subscription_id"] == "sub_1", row


def test_subscription_created_maps_gate():
    # use a real price_id from stripe_config so gate resolution is exercised
    from tollkeeper import stripe_config as sc
    price_id = sc.GATE_STRIPE[5]["price_id"]
    body = event_body("customer.subscription.created", {
        "id": "sub_9", "customer": "cus_gate5", "status": "active",
        "items": {"data": [{"price": {"id": price_id}}]}})
    header, _ = sign(body)
    code, resp = sw.handle_webhook(body, header, SECRET)
    assert code == 200 and resp["handled"] is True, resp
    row = sw.get_customer("cus_gate5")
    assert row["status"] == "active" and row["gate_key"] == "5", row


def test_subscription_deleted():
    body = event_body("customer.subscription.deleted", {
        "id": "sub_9", "customer": "cus_gate5", "status": "canceled"})
    header, _ = sign(body)
    code, resp = sw.handle_webhook(body, header, SECRET)
    assert code == 200, resp
    row = sw.get_customer("cus_gate5")
    assert row["status"] == "canceled", row


def test_invoice_failed_is_dunning_not_cutoff():
    body = event_body("invoice.payment_failed", {
        "id": "in_1", "customer": "cus_gate5",
        "subscription": "sub_9", "amount_due": 1000})
    header, _ = sign(body)
    code, resp = sw.handle_webhook(body, header, SECRET)
    assert code == 200 and resp["handled"] is True, resp
    assert resp["action"]["action"] == "invoice_failed_dunning", resp


def test_unknown_type_acks():
    body = event_body("customer.tax_id.created", {"id": "x"})
    header, _ = sign(body)
    code, resp = sw.handle_webhook(body, header, SECRET)
    assert code == 200 and resp["handled"] is False, resp


def test_bad_signature_400():
    body = event_body("invoice.paid", {"id": "in_2"})
    code, resp = sw.handle_webhook(body, "t=1,v1=nope", SECRET)
    assert code == 400, resp


def test_missing_secret_500():
    body = event_body("invoice.paid", {"id": "in_3"})
    header, _ = sign(body)
    code, resp = sw.handle_webhook(body, header, webhook_secret="")
    old = os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
    try:
        code, resp = sw.handle_webhook(body, header, webhook_secret="")
        assert code == 500, resp
    finally:
        if old is not None:
            os.environ["STRIPE_WEBHOOK_SECRET"] = old


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as e:
            failed += 1
            print("FAIL", fn.__name__, "->", repr(e))
    print("%d/%d passed" % (len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
