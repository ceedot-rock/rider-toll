#!/usr/bin/env python3
"""Tests for tollkeeper.server — run: python3 test_server.py

Spins up the real HTTP server on an ephemeral port. No network beyond
localhost. Uses a temp SQLite DB.
"""
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TOLLKEEPER_DB"] = "/tmp/tollkeeper-test-server.db"
if os.path.exists(os.environ["TOLLKEEPER_DB"]):
    os.remove(os.environ["TOLLKEEPER_DB"])

from tollkeeper import server as srv

BASE = None


def _req(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, data=body, method=method,
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def _sig(body, secret):
    ts = str(int(time.time()))
    digest = hmac.new(secret.encode(), ts.encode() + b"." + body,
                      hashlib.sha256).hexdigest()
    return "t=%s,v1=%s" % (ts, digest)


def test_health():
    code, doc = _req("GET", "/health")
    assert code == 200 and doc["ok"] is True, (code, doc)
    assert doc["service"] == "tollkeeper", doc


def test_status_readonly_all_dark():
    code, doc = _req("GET", "/v1/tolls/status")
    assert code == 200, (code, doc)
    assert doc["pricing_status"] == "proposed", doc
    assert doc["stripe_mode"] == "live", doc
    assert all(v is False for v in doc["gates_live"].values()), doc


def test_webhook_no_secret_500():
    old = os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
    try:
        code, doc = _req("POST", "/webhooks/stripe", body=b"{}",
                         headers={"Stripe-Signature": "t=1,v1=x"})
        assert code == 500 and "not configured" in doc["error"], (code, doc)
    finally:
        if old is not None:
            os.environ["STRIPE_WEBHOOK_SECRET"] = old


def test_webhook_bad_signature_400():
    os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test"
    try:
        code, doc = _req("POST", "/webhooks/stripe", body=b"{}",
                         headers={"Stripe-Signature": "t=1,v1=deadbeef"})
        assert code == 400 and doc["error"] == "bad signature", (code, doc)
    finally:
        del os.environ["STRIPE_WEBHOOK_SECRET"]


def test_webhook_good_signature_dispatched():
    os.environ["STRIPE_WEBHOOK_SECRET"] = "whsec_test"
    try:
        event = {"id": "evt_1", "type": "invoice.paid",
                 "data": {"object": {"id": "in_1", "customer": "cus_srv",
                                     "amount_due": 900}}}
        body = json.dumps(event).encode()
        code, doc = _req(
            "POST", "/webhooks/stripe", body=body,
            headers={"Stripe-Signature": _sig(body, "whsec_test"),
                     "Content-Type": "application/json"})
        assert code == 200 and doc["handled"] is True, (code, doc)
        assert doc["action"]["action"] == "invoice_paid", doc
    finally:
        del os.environ["STRIPE_WEBHOOK_SECRET"]


def test_unknown_route_404():
    code, doc = _req("GET", "/nope")
    assert code == 404, (code, doc)
    code, doc = _req("POST", "/webhooks/other", body=b"{}")
    assert code == 404, (code, doc)


if __name__ == "__main__":
    httpd = srv.make_server(0)
    port = httpd.server_address[1]
    BASE = "http://127.0.0.1:%d" % port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
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
    finally:
        httpd.shutdown()
