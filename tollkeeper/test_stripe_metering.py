#!/usr/bin/env python3
"""Tests for tollkeeper.stripe_metering — run: python3 test_stripe_metering.py

No network: urllib.request.urlopen is monkeypatched. No real Stripe calls.
"""
import io
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TOLLKEEPER_DB"] = "/tmp/tollkeeper-test-metering.db"
if os.path.exists(os.environ["TOLLKEEPER_DB"]):
    os.remove(os.environ["TOLLKEEPER_DB"])

from tollkeeper import stripe_config as sc
from tollkeeper import stripe_metering as sm

SAVED_LIVE = dict(sc.GATES_LIVE)
CALLS = []


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_urlopen(req, timeout=None):
    CALLS.append(req)
    body = req.data.decode()
    assert "event_name=toll_gate" in body, body
    assert req.get_header("Authorization").startswith("Bearer sk_"), \
        "key must ride the Authorization header"
    return FakeResp({"identifier": "evt_test_123"})


def set_live(*gates):
    for k in sc.GATES_LIVE:
        sc.GATES_LIVE[k] = k in gates


def teardown():
    for k, v in SAVED_LIVE.items():
        sc.GATES_LIVE[k] = v


def test_dark_gate_is_noop():
    urllib.request.urlopen = fake_urlopen
    try:
        set_live()  # everything dark
        r = sm.report_toll(1, "cus_1", api_key="sk_test_x")
        assert r == {"reported": False, "reason": "gate-dark", "gate": 1}, r
        assert CALLS == [], "dark gate must not touch the network"
    finally:
        teardown()


def test_live_gate_reports():
    urllib.request.urlopen = fake_urlopen
    try:
        set_live(5)
        r = sm.report_toll(5, "cus_9", value=3, api_key="sk_test_x",
                           dedup_key="retry-1")
        assert r["reported"] is True, r
        assert r["meter_event"] == "toll_gate5_cuni_check", r
        assert r["value"] == 3 and r["identifier"] == "retry-1", r
        body = CALLS[-1].data.decode()
        assert "payload%5Bvalue%5D=3" in body or "payload[value]=3" in body.replace("%5B", "[").replace("%5D", "]"), body
        assert "identifier=retry-1" in body, body
    finally:
        teardown()


def test_gate1_free_quota():
    urllib.request.urlopen = fake_urlopen
    try:
        set_live(1)
        # first 100 are free: no network, no report
        for _ in range(100):
            r = sm.report_toll(1, "cus_free", api_key="sk_test_x")
            assert r["reported"] is False and r["reason"] == "free-quota", r
        assert CALLS == [], "free quota must not touch the network"
        # 101st is billable
        r = sm.report_toll(1, "cus_free", api_key="sk_test_x")
        assert r["reported"] is True and r["value"] == 1, r
        assert r["free_used"] == 0, r
        # bulk: 50 at once after quota spent -> all 50 reported
        r = sm.report_toll(1, "cus_free", value=50, api_key="sk_test_x")
        assert r["reported"] is True and r["value"] == 50, r
    finally:
        teardown()


def test_gate4_needs_kind():
    urllib.request.urlopen = fake_urlopen
    try:
        set_live(4)
        try:
            sm.report_toll(4, "cus_4", api_key="sk_test_x")
            raise AssertionError("expected MeteringError")
        except sm.MeteringError:
            pass
        r = sm.report_toll(4, "cus_4", kind="issue", api_key="sk_test_x")
        assert r["reported"] is True, r
        assert r["meter_event"] == "toll_gate4_grant_issue", r
        r = sm.report_toll(4, "cus_4", kind="check", api_key="sk_test_x")
        assert r["meter_event"] == "toll_gate4_grant_check", r
    finally:
        teardown()


def test_missing_key_raises():
    urllib.request.urlopen = fake_urlopen
    old = os.environ.pop("STRIPE_SECRET_KEY", None)
    try:
        set_live(7)
        try:
            sm.report_toll(7, "cus_7")
            raise AssertionError("expected MeteringError")
        except sm.MeteringError as e:
            assert "no Stripe key" in str(e), e
    finally:
        if old is not None:
            os.environ["STRIPE_SECRET_KEY"] = old
        teardown()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        CALLS.clear()
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as e:
            failed += 1
            print("FAIL", fn.__name__, "->", repr(e))
    print("%d/%d passed" % (len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
