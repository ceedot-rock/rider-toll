#!/usr/bin/env python3
"""Tests for tollkeeper.identity + tollkeeper.reputation.
Run: python3 test_identity_reputation.py"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TOLLKEEPER_DB"] = "/tmp/tollkeeper-test-identrep.db"
if os.path.exists(os.environ["TOLLKEEPER_DB"]):
    os.remove(os.environ["TOLLKEEPER_DB"])

from tollkeeper import identity as I
from tollkeeper import reputation as R
from tollkeeper import billing as B
from tollkeeper import store
from tollkeeper.envelope import (dev_lab_keypair, generate_keypair, lab_jwks,
                                 jwk_public)


def test_verify_valid_credential():
    tok = I.mint_test_credential("agent-1", "L2")
    res = I.verify_credential(tok)
    assert res["valid"], res
    assert res["agent_id"] == "agent-1" and res["clearance"] == "L2"
    assert res["expires"] > int(time.time())


def test_clearance_levels():
    for lvl in ("L0", "L1", "L2", "L3", "L4"):
        res = I.verify_credential(I.mint_test_credential("a", lvl))
        assert res["valid"] and res["clearance"] == lvl, lvl


def test_expired_refused():
    tok = I.mint_test_credential("a", "L1", ttl=-10)
    res = I.verify_credential(tok)
    assert not res["valid"] and "expired" in res["reason"]


def test_bad_clearance_refused():
    tok = I.mint_test_credential("a", "L9")
    res = I.verify_credential(tok)
    assert not res["valid"] and "clearance" in res["reason"]


def test_tampered_sig_refused():
    tok = I.mint_test_credential("a", "L1")
    h, p, s = tok.split(".")
    s = ("A" if s[0] != "A" else "B") + s[1:]
    res = I.verify_credential(h + "." + p + "." + s)
    assert not res["valid"] and "signature" in res["reason"]


def test_unknown_kid_refused():
    other = generate_keypair("other-1")
    tok = I.mint_test_credential("a", "L1", key=other)
    res = I.verify_credential(tok)  # lab JWKS has no "other-1"
    assert not res["valid"] and "kid" in res["reason"]


def test_wrong_alg_refused():
    import json
    from tollkeeper import envelope as E
    tok = I.mint_test_credential("a", "L1")
    h, p, s = tok.split(".")
    bad_h = E._b64u_encode(json.dumps(
        {"alg": "none", "typ": "JWT"}).encode())
    res = I.verify_credential(bad_h + "." + p + "." + s)
    assert not res["valid"] and "alg" in res["reason"]


def test_future_iat_refused():
    tok = I.mint_test_credential("a", "L1", now=int(time.time()) + 10_000)
    res = I.verify_credential(tok)
    assert not res["valid"] and "iat" in res["reason"]


def test_bad_iss_refused():
    tok = I.mint_test_credential("a", "L1", iss="evil.example")
    res = I.verify_credential(tok)
    assert not res["valid"] and "iss" in res["reason"]


def test_metering_counts():
    before = I.query_count()
    I.verify_credential(I.mint_test_credential("metered-1", "L0"))
    I.verify_credential("garbage")
    assert I.query_count() == before + 2
    assert I.query_count("metered-1") == 1


def test_reputation_empty():
    rep = R.reputation("brand-new-agent")
    assert rep["jobs"] == 0 and rep["score"] is None
    assert rep["total_volume_uusdc"] == 0


def test_receipt_issue_and_offline_verify():
    tx = B.mock_transfer("payerA", "workerA", 2_500_000, "job pay")
    env = R.issue_receipt("payerA", "workerA", "job-A1", tx, 2_500_000,
                          True, 250, "great work")
    ok, payload = R.verify_receipt_offline(env)
    assert ok and payload["job_id"] == "job-A1"
    assert payload["paid_amount_uusdc"] == 2_500_000
    # offline verify needs no database rows beyond the envelope itself
    ok2, _ = R.verify_receipt_offline(env, lab_jwks())
    assert ok2


def test_receipt_refused_unknown_tx():
    try:
        R.issue_receipt("p", "w", "job-fake", "mock_doesnotexist",
                        1_000_000, True, 10)
    except R.ReceiptRefused as e:
        assert "ledger" in str(e)
        return
    raise AssertionError("fake-tx receipt accepted")


def test_receipt_refused_overclaimed_amount():
    tx = B.mock_transfer("p", "w", 1_000_000)
    try:
        R.issue_receipt("p", "w", "job-over", tx, 2_000_000, True, 10)
    except R.ReceiptRefused:
        return
    raise AssertionError("over-claimed receipt accepted")


def test_receipt_refused_duplicate_job():
    tx = B.mock_transfer("p", "w", 1_000_000)
    R.issue_receipt("p", "w", "job-dup", tx, 1_000_000, True, 10)
    try:
        R.issue_receipt("p", "w", "job-dup", tx, 1_000_000, True, 10)
    except R.ReceiptRefused as e:
        assert "duplicate" in str(e)
        return
    raise AssertionError("duplicate job_id receipt accepted")


def test_reputation_score_math():
    agent = "workerScore"
    tx1 = B.mock_transfer("p", agent, 1_000_000)
    tx2 = B.mock_transfer("p", agent, 2_000_000)
    tx3 = B.mock_transfer("p", agent, 1_000_000)
    R.issue_receipt("p", agent, "js-1", tx1, 1_000_000, True, 10)
    R.issue_receipt("p", agent, "js-2", tx2, 2_000_000, True, 10)
    R.issue_receipt("p", agent, "js-3", tx3, 1_000_000, False, 10)
    rep = R.reputation(agent)
    assert rep["jobs"] == 3 and rep["completed"] == 2
    assert rep["disputed"] == 0
    assert rep["total_volume_uusdc"] == 4_000_000
    assert rep["total_volume_usdc"] == 4.0
    # 100 * (3M/4M) * 1 = 75.0
    assert rep["score"] == 75.0, rep["score"]


def test_dispute_decays_score():
    agent = "workerDisp"
    tx = B.mock_transfer("payerD", agent, 1_000_000)
    R.issue_receipt("payerD", agent, "jd-1", tx, 1_000_000, True, 10)
    before = R.reputation(agent)["score"]
    assert before == 100.0
    lock = B.lock_escrow("payerD", agent, "jd-2", 1_000_000, "hashD")
    d = B.open_dispute(lock["escrow_id"], "payerD", "bad job")
    B.resolve_dispute(d["dispute_id"], "refund")  # opener wins
    rep = R.reputation(agent)
    assert rep["disputed"] == 1
    # weight ~1.0 (fresh), jobs=1: 100 * 1 * (1 - 1/1) = 0.0
    assert rep["score"] == 0.0, rep["score"]


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("%d identity+reputation tests passed" % len(tests))
