#!/usr/bin/env python3
"""Tests for tollkeeper.billing — run: python3 test_billing.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TOLLKEEPER_DB"] = "/tmp/tollkeeper-test-billing.db"
if os.path.exists(os.environ["TOLLKEEPER_DB"]):
    os.remove(os.environ["TOLLKEEPER_DB"])

from tollkeeper import billing as B
from tollkeeper import store
from tollkeeper.envelope import lab_jwks, verify_ok


def test_mock_transfer_and_ledger():
    tx = B.mock_transfer("alice", "bob", 1_500_000, "test")
    assert tx.startswith("mock_")
    assert B.ledger_has(tx)
    assert not B.ledger_has("mock_nope")
    got = B.get_transfer(tx)
    assert got["sender"] == "alice" and got["amount"] == 1_500_000


def test_mock_transfer_rejects_bad_amount():
    for bad in (0, -5, 1.5, "100"):
        try:
            B.mock_transfer("a", "b", bad)
        except B.BillingError:
            continue
        raise AssertionError("accepted bad amount %r" % bad)


def test_payment_receipt():
    tx = B.mock_transfer("alice", "bob", 2_000_000)
    env = B.payment_receipt(tx)
    ok, payload = verify_ok(env, lab_jwks())
    assert ok and payload["type"] == "payment_receipt"
    assert payload["tx_hash"] == tx and payload["amount_uusdc"] == 2_000_000
    try:
        B.payment_receipt("mock_unknown")
    except B.BillingError:
        return
    raise AssertionError("receipt for unknown tx")


def test_settle_onchain_is_stub():
    try:
        B.settle_onchain("0xabc")
    except NotImplementedError:
        return
    raise AssertionError("settle_onchain did not refuse")


def test_budget_authorize_and_exhaust():
    B.set_budget("agent1", 10_000_000, window="monthly")
    r = B.authorize("agent1", 3_000_000)
    assert r["spent_uusdc"] == 3_000_000 and r["cap_uusdc"] == 10_000_000
    B.authorize("agent1", 7_000_000)  # exactly at cap: ok
    try:
        B.authorize("agent1", 1)
    except B.BudgetExhausted as e:
        assert e.http_status == 402 and e.code == "BUDGET_EXHAUSTED"
        as402 = e.as_402()
        assert as402["status"] == 402 and as402["code"] == "BUDGET_EXHAUSTED"
        return
    raise AssertionError("over-cap charge authorized")


def test_no_budget_refuses():
    try:
        B.authorize("nobody", 100)
    except B.BudgetExhausted as e:
        assert e.cap == 0
        return
    raise AssertionError("charge with no budget authorized")


def test_budget_categories():
    B.set_budget("agent2", 5_000_000, categories=["compress"])
    B.authorize("agent2", 1_000_000, category="compress")
    try:
        B.authorize("agent2", 1_000_000, category="other")
    except B.BudgetExhausted:
        return
    raise AssertionError("wrong-category charge authorized")


def test_budget_window_reset():
    past = store.now() - 100_000  # > 1 day ago
    B.set_budget("agent3", 1_000_000, window="daily")
    # rewrite window_start into the past, spend the cap
    con = store.connect()
    con.execute("UPDATE budgets SET window_start=?, spent=1000000"
                " WHERE agent_id='agent3'", (past,))
    con.commit()
    con.close()
    r = B.authorize("agent3", 500_000, now=store.now())  # window rolled: ok
    assert r["spent_uusdc"] == 500_000


def test_escrow_lock_and_release():
    from tollkeeper import reputation as R
    payer, agent = "payer1", "worker1"
    lock = B.lock_escrow(payer, agent, "job-1", 2_000_000, "spechash1")
    assert lock["fee_uusdc"] == 20_000  # 1%
    assert lock["net_uusdc"] == 1_980_000
    esc = B.get_escrow(lock["escrow_id"])
    assert esc["status"] == "locked"
    # fee went to lab
    con = store.connect()
    fee_tx = con.execute(
        "SELECT * FROM transfers WHERE recipient=? AND amount=?",
        (B.LAB_FEES_ACCT, 20_000)).fetchone()
    con.close()
    assert fee_tx is not None
    # worker delivers; payer receipts; release
    pay_tx = B.mock_transfer(payer, agent, 2_000_000, "job-1 pay")
    receipt = R.issue_receipt(payer, agent, "job-1", pay_tx, 2_000_000,
                              True, 120, "done")
    rel = B.release_escrow(lock["escrow_id"], receipt)
    ok, payload = verify_ok(rel, lab_jwks())
    assert ok and payload["net_uusdc"] == 1_980_000
    assert B.get_escrow(lock["escrow_id"])["status"] == "released"
    # double release refused
    try:
        B.release_escrow(lock["escrow_id"], receipt)
    except B.BillingError:
        return
    raise AssertionError("double release allowed")


def test_escrow_release_needs_matching_receipt():
    from tollkeeper import reputation as R
    lock = B.lock_escrow("p2", "w2", "job-2", 1_000_000, "hash2")
    pay_tx = B.mock_transfer("p2", "w2", 1_000_000)
    wrong_job = R.issue_receipt("p2", "w2", "job-OTHER", pay_tx, 1_000_000,
                                True, 5)
    try:
        B.release_escrow(lock["escrow_id"], wrong_job)
    except B.BillingError as e:
        assert "job_id" in str(e)
    else:
        raise AssertionError("mismatched receipt released escrow")
    failed = R.issue_receipt("p2", "w2", "job-2b", pay_tx, 1_000_000,
                             False, 5)
    try:
        B.release_escrow(lock["escrow_id"], failed)
    except B.BillingError as e:
        assert "failure" in str(e)
        return
    raise AssertionError("failed-delivery receipt released escrow")


def test_escrow_timeout_refunds():
    lock = B.lock_escrow("p3", "w3", "job-3", 1_000_000, "hash3",
                         timeout_sec=10)
    swept = B.sweep_timeouts(now=store.now() + 10_000)
    assert lock["escrow_id"] in swept
    assert B.get_escrow(lock["escrow_id"])["status"] == "timed_out"
    con = store.connect()
    refund = con.execute(
        "SELECT * FROM transfers WHERE sender LIKE 'escrow:%'"
        " AND recipient='p3'").fetchone()
    con.close()
    assert refund is not None and refund["amount"] == 990_000  # fee kept


def test_dispute_refund_path():
    lock = B.lock_escrow("p4", "w4", "job-4", 1_000_000, "hash4")
    d = B.open_dispute(lock["escrow_id"], "p4", "never delivered")
    assert d["dispute_id"] > 0
    B.respond_dispute(d["dispute_id"], "w4", "did too")
    env = B.resolve_dispute(d["dispute_id"], "refund")
    ok, payload = verify_ok(env, lab_jwks())
    assert ok and payload["outcome"] == "refund" and payload["opener_won"] == 1
    # opener got the 5c fee back
    con = store.connect()
    fee_back = con.execute(
        "SELECT * FROM transfers WHERE sender=? AND recipient='p4'"
        " AND amount=?", (B.LAB_FEES_ACCT, B.DISPUTE_FEE)).fetchone()
    con.close()
    assert fee_back is not None
    assert B.get_escrow(lock["escrow_id"])["status"] == "refunded"


def test_dispute_release_path():
    lock = B.lock_escrow("p5", "w5", "job-5", 1_000_000, "hash5")
    d = B.open_dispute(lock["escrow_id"], "p5", "late")
    env = B.resolve_dispute(d["dispute_id"], "release")
    ok, payload = verify_ok(env, lab_jwks())
    assert ok and payload["opener_won"] == 0
    # lab kept the fee: no fee-return transfer
    con = store.connect()
    fee_back = con.execute(
        "SELECT * FROM transfers WHERE sender=? AND recipient='p5'"
        " AND amount=?", (B.LAB_FEES_ACCT, B.DISPUTE_FEE)).fetchone()
    con.close()
    assert fee_back is None
    assert B.get_escrow(lock["escrow_id"])["status"] == "released"


def test_dispute_partial_path():
    lock = B.lock_escrow("p6", "w6", "job-6", 1_000_000, "hash6")
    d = B.open_dispute(lock["escrow_id"], "p6", "half done")
    env = B.resolve_dispute(d["dispute_id"], "partial",
                            partial_uusdc=400_000)
    ok, payload = verify_ok(env, lab_jwks())
    assert ok and payload["outcome"] == "partial:400000"
    con = store.connect()
    to_payer = con.execute(
        "SELECT amount FROM transfers WHERE recipient='p6'"
        " AND memo LIKE '%partial%'").fetchone()
    con.close()
    assert to_payer is not None and to_payer["amount"] == 400_000


def test_dispute_rules():
    lock = B.lock_escrow("p7", "w7", "job-7", 1_000_000, "hash7")
    # stranger cannot open
    try:
        B.open_dispute(lock["escrow_id"], "stranger", "x")
    except B.DisputeError:
        pass
    else:
        raise AssertionError("stranger opened dispute")
    d = B.open_dispute(lock["escrow_id"], "p7", "x")
    B.resolve_dispute(d["dispute_id"], "release")
    # cannot open on settled escrow
    try:
        B.open_dispute(lock["escrow_id"], "p7", "again")
    except B.DisputeError:
        pass
    else:
        raise AssertionError("dispute opened on settled escrow")
    # bad partial amount
    lock2 = B.lock_escrow("p8", "w8", "job-8", 1_000_000, "hash8")
    d2 = B.open_dispute(lock2["escrow_id"], "p8", "x")
    try:
        B.resolve_dispute(d2["dispute_id"], "partial", partial_uusdc=990_000)
    except B.DisputeError:
        return
    raise AssertionError("over-net partial accepted")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("%d billing tests passed" % len(tests))
