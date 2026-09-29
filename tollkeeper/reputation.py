#!/usr/bin/env python3
"""tollkeeper.reputation — Module A, part 2: portable reputation.

Delivery receipts are signed envelopes::

    {"type": "delivery_receipt", "job_id": …, "agent_id": …, "payer": …,
     "tx_hash": …, "paid_amount_uusdc": …, "delivered_ok": bool,
     "latency_ms": …, "note": …, "issued_at": …}

REFUSAL RULE (no fake reviews): a receipt is refused unless its tx_hash
exists in the billing ledger AND the ledger amount covers the receipt's
paid_amount. In production the ledger is x402-verified chain state; here it
is the mocked ledger — the rule's strength follows the ledger's integrity.

`reputation(agent_id)` -> {jobs, completed, disputed, total_volume_uusdc,
total_volume_usdc, score}. Score formula (transparent, no black box):

    jobs == 0                      -> score None ("insufficient data")
    volume_completion = completed_volume / total_volume
    w(d)  = 0.5 ** (age_days / 180)        # per-dispute half-life decay
    dispute_factor = 1 - min(1, sum(w) / max(1, jobs))
    score = round(100 * volume_completion * dispute_factor, 2)

"Disputed" counts open disputes plus resolved disputes the opener won
against the agent's escrows. Receipts verify offline anywhere with the lab
JWKS — reputation is portable, not locked to this database.

Toll: 1¢ per receipt issuance — metered here (receipt count), not charged.
Reputation QUERIES are free (the toll was paid at write time).
"""

import sqlite3
import time

from . import store
from . import billing
from .envelope import (EnvelopeError, lab_jwks, seal_with_lab, verify_ok)


class ReceiptRefused(Exception):
    """A delivery receipt was refused (fake/unknown payment, duplicate)."""


ISSUE_TOLL_METER = "receipt_issued"  # accounting key; charging is future work


def issue_receipt(payer, agent_id, job_id, tx_hash, paid_amount_uusdc,
                  delivered_ok, latency_ms, note="", now=None):
    """Issue a signed delivery receipt. Refuses fake reviews.

    Raises ReceiptRefused if tx_hash is unknown to the billing ledger, if
    the ledger amount is smaller than paid_amount_uusdc, or if job_id was
    already receipted.
    """
    now = store.now() if now is None else now
    if not isinstance(paid_amount_uusdc, int) or paid_amount_uusdc <= 0:
        raise ReceiptRefused("paid_amount must be a positive int (uusdc)")
    if not isinstance(latency_ms, int) or latency_ms < 0:
        raise ReceiptRefused("latency_ms must be a non-negative int")
    tx = billing.get_transfer(tx_hash)
    if tx is None:
        raise ReceiptRefused(
            "tx_hash %r not in the billing ledger — no fake reviews" % tx_hash)
    if tx["amount"] < paid_amount_uusdc:
        raise ReceiptRefused(
            "ledger amount %d < receipt paid_amount %d"
            % (tx["amount"], paid_amount_uusdc))
    payload = {"type": "delivery_receipt", "job_id": job_id,
               "agent_id": agent_id, "payer": payer, "tx_hash": tx_hash,
               "paid_amount_uusdc": paid_amount_uusdc,
               "delivered_ok": bool(delivered_ok),
               "latency_ms": latency_ms, "note": note, "issued_at": now}
    env = seal_with_lab(payload)
    con = store.connect()
    try:
        con.execute(
            "INSERT INTO receipts(job_id, agent_id, payer, tx_hash,"
            " paid_amount, delivered_ok, latency_ms, note, envelope,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (job_id, agent_id, payer, tx_hash, paid_amount_uusdc,
             1 if delivered_ok else 0, latency_ms, note,
             store.dumps(env), now))
        con.commit()
    except sqlite3.IntegrityError:
        raise ReceiptRefused("duplicate job_id %r" % job_id)
    finally:
        con.close()
    return env


def verify_receipt_offline(envelope, jwks=None):
    """Verify a receipt anywhere, no database. Returns (ok, payload|reason)."""
    jwks = lab_jwks() if jwks is None else jwks
    ok, payload = verify_ok(envelope, jwks)
    if not ok:
        return False, payload
    if payload.get("type") != "delivery_receipt":
        return False, "not a delivery receipt"
    return True, payload


def get_receipts(agent_id):
    con = store.connect()
    try:
        rows = con.execute(
            "SELECT * FROM receipts WHERE agent_id=? ORDER BY created_at",
            (agent_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()


def receipt_count():
    """Toll accounting: receipts issued (1¢ each at write time)."""
    con = store.connect()
    try:
        return con.execute("SELECT COUNT(*) c FROM receipts").fetchone()["c"]
    finally:
        con.close()


def _dispute_weight(dispute, now):
    ts = dispute.get("resolved_at") or dispute.get("created_at") or now
    age_days = max(0.0, (now - ts) / 86400.0)
    return 0.5 ** (age_days / 180.0)


def reputation(agent_id, now=None):
    """Reputation summary. score is None when there is no history."""
    now = store.now() if now is None else now
    receipts = get_receipts(agent_id)
    jobs = len(receipts)
    completed = sum(1 for r in receipts if r["delivered_ok"])
    total_volume = sum(r["paid_amount"] for r in receipts)
    completed_volume = sum(r["paid_amount"] for r in receipts
                           if r["delivered_ok"])
    disputes = billing.disputes_against(agent_id)
    disputed = len(disputes)
    if jobs == 0:
        score = None
    else:
        volume_completion = (completed_volume / total_volume
                             if total_volume else 0.0)
        decayed = sum(_dispute_weight(d, now) for d in disputes)
        dispute_factor = 1.0 - min(1.0, decayed / max(1, jobs))
        score = round(100.0 * volume_completion * dispute_factor, 2)
    return {"agent_id": agent_id, "jobs": jobs, "completed": completed,
            "disputed": disputed, "total_volume_uusdc": total_volume,
            "total_volume_usdc": total_volume / billing.MICRO,
            "score": score,
            "score_formula": ("100 * (completed_volume/total_volume)"
                              " * (1 - min(1, sum(0.5^(age_days/180))/jobs))")}
