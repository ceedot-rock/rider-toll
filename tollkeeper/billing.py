#!/usr/bin/env python3
"""tollkeeper.billing — Module B: the billing engine.

Built ON the x402 payment pattern, not beside it:

- Mocked settlement ledger: `mock_transfer` / `ledger_has`. In-memory
  SQLite, fake USDC, zero chain IO. Mainnet hooks are stub interfaces only
  (`settle_onchain` raises NotImplementedError). NO real money moves.
- Budgets: {agent_id, cap, window, categories}; every `authorize` decrements;
  over-cap raises BudgetExhausted (HTTP 402, code BUDGET_EXHAUSTED).
- Verified payment receipts: every settled payment yields a signed envelope
  receipt both sides can verify offline via the lab JWKS.
- Escrow: lock funds against a job-spec hash; release on a valid signed
  delivery receipt, or refund-on-timeout. 1% routing fee accounted at lock.
- Refunds/disputes: open with evidence -> respond -> resolve
  (refund / partial / release). Every step is a signed envelope in the
  audit trail. 5¢ dispute fee from the opener, returned if they win.

Money: integer micro-USDC ("uusdc"), 1 USDC = 1_000_000 uusdc.
"""

import hashlib
import time

from . import store
from .envelope import EnvelopeError, seal_with_lab, lab_jwks, verify_ok

MICRO = 1_000_000
DISPUTE_FEE = 50_000          # 5¢ in uusdc
ESCROW_FEE_BPS = 100          # 1% routing fee at lock time
LAB_FEES_ACCT = "lab:fees"

_TX_COUNTER = [0]  # process-local nonce so no two mock tx collide

WINDOWS = {"daily": 86400, "weekly": 604800, "monthly": 2592000, "job": None}


class BillingError(Exception):
    """Base billing failure."""


class BudgetExhausted(BillingError):
    """402-style refusal: the budget cannot cover this charge."""
    http_status = 402
    code = "BUDGET_EXHAUSTED"

    def __init__(self, agent_id, cap, spent, amount):
        self.agent_id = agent_id
        self.cap = cap
        self.spent = spent
        self.amount = amount
        super().__init__(
            "BUDGET_EXHAUSTED: agent %s cap %d spent %d charge %d (uusdc)"
            % (agent_id, cap, spent, amount))

    def as_402(self):
        return {"status": self.http_status, "code": self.code,
                "agent_id": self.agent_id, "cap_uusdc": self.cap,
                "spent_uusdc": self.spent, "charge_uusdc": self.amount}


# ---------------------------------------------------------------------------
# Mocked settlement ledger
# ---------------------------------------------------------------------------

def mock_transfer(sender, recipient, amount_uusdc, memo="", now=None):
    """Record a FAKE USDC transfer. Returns the mock tx_hash.

    No chain IO, no real money. The tx_hash is prefixed 'mock_' so it can
    never be mistaken for a real transaction.
    """
    if not isinstance(amount_uusdc, int) or amount_uusdc <= 0:
        raise BillingError("amount must be a positive int (uusdc)")
    now = store.now() if now is None else now
    _TX_COUNTER[0] += 1
    preimage = "%s|%s|%d|%s|%d|%d" % (
        sender, recipient, amount_uusdc, memo, now, _TX_COUNTER[0])
    tx_hash = "mock_" + hashlib.sha256(preimage.encode()).hexdigest()
    con = store.connect()
    try:
        con.execute(
            "INSERT INTO transfers(tx_hash, sender, recipient, amount, memo,"
            " created_at) VALUES (?,?,?,?,?,?)",
            (tx_hash, sender, recipient, amount_uusdc, memo, now))
        con.commit()
    finally:
        con.close()
    return tx_hash


def ledger_has(tx_hash):
    con = store.connect()
    try:
        row = con.execute("SELECT tx_hash FROM transfers WHERE tx_hash=?",
                          (tx_hash,)).fetchone()
        return row is not None
    finally:
        con.close()


def get_transfer(tx_hash):
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM transfers WHERE tx_hash=?",
                          (tx_hash,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def payment_receipt(tx_hash):
    """Signed verified-payment receipt envelope for a ledger transfer."""
    tx = get_transfer(tx_hash)
    if tx is None:
        raise BillingError("unknown tx_hash %r" % tx_hash)
    payload = {"type": "payment_receipt", "tx_hash": tx_hash,
               "sender": tx["sender"], "recipient": tx["recipient"],
               "amount_uusdc": tx["amount"], "created_at": store.now()}
    env = seal_with_lab(payload)
    con = store.connect()
    try:
        con.execute(
            "INSERT OR IGNORE INTO payment_receipts(tx_hash, envelope,"
            " created_at) VALUES (?,?,?)",
            (tx_hash, store.dumps(env), store.now()))
        con.commit()
    finally:
        con.close()
    return env


def settle_onchain(*args, **kwargs):
    """Mainnet hook — STUB. Real settlement is never attempted from here."""
    raise NotImplementedError(
        "settle_onchain is a stub: no real USDC moves without Corey's "
        "explicit per-charge approval, executed through the x402 flow.")


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

def set_budget(agent_id, cap_uusdc, window="monthly", categories=(), now=None):
    """Create a budget. window in daily/weekly/monthly/job. 1¢/mo toll —
    metered by budget count, not charged here."""
    if window not in WINDOWS:
        raise BillingError("unknown window %r" % window)
    if not isinstance(cap_uusdc, int) or cap_uusdc <= 0:
        raise BillingError("cap must be a positive int (uusdc)")
    now = store.now() if now is None else now
    con = store.connect()
    try:
        cur = con.execute(
            "INSERT INTO budgets(agent_id, cap, spent, window, window_start,"
            " categories, active, created_at) VALUES (?,?,?,?,?,?,1,?)",
            (agent_id, cap_uusdc, 0, window, now,
             store.dumps(list(categories)), now))
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def _active_budget(con, agent_id, category, now):
    rows = con.execute(
        "SELECT * FROM budgets WHERE agent_id=? AND active=1"
        " ORDER BY created_at DESC", (agent_id,)).fetchall()
    for row in rows:
        cats = store.loads(row["categories"]) or []
        if cats and category not in cats:
            continue
        secs = WINDOWS[row["window"]]
        if secs is not None and now >= row["window_start"] + secs:
            con.execute(
                "UPDATE budgets SET spent=0, window_start=? WHERE id=?",
                (now, row["id"]))
            row = con.execute("SELECT * FROM budgets WHERE id=?",
                              (row["id"],)).fetchone()
        return row
    return None


def authorize(agent_id, amount_uusdc, category="default", now=None):
    """Decrement the agent's budget. Raises BudgetExhausted on over-cap."""
    if not isinstance(amount_uusdc, int) or amount_uusdc <= 0:
        raise BillingError("amount must be a positive int (uusdc)")
    now = store.now() if now is None else now
    con = store.connect()
    try:
        row = _active_budget(con, agent_id, category, now)
        if row is None:
            raise BudgetExhausted(agent_id, 0, 0, amount_uusdc)
        if row["spent"] + amount_uusdc > row["cap"]:
            raise BudgetExhausted(agent_id, row["cap"], row["spent"],
                                  amount_uusdc)
        con.execute("UPDATE budgets SET spent=spent+? WHERE id=?",
                    (amount_uusdc, row["id"]))
        con.commit()
        return {"budget_id": row["id"], "spent_uusdc": row["spent"] + amount_uusdc,
                "cap_uusdc": row["cap"]}
    finally:
        con.close()


def get_budget(agent_id):
    con = store.connect()
    try:
        row = con.execute(
            "SELECT * FROM budgets WHERE agent_id=? AND active=1"
            " ORDER BY created_at DESC LIMIT 1", (agent_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Escrow
# ---------------------------------------------------------------------------

def _escrow_acct(escrow_id):
    return "escrow:%d" % escrow_id


def lock_escrow(payer, agent_id, job_id, amount_uusdc, job_spec_hash,
                timeout_sec=86400, now=None):
    """Payer locks funds against a job-spec hash.

    1% routing fee accounted at lock time (mock transfer to lab:fees).
    Returns {"escrow_id", "fee_uusdc", "net_uusdc", "envelope"}.
    """
    if not isinstance(amount_uusdc, int) or amount_uusdc <= 0:
        raise BillingError("amount must be a positive int (uusdc)")
    if not job_id or not job_spec_hash:
        raise BillingError("job_id and job_spec_hash are required")
    now = store.now() if now is None else now
    fee = amount_uusdc * ESCROW_FEE_BPS // 10000
    net = amount_uusdc - fee
    con = store.connect()
    try:
        cur = con.execute(
            "INSERT INTO escrows(job_id, payer, agent_id, amount, fee,"
            " job_spec_hash, status, lock_tx, created_at, timeout_at)"
            " VALUES (?,?,?,?,?,?,'locked','',?,?)",
            (job_id, payer, agent_id, amount_uusdc, fee, job_spec_hash,
             now, now + timeout_sec))
        escrow_id = cur.lastrowid
        con.commit()  # release the write lock before mock_transfer's
        con.close()   # own connection below
    except Exception:
        con.rollback()
        con.close()
        raise
    # Mock transfers run on their own connections (committed immediately).
    lock_tx = mock_transfer(payer, _escrow_acct(escrow_id), amount_uusdc,
                            "escrow lock job %s" % job_id, now=now)
    mock_transfer(_escrow_acct(escrow_id), LAB_FEES_ACCT, fee,
                  "1%% routing fee job %s" % job_id, now=now)
    con = store.connect()
    try:
        con.execute("UPDATE escrows SET lock_tx=? WHERE id=?",
                    (lock_tx, escrow_id))
        con.commit()
    finally:
        con.close()
    env = seal_with_lab({"type": "escrow_locked", "escrow_id": escrow_id,
                         "job_id": job_id, "payer": payer, "agent_id": agent_id,
                         "amount_uusdc": amount_uusdc, "fee_uusdc": fee,
                         "job_spec_hash": job_spec_hash,
                         "timeout_at": now + timeout_sec, "created_at": now})
    return {"escrow_id": escrow_id, "fee_uusdc": fee, "net_uusdc": net,
            "lock_tx": lock_tx, "envelope": env}


def get_escrow(escrow_id):
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM escrows WHERE id=?",
                          (escrow_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def release_escrow(escrow_id, delivery_receipt_envelope, jwks=None, now=None):
    """Release escrowed funds to the agent on a valid signed delivery receipt.

    The receipt must be a lab-sealed envelope with type "delivery_receipt",
    delivered_ok=true, and a job_id matching this escrow.
    """
    now = store.now() if now is None else now
    jwks = lab_jwks() if jwks is None else jwks
    ok, payload = verify_ok(delivery_receipt_envelope, jwks)
    if not ok:
        raise BillingError("delivery receipt invalid: %s" % payload)
    if payload.get("type") != "delivery_receipt":
        raise BillingError("envelope is not a delivery receipt")
    if not payload.get("delivered_ok"):
        raise BillingError("delivery receipt reports failure; use disputes")
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM escrows WHERE id=?",
                          (escrow_id,)).fetchone()
        if row is None:
            raise BillingError("unknown escrow %r" % escrow_id)
        if row["status"] != "locked":
            raise BillingError("escrow %d is %s, not locked"
                               % (escrow_id, row["status"]))
        if payload.get("job_id") != row["job_id"]:
            raise BillingError("receipt job_id does not match escrow")
        if payload.get("agent_id") != row["agent_id"]:
            raise BillingError("receipt agent_id does not match escrow")
        net = row["amount"] - row["fee"]
        mock_transfer(_escrow_acct(escrow_id), row["agent_id"], net,
                      "escrow release job %s" % row["job_id"], now=now)
        con.execute("UPDATE escrows SET status='released', settled_at=?"
                    " WHERE id=?", (now, escrow_id))
        con.commit()
    finally:
        con.close()
    return seal_with_lab({"type": "escrow_released", "escrow_id": escrow_id,
                          "job_id": row["job_id"], "agent_id": row["agent_id"],
                          "net_uusdc": net, "created_at": now})


def sweep_timeouts(now=None):
    """Refund payer on escrows past timeout. Lab keeps the lock-time fee."""
    now = store.now() if now is None else now
    con = store.connect()
    swept = []
    try:
        rows = con.execute(
            "SELECT * FROM escrows WHERE status='locked' AND timeout_at<=?",
            (now,)).fetchall()
        for row in rows:
            net = row["amount"] - row["fee"]
            mock_transfer(_escrow_acct(row["id"]), row["payer"], net,
                          "escrow timeout refund job %s" % row["job_id"],
                          now=now)
            con.execute("UPDATE escrows SET status='timed_out', settled_at=?"
                        " WHERE id=?", (now, row["id"]))
            swept.append(row["id"])
        con.commit()
    finally:
        con.close()
    return swept


# ---------------------------------------------------------------------------
# Disputes
# ---------------------------------------------------------------------------

class DisputeError(BillingError):
    """Dispute-flow failure."""


def open_dispute(escrow_id, opener, evidence="", now=None):
    """Open a dispute on a locked escrow. 5¢ fee from the opener (spam
    deterrent), returned if they win. Returns {"dispute_id", "envelope"}."""
    now = store.now() if now is None else now
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM escrows WHERE id=?",
                          (escrow_id,)).fetchone()
        if row is None:
            raise DisputeError("unknown escrow %r" % escrow_id)
        if row["status"] != "locked":
            raise DisputeError("escrow %d is %s; disputes need locked funds"
                               % (escrow_id, row["status"]))
        if opener not in (row["payer"], row["agent_id"]):
            raise DisputeError("opener must be the payer or the agent")
        fee_tx = mock_transfer(opener, LAB_FEES_ACCT, DISPUTE_FEE,
                               "dispute fee escrow %d" % escrow_id, now=now)
        cur = con.execute(
            "INSERT INTO disputes(escrow_id, opener, evidence, status, fee,"
            " fee_tx, created_at) VALUES (?,?,?,'open',?,?,?)",
            (escrow_id, opener, evidence, DISPUTE_FEE, fee_tx, now))
        dispute_id = cur.lastrowid
        con.commit()
    finally:
        con.close()
    env = seal_with_lab({"type": "dispute_opened", "dispute_id": dispute_id,
                         "escrow_id": escrow_id, "opener": opener,
                         "evidence": evidence, "fee_uusdc": DISPUTE_FEE,
                         "created_at": now})
    return {"dispute_id": dispute_id, "fee_tx": fee_tx, "envelope": env}


def respond_dispute(dispute_id, responder, response, now=None):
    now = store.now() if now is None else now
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM disputes WHERE id=?",
                          (dispute_id,)).fetchone()
        if row is None:
            raise DisputeError("unknown dispute %r" % dispute_id)
        if row["status"] != "open":
            raise DisputeError("dispute %d is %s" % (dispute_id, row["status"]))
        esc = con.execute("SELECT * FROM escrows WHERE id=?",
                          (row["escrow_id"],)).fetchone()
        if responder not in (esc["payer"], esc["agent_id"]):
            raise DisputeError("responder must be a party to the escrow")
        con.execute("UPDATE disputes SET response=?, status='answered'"
                    " WHERE id=?", (response, dispute_id))
        con.commit()
    finally:
        con.close()
    return seal_with_lab({"type": "dispute_answered", "dispute_id": dispute_id,
                          "responder": responder, "response": response,
                          "created_at": now})


def resolve_dispute(dispute_id, outcome, partial_uusdc=None, resolver="lab",
                    now=None):
    """Resolve: "refund" | "partial" | "release".

    - refund: payer gets net escrow; opener's 5¢ fee returned (opener wins).
    - release: agent gets net escrow; lab keeps the 5¢ (opener loses).
    - partial: partial_uusdc to payer, remainder to agent; fee returned
      (opener wins partially).
    Returns the resolution envelope.
    """
    if outcome not in ("refund", "partial", "release"):
        raise DisputeError("outcome must be refund|partial|release")
    now = store.now() if now is None else now
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM disputes WHERE id=?",
                          (dispute_id,)).fetchone()
        if row is None:
            raise DisputeError("unknown dispute %r" % dispute_id)
        if row["status"] not in ("open", "answered"):
            raise DisputeError("dispute %d already %s"
                               % (dispute_id, row["status"]))
        esc = con.execute("SELECT * FROM escrows WHERE id=?",
                          (row["escrow_id"],)).fetchone()
        if esc["status"] != "locked":
            raise DisputeError("escrow %d is %s" % (esc["id"], esc["status"]))
        net = esc["amount"] - esc["fee"]
        acct = _escrow_acct(esc["id"])
        if outcome == "refund":
            mock_transfer(acct, esc["payer"], net,
                          "dispute refund job %s" % esc["job_id"], now=now)
            mock_transfer(LAB_FEES_ACCT, row["opener"], row["fee"],
                          "dispute fee returned %d" % dispute_id, now=now)
            opener_won, resolution, new_status = 1, "refund", "refunded"
        elif outcome == "release":
            mock_transfer(acct, esc["agent_id"], net,
                          "dispute release job %s" % esc["job_id"], now=now)
            opener_won, resolution, new_status = 0, "release", "released"
        else:
            if (not isinstance(partial_uusdc, int) or
                    not 0 < partial_uusdc < net):
                raise DisputeError(
                    "partial needs 0 < partial_uusdc < net (%d)" % net)
            mock_transfer(acct, esc["payer"], partial_uusdc,
                          "dispute partial job %s" % esc["job_id"], now=now)
            mock_transfer(acct, esc["agent_id"], net - partial_uusdc,
                          "dispute partial job %s" % esc["job_id"], now=now)
            mock_transfer(LAB_FEES_ACCT, row["opener"], row["fee"],
                          "dispute fee returned %d" % dispute_id, now=now)
            opener_won = 1
            resolution = "partial:%d" % partial_uusdc
            new_status = "released"
        con.execute("UPDATE disputes SET status='resolved', opener_won=?,"
                    " resolution=?, resolved_at=? WHERE id=?",
                    (opener_won, resolution, now, dispute_id))
        con.execute("UPDATE escrows SET status=?, settled_at=? WHERE id=?",
                    (new_status, now, esc["id"]))
        con.commit()
    finally:
        con.close()
    return seal_with_lab({"type": "dispute_resolved",
                          "dispute_id": dispute_id, "escrow_id": esc["id"],
                          "outcome": resolution, "opener_won": opener_won,
                          "resolver": resolver, "created_at": now})


def get_dispute(dispute_id):
    con = store.connect()
    try:
        row = con.execute("SELECT * FROM disputes WHERE id=?",
                          (dispute_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def disputes_against(agent_id):
    """Disputes touching an agent's escrows: open ones plus resolved ones
    the opener won. Used by the reputation module's dispute decay."""
    con = store.connect()
    try:
        rows = con.execute(
            """SELECT d.* FROM disputes d JOIN escrows e ON d.escrow_id = e.id
               WHERE e.agent_id = ?
               AND (d.status IN ('open','answered')
                    OR (d.status='resolved' AND d.opener_won=1))""",
            (agent_id,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        con.close()
