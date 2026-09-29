"""Module E — bonding & insurance primitives.

An agent stakes a USDC-denominated bond behind a promise. If a machine-
readable attestation fires a condition (dispute upheld, oracle refusal...),
the bond is slashed per the conditions; otherwise it is released. Every
movement is a signed envelope in the ledger. The audit-trail export is the
underwriting data an insurer needs — we sell the data, we don't underwrite.

ALL settlement is MOCKED (in-memory / SQLite balances). No real USDC moves.

Tolls (metered, no real charge):
  - stake: 1% of bonded value at stake time
  - export_audit_trail: 5c

Money: integer micro-USDC ("uusdc") inside envelopes. Never floats.
"""

import json
import secrets
import sqlite3
import time
from datetime import datetime, timezone

from . import store
from .envelope import sign, verify, envelope_id, EnvelopeError

DB_PATH = None  # set by TollkeeperDB or defaults to package tollkeeper.db

# trigger -> (expected attestation_type, expected verdict/outcome)
TRIGGER_ATTESTATION = {
    "dispute_upheld": ("dispute_resolution", "upheld"),
    "oracle_refuse": ("exactness_attestation", "refuse"),
    "oracle_fail": ("exactness_attestation", "fail"),
    "timeout_default": ("timeout_certificate", "default"),
}

RECOURSE_POOL = "lab:recourse-pool"  # default slash recipient (mocked)

AUDIT_EXPORT_FEE_UUSDC = 50_000   # 5c
TRANSFER_FEE_UUSDC = 20_000       # 2c (memory module; kept here for reference)


class BondsError(Exception):
    pass


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_uusdc(amount_usdc):
    """int/float USDC -> integer micro-USDC. Refuses negatives and non-numeric."""
    if isinstance(amount_usdc, bool) or not isinstance(amount_usdc, (int, float)):
        raise BondsError("amount_usdc must be a number, got %r" % type(amount_usdc))
    if amount_usdc < 0:
        raise BondsError("amount_usdc must be >= 0")
    return int(round(amount_usdc * 1_000_000))


def _validate_conditions(conditions):
    if not isinstance(conditions, list) or not conditions:
        raise BondsError("conditions must be a non-empty list")
    seen = set()
    for c in conditions:
        if not isinstance(c, dict):
            raise BondsError("each condition must be a dict")
        on = c.get("on")
        pct = c.get("slash_pct")
        if on not in TRIGGER_ATTESTATION:
            raise BondsError("unknown trigger %r; known: %s"
                             % (on, sorted(TRIGGER_ATTESTATION)))
        if on in seen:
            raise BondsError("duplicate trigger %r" % on)
        seen.add(on)
        if not isinstance(pct, (int, float)) or isinstance(pct, bool):
            raise BondsError("slash_pct must be a number")
        if not (0 < pct <= 100):
            raise BondsError("slash_pct must be in (0, 100]")
    return conditions


SCHEMA = """
CREATE TABLE IF NOT EXISTS bonds(
  bond_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  amount_uusdc INTEGER NOT NULL,
  remaining_uusdc INTEGER NOT NULL,
  conditions_json TEXT NOT NULL,
  status TEXT NOT NULL,            -- active | released | exhausted
  stake_envelope TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bond_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bond_id TEXT NOT NULL,
  kind TEXT NOT NULL,              -- stake | slash | release
  amount_uusdc INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meter(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  module TEXT NOT NULL,
  operation TEXT NOT NULL,
  amount_uusdc INTEGER NOT NULL,
  ref_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mock_balances(
  agent_id TEXT PRIMARY KEY,
  balance_uusdc INTEGER NOT NULL
);
"""


class BondLedger:
    """Bonding ledger. Pass a dev keypair (dict with d/kid) for signing and a
    JWKS ({kid: jwk}) for verifying evidence envelopes."""

    def __init__(self, key, jwks, db_path=None):
        if "d" not in key or "kid" not in key:
            raise BondsError("key must be a keypair dict with 'd' and 'kid'")
        self.key = key
        self.jwks = jwks
        self.db_path = db_path or DB_PATH or _default_db()
        self.db = sqlite3.connect(self.db_path)
        self.db.executescript(SCHEMA)
        self.db.commit()

    # -- mocked balances -------------------------------------------------
    def fund(self, agent_id, amount_usdc):
        """Test/ops helper: credit a mocked balance. No real money."""
        amt = to_uusdc(amount_usdc)
        cur = self.db.execute("SELECT balance_uusdc FROM mock_balances WHERE agent_id=?",
                              (agent_id,))
        row = cur.fetchone()
        new = (row[0] if row else 0) + amt
        self.db.execute(
            "INSERT INTO mock_balances(agent_id, balance_uusdc) VALUES(?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET balance_uusdc=?",
            (agent_id, new, new))
        self.db.commit()
        return new

    def balance_of(self, agent_id):
        cur = self.db.execute("SELECT balance_uusdc FROM mock_balances WHERE agent_id=?",
                              (agent_id,))
        row = cur.fetchone()
        return row[0] if row else 0

    def _move(self, frm, to, amount_uusdc):
        if amount_uusdc < 0:
            raise BondsError("negative movement")
        if self.balance_of(frm) < amount_uusdc:
            raise BondsError("insufficient mocked balance for %s" % frm)
        self.db.execute("UPDATE mock_balances SET balance_uusdc=balance_uusdc-? WHERE agent_id=?",
                        (amount_uusdc, frm))
        cur = self.db.execute("SELECT balance_uusdc FROM mock_balances WHERE agent_id=?", (to,))
        if cur.fetchone():
            self.db.execute("UPDATE mock_balances SET balance_uusdc=balance_uusdc+? WHERE agent_id=?",
                            (amount_uusdc, to))
        else:
            self.db.execute("INSERT INTO mock_balances(agent_id, balance_uusdc) VALUES(?,?)",
                            (to, amount_uusdc))

    def _meter(self, module, operation, amount_uusdc, ref_id):
        """Platform-shared meter table: (module, operation, amount_uusdc,
        ref_id, created_at). Metered only — no real charge."""
        self.db.execute(
            "INSERT INTO meter(module, operation, amount_uusdc, ref_id, created_at)"
            " VALUES(?,?,?,?,?)",
            (module, operation, amount_uusdc, ref_id, int(time.time())))

    def meter_total(self, agent_id):
        """Total metered tolls for an agent across bond stakes (1%) and
        audit exports (5c). Joins meter -> bonds on bond_id; audit exports
        are keyed by agent_id directly."""
        cur = self.db.execute(
            "SELECT COALESCE(SUM(m.amount_uusdc),0) FROM meter m"
            " WHERE m.module='bonds' AND ("
            "   m.ref_id IN (SELECT bond_id FROM bonds WHERE agent_id=?)"
            "   OR (m.operation='audit_export' AND m.ref_id=?)"
            " )", (agent_id, agent_id))
        return cur.fetchone()[0]

    # -- stake -----------------------------------------------------------
    def stake_bond(self, agent_id, amount_usdc, conditions):
        amount = to_uusdc(amount_usdc)
        if amount <= 0:
            raise BondsError("bond amount must be > 0")
        conditions = _validate_conditions(conditions)
        if self.balance_of(agent_id) < amount:
            raise BondsError("insufficient mocked balance to stake")

        bond_id = "bnd_" + secrets.token_hex(8)
        # lock funds: agent -> bond escrow (mocked)
        escrow = "bond:" + bond_id
        self._move(agent_id, escrow, amount)

        payload = {
            "type": "bond_stake",
            "bond_id": bond_id,
            "agent_id": agent_id,
            "amount_uusdc": amount,
            "conditions": conditions,
            "created_at": utcnow(),
        }
        env = sign(payload, self.key)
        self.db.execute(
            "INSERT INTO bonds(bond_id, agent_id, amount_uusdc, remaining_uusdc,"
            " conditions_json, status, stake_envelope, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (bond_id, agent_id, amount, amount, json.dumps(conditions),
             "active", json.dumps(env), payload["created_at"]))
        self.db.execute(
            "INSERT INTO bond_events(bond_id, kind, amount_uusdc, envelope_json, created_at)"
            " VALUES(?,?,?,?,?)",
            (bond_id, "stake", amount, json.dumps(env), payload["created_at"]))
        # toll: 1% of bonded value, metered (no real charge)
        self._meter("bonds", "stake_1pct", amount // 100, bond_id)
        self.db.commit()
        return {"bond_id": bond_id, "envelope": env,
                "toll_uusdc": amount // 100}

    def _get_bond(self, bond_id):
        cur = self.db.execute("SELECT * FROM bonds WHERE bond_id=?", (bond_id,))
        row = cur.fetchone()
        if not row:
            raise BondsError("unknown bond_id %r" % bond_id)
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))

    # -- slash -----------------------------------------------------------
    def _check_evidence(self, bond_id, trigger, evidence_envelope):
        """Verify the evidence envelope: valid signature, references this
        bond, attestation type/verdict matches the trigger."""
        try:
            payload = verify(evidence_envelope, self.jwks)
        except EnvelopeError as exc:
            raise BondsError("evidence envelope invalid: %s" % exc)
        if not isinstance(payload, dict):
            raise BondsError("evidence payload must be a dict")
        if payload.get("bond_id") != bond_id:
            raise BondsError("evidence does not reference bond %r" % bond_id)
        want_type, want_verdict = TRIGGER_ATTESTATION[trigger]
        if payload.get("attestation_type") != want_type:
            raise BondsError(
                "evidence attestation_type %r does not satisfy trigger %r (want %r)"
                % (payload.get("attestation_type"), trigger, want_type))
        verdict = payload.get("verdict", payload.get("outcome"))
        if verdict != want_verdict:
            raise BondsError(
                "evidence verdict %r does not satisfy trigger %r (want %r)"
                % (verdict, trigger, want_verdict))
        return payload

    def slash(self, bond_id, trigger, evidence_envelope):
        bond = self._get_bond(bond_id)
        if bond["status"] != "active":
            raise BondsError("bond %s is %s, cannot slash" % (bond_id, bond["status"]))
        if trigger not in TRIGGER_ATTESTATION:
            raise BondsError("unknown trigger %r" % trigger)
        conditions = json.loads(bond["conditions_json"])
        cond = next((c for c in conditions if c["on"] == trigger), None)
        if cond is None:
            raise BondsError("bond has no condition for trigger %r" % trigger)

        ev_payload = self._check_evidence(bond_id, trigger, evidence_envelope)

        slash_amt = (bond["remaining_uusdc"] * cond["slash_pct"]) // 100
        if slash_amt <= 0:
            raise BondsError("nothing left to slash")
        recipient = ev_payload.get("pay_to") or RECOURSE_POOL
        self._move("bond:" + bond_id, recipient, slash_amt)
        remaining = bond["remaining_uusdc"] - slash_amt
        status = "exhausted" if remaining == 0 else "active"
        self.db.execute("UPDATE bonds SET remaining_uusdc=?, status=? WHERE bond_id=?",
                        (remaining, status, bond_id))

        payload = {
            "type": "bond_slash",
            "bond_id": bond_id,
            "agent_id": bond["agent_id"],
            "trigger": trigger,
            "slash_pct": cond["slash_pct"],
            "slashed_uusdc": slash_amt,
            "recipient": recipient,
            "evidence_id": envelope_id(evidence_envelope),
            "remaining_uusdc": remaining,
            "created_at": utcnow(),
        }
        env = sign(payload, self.key)
        self.db.execute(
            "INSERT INTO bond_events(bond_id, kind, amount_uusdc, envelope_json, created_at)"
            " VALUES(?,?,?,?,?)",
            (bond_id, "slash", slash_amt, json.dumps(env), payload["created_at"]))
        self.db.commit()
        return {"envelope": env, "slashed_uusdc": slash_amt,
                "recipient": recipient, "remaining_uusdc": remaining}

    # -- release ---------------------------------------------------------
    def release(self, bond_id):
        bond = self._get_bond(bond_id)
        if bond["status"] != "active":
            raise BondsError("bond %s is %s, cannot release" % (bond_id, bond["status"]))
        amount = bond["remaining_uusdc"]
        self._move("bond:" + bond_id, bond["agent_id"], amount)
        self.db.execute("UPDATE bonds SET remaining_uusdc=0, status='released' WHERE bond_id=?",
                        (bond_id,))
        payload = {
            "type": "bond_release",
            "bond_id": bond_id,
            "agent_id": bond["agent_id"],
            "released_uusdc": amount,
            "created_at": utcnow(),
        }
        env = sign(payload, self.key)
        self.db.execute(
            "INSERT INTO bond_events(bond_id, kind, amount_uusdc, envelope_json, created_at)"
            " VALUES(?,?,?,?,?)",
            (bond_id, "release", amount, json.dumps(env), payload["created_at"]))
        self.db.commit()
        return {"envelope": env, "released_uusdc": amount}

    # -- audit trail -----------------------------------------------------
    def export_audit_trail(self, agent_id):
        """Full signed envelope chain for an agent: every stake/slash/release
        envelope on their bonds, in order. 5c metered. This is the
        underwriting data."""
        cur = self.db.execute(
            "SELECT e.envelope_json FROM bond_events e"
            " JOIN bonds b ON b.bond_id = e.bond_id"
            " WHERE b.agent_id=? ORDER BY e.id", (agent_id,))
        chain = [json.loads(r[0]) for r in cur.fetchall()]
        payload = {
            "type": "audit_trail",
            "agent_id": agent_id,
            "exported_at": utcnow(),
            "envelope_count": len(chain),
            "chain": chain,
        }
        env = sign(payload, self.key)
        self._meter("bonds", "audit_export", AUDIT_EXPORT_FEE_UUSDC, agent_id)
        self.db.commit()
        return env


def _default_db():
    return store.db_path()
