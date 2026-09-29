"""Module C — delegation grants: Warrant-compatible scoped authority.

A grant is a signed envelope::

    {grantor, agent_id, scope: [actions], cap_uusdc, not_before, not_after,
     revocable: true, ...}

Tolls: 1c per issuance, 0.5c per check (metered into the shared `meter`
table, amounts in integer micro-USDC).

Fail-closed revocation: every check consults the revocation list. A caller
may pass a cached `revocation_checked_at` timestamp; if that check is older
than `revocation_max_age` (default 300 s) the grant is refused with
`revocation_check_stale`. The default path does a live lookup, which is
always fresh.

Money rule: all amounts are integer micro-USDC (uusdc). Floats are refused
by the envelope layer.
"""

import hashlib
import os
import sqlite3
import time
from decimal import Decimal

from .envelope import canonical, sign, verify, EnvelopeError

DEFAULT_DB = os.path.expanduser("~/workspace/rider-toll/tollkeeper.db")

# Tolls, in micro-USDC (1c = 10_000 uusdc, 0.5c = 5_000 uusdc).
ISSUE_TOLL_UUSDC = 10_000
CHECK_TOLL_UUSDC = 5_000

# A revocation check older than this is stale -> refuse (fail closed).
DEFAULT_REVOCATION_MAX_AGE = 300

_GRANT_FIELDS = (
    "grant_id", "grantor", "agent_id", "scope", "cap_uusdc",
    "not_before", "not_after", "revocable", "issued_at",
)


class GrantError(Exception):
    """Raised for malformed grant requests (not for check refusals)."""


def usdc_to_uusdc(amount) -> int:
    """Convert a USDC amount (int, str, or Decimal) to integer micro-USDC."""
    d = Decimal(str(amount))
    out = int((d * 1_000_000).to_integral_value())
    if out < 0:
        raise GrantError("amount must be >= 0")
    return out


def _connect(db_path=None):
    path = db_path or DEFAULT_DB
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS grants(
               grant_id TEXT PRIMARY KEY,
               envelope_json TEXT NOT NULL,
               grantor TEXT NOT NULL,
               agent_id TEXT NOT NULL,
               cap_uusdc INTEGER NOT NULL,
               not_before INTEGER NOT NULL,
               not_after INTEGER NOT NULL,
               issued_at INTEGER NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS grant_spends(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               grant_id TEXT NOT NULL,
               amount_uusdc INTEGER NOT NULL,
               action TEXT NOT NULL,
               created_at INTEGER NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS revocations(
               grant_id TEXT PRIMARY KEY,
               envelope_json TEXT NOT NULL,
               revoked_at INTEGER NOT NULL,
               revoker TEXT NOT NULL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS meter(
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               module TEXT NOT NULL,
               operation TEXT NOT NULL,
               amount_uusdc INTEGER NOT NULL,
               ref_id TEXT NOT NULL,
               created_at INTEGER NOT NULL)"""
    )
    conn.commit()
    return conn


def _meter(conn, module, operation, amount_uusdc, ref_id, now):
    conn.execute(
        "INSERT INTO meter(module, operation, amount_uusdc, ref_id, created_at)"
        " VALUES (?,?,?,?,?)",
        (module, operation, amount_uusdc, ref_id, now),
    )


def _grant_id_for(payload_core: dict) -> str:
    digest = hashlib.sha256(canonical(payload_core)).hexdigest()
    return "gr_" + digest[:16]


def issue_grant(*, grantor, agent_id, scope, cap_uusdc, not_before,
                not_after, key, db_path=None, issued_at=None,
                revocable=True):
    """Issue a scoped delegation grant as a signed envelope.

    Toll: 1c, metered. Returns the envelope dict.
    """
    now = issued_at if issued_at is not None else int(time.time())
    if not grantor or not isinstance(grantor, str):
        raise GrantError("grantor must be a non-empty string")
    if not agent_id or not isinstance(agent_id, str):
        raise GrantError("agent_id must be a non-empty string")
    if not scope or not isinstance(scope, (list, tuple)) or not all(
        isinstance(a, str) and a for a in scope
    ):
        raise GrantError("scope must be a non-empty list of action strings")
    if not isinstance(cap_uusdc, int) or isinstance(cap_uusdc, bool) \
            or cap_uusdc <= 0:
        raise GrantError("cap_uusdc must be a positive integer (micro-USDC)")
    if not isinstance(not_before, int) or not isinstance(not_after, int):
        raise GrantError("not_before/not_after must be integer epoch seconds")
    if not_after <= not_before:
        raise GrantError("not_after must be after not_before")

    core = {
        "grantor": grantor,
        "agent_id": agent_id,
        "scope": list(scope),
        "cap_uusdc": cap_uusdc,
        "not_before": not_before,
        "not_after": not_after,
        "issued_at": now,
    }
    payload = {
        "type": "delegation-grant",
        "version": 1,
        "grant_id": _grant_id_for(core),
        "revocable": bool(revocable),
        **core,
    }
    envelope = sign(payload, key)

    import json
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO grants(grant_id, envelope_json, grantor, agent_id,"
            " cap_uusdc, not_before, not_after, issued_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (payload["grant_id"], json.dumps(envelope), grantor, agent_id,
             cap_uusdc, not_before, not_after, now),
        )
        _meter(conn, "grants", "issue", ISSUE_TOLL_UUSDC,
               payload["grant_id"], now)
        conn.commit()
    finally:
        conn.close()
    return envelope


def revoke_grant(grant_id, *, revoker, key, db_path=None, revoked_at=None):
    """Revoke a grant. The revocation is itself a signed envelope.

    No toll. Returns the revocation envelope.
    """
    now = revoked_at if revoked_at is not None else int(time.time())
    if not grant_id or not isinstance(grant_id, str):
        raise GrantError("grant_id must be a non-empty string")
    if not revoker or not isinstance(revoker, str):
        raise GrantError("revoker must be a non-empty string")
    payload = {
        "type": "grant-revocation",
        "version": 1,
        "grant_id": grant_id,
        "revoker": revoker,
        "revoked_at": now,
    }
    envelope = sign(payload, key)
    import json
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO revocations(grant_id, envelope_json,"
            " revoked_at, revoker) VALUES (?,?,?,?)",
            (grant_id, json.dumps(envelope), now, revoker),
        )
        conn.commit()
    finally:
        conn.close()
    return envelope


def record_spend(grant_id, amount_uusdc, action, db_path=None):
    """Log actual spend against a grant. Returns total spent (uusdc)."""
    if not isinstance(amount_uusdc, int) or isinstance(amount_uusdc, bool) \
            or amount_uusdc < 0:
        raise GrantError("amount_uusdc must be a non-negative integer")
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO grant_spends(grant_id, amount_uusdc, action,"
            " created_at) VALUES (?,?,?,?)",
            (grant_id, amount_uusdc, action, int(time.time())),
        )
        conn.commit()
        return spent_total(grant_id, db_path=db_path)
    finally:
        conn.close()


def spent_total(grant_id, db_path=None):
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_uusdc),0) FROM grant_spends"
            " WHERE grant_id=?",
            (grant_id,),
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


def get_grant(grant_id, db_path=None):
    """Return the stored grant envelope dict, or None."""
    import json
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT envelope_json FROM grants WHERE grant_id=?",
            (grant_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None
    finally:
        conn.close()


def is_revoked(grant_id, db_path=None) -> bool:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM revocations WHERE grant_id=?", (grant_id,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def check_grant(grant_envelope, action, amount_uusdc, *, jwks, db_path=None,
                revocation_checked_at=None,
                revocation_max_age=DEFAULT_REVOCATION_MAX_AGE, now=None):
    """Check whether a grant authorizes (action, amount_uusdc).

    Returns (allowed: bool, reason: str). Reasons: ok | bad_signature |
    malformed_grant | not_yet_valid | expired | revocation_check_stale |
    revoked | scope_miss | cap_exceeded.

    Toll: 0.5c per check, metered on every call.
    """
    now = now if now is not None else int(time.time())
    ref = "unknown"
    try:
        ref = grant_envelope.get("payload", {}).get("grant_id", "unknown")
    except Exception:
        pass

    def decided(allowed, reason):
        conn = _connect(db_path)
        try:
            _meter(conn, "grants", "check", CHECK_TOLL_UUSDC, ref, now)
            conn.commit()
        finally:
            conn.close()
        return allowed, reason

    try:
        payload = verify(grant_envelope, jwks)
    except EnvelopeError:
        return decided(False, "bad_signature")

    if payload.get("type") != "delegation-grant" or not all(
        f in payload for f in _GRANT_FIELDS
    ):
        return decided(False, "malformed_grant")

    if not isinstance(amount_uusdc, int) or isinstance(amount_uusdc, bool) \
            or amount_uusdc < 0:
        return decided(False, "malformed_grant")

    if now < payload["not_before"]:
        return decided(False, "not_yet_valid")
    if now > payload["not_after"]:
        return decided(False, "expired")

    # Fail closed on revocation freshness.
    checked_at = revocation_checked_at if revocation_checked_at is not None \
        else now
    if now - checked_at > revocation_max_age:
        return decided(False, "revocation_check_stale")
    if is_revoked(payload["grant_id"], db_path=db_path):
        return decided(False, "revoked")

    if action not in payload["scope"]:
        return decided(False, "scope_miss")

    spent = spent_total(payload["grant_id"], db_path=db_path)
    if spent + amount_uusdc > payload["cap_uusdc"]:
        return decided(False, "cap_exceeded")

    return decided(True, "ok")
