"""Module D — verification oracle: CuNi/Chamber exactness as a service.

Submit {artifact, claim} -> run the exactness check -> return a sealed
attestation envelope::

    {attestation_id, artifact_hash, claim, result: pass|refuse, seats,
     policy_ref, checked_at, oracle, ...}

Toll: 10c per check (mirrors the x402 check price), metered into the shared
`meter` table, amounts in integer micro-USDC.

The exactness function is PLUGGABLE. Interface (ExactnessFn)::

    fn(artifact: dict, claim: dict) -> {
        "result": "pass" | "refuse",   # machine-readable, for module E
        "seats": [str, ...],           # seats the check ran on
        "detail": {...},               # human/machine diagnostic payload
    }

The default is a stub that byte-compares the claimed stdout against a
simulated stdout on two seats (same-stdout-or-refuse). The real CuNi gate
plugs in via `set_exactness_fn()` or the per-call `exactness_fn=` kwarg;
it must honor the interface above.

The attestation schema is directly consumable by module E (bonding/slash):
`result` and `policy_ref` are machine-readable, and attestations are
queryable by `artifact_hash`.
"""

import hashlib
import os
import sqlite3
import time

from .envelope import canonical, sign, verify, EnvelopeError

DEFAULT_DB = os.path.expanduser("~/workspace/rider-toll/tollkeeper.db")

# 10c per check, in micro-USDC.
CHECK_TOLL_UUSDC = 100_000

# Machine-readable policy reference consumed by module E slash conditions.
POLICY_REF = "tollkeeper.oracle.exactness/v1"
ORACLE_ID = "tollkeeper-oracle/v1"

# Seats the default stub simulates.
DEFAULT_SEATS = ("seat-a", "seat-b")


class OracleError(Exception):
    """Raised for malformed check requests (not for refuse results)."""


# ---------------------------------------------------------------------------
# pluggable exactness
# ---------------------------------------------------------------------------
_registered_fn = None


def set_exactness_fn(fn):
    """Plug in the real exactness gate (e.g. the CuNi gate).

    fn must accept (artifact: dict, claim: dict) and return
    {"result": "pass"|"refuse", "seats": [...], "detail": {...}}.
    Pass None to restore the default stub.
    """
    global _registered_fn
    if fn is not None and not callable(fn):
        raise OracleError("exactness_fn must be callable")
    _registered_fn = fn


def _active_fn(exactness_fn):
    return exactness_fn or _registered_fn or default_exactness


def _simulate_seat_stdout(artifact, seat) -> str:
    """Deterministic simulated stdout for a seat (stub only).

    Every seat runs the same artifact, so every seat must produce the same
    stdout — the seat id is deliberately NOT part of the hash. (The real
    CuNi gate gets genuine cross-seat divergence from running different
    language seats.)
    """
    return hashlib.sha256(canonical({"artifact": artifact})).hexdigest()


def default_exactness(artifact, claim):
    """Stub exactness: byte-compare claimed stdout vs simulated stdout on
    two seats. Pass only if every seat's stdout matches the claim
    (same-stdout-or-refuse)."""
    if not isinstance(artifact, dict):
        raise OracleError("artifact must be a dict")
    if not isinstance(claim, dict) or not isinstance(
        claim.get("stdout"), str
    ):
        raise OracleError("claim must be a dict with a string 'stdout'")
    per_seat = {s: _simulate_seat_stdout(artifact, s) for s in DEFAULT_SEATS}
    seats_agree = len(set(per_seat.values())) == 1
    match = seats_agree and all(
        out == claim["stdout"] for out in per_seat.values()
    )
    return {
        "result": "pass" if match else "refuse",
        "seats": list(DEFAULT_SEATS),
        "detail": {
            "per_seat_stdout": per_seat,
            "claim_stdout": claim["stdout"],
            "seats_agree": seats_agree,
        },
    }


def _validate_check_result(res):
    if not isinstance(res, dict):
        raise OracleError("exactness_fn must return a dict")
    if res.get("result") not in ("pass", "refuse"):
        raise OracleError("exactness_fn result must be 'pass' or 'refuse'")
    if not isinstance(res.get("seats"), list) or not res["seats"]:
        raise OracleError("exactness_fn must return a non-empty seats list")
    if "detail" not in res:
        raise OracleError("exactness_fn must return a detail payload")
    return res


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------
def _connect(db_path=None):
    path = db_path or DEFAULT_DB
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS attestations(
               attestation_id TEXT PRIMARY KEY,
               artifact_hash TEXT NOT NULL,
               envelope_json TEXT NOT NULL,
               result TEXT NOT NULL,
               checked_at INTEGER NOT NULL)"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_att_artifact"
                 " ON attestations(artifact_hash)")
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


def artifact_hash_of(artifact: dict) -> str:
    """Content hash identifying the artifact (query key)."""
    return hashlib.sha256(canonical(artifact)).hexdigest()


def _attestation_id_for(core: dict) -> str:
    return "at_" + hashlib.sha256(canonical(core)).hexdigest()[:16]


def submit_check(artifact, claim, *, key, db_path=None, exactness_fn=None,
                 now=None):
    """Run the exactness check and return a sealed attestation envelope.

    Toll: 10c, metered. `result` is "pass" or "refuse" — a refuse is a
    successful check with a negative outcome, not an error.
    """
    now = now if now is not None else int(time.time())
    fn = _active_fn(exactness_fn)
    res = _validate_check_result(fn(artifact, claim))

    ahash = artifact_hash_of(artifact)
    core = {
        "artifact_hash": ahash,
        "claim": claim,
        "result": res["result"],
        "seats": res["seats"],
        "checked_at": now,
    }
    payload = {
        "type": "exactness-attestation",
        "version": 1,
        "attestation_id": _attestation_id_for(core),
        "policy_ref": POLICY_REF,
        "oracle": ORACLE_ID,
        **core,
    }
    envelope = sign(payload, key)

    import json
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO attestations(attestation_id, artifact_hash,"
            " envelope_json, result, checked_at) VALUES (?,?,?,?,?)",
            (payload["attestation_id"], ahash, json.dumps(envelope),
             res["result"], now),
        )
        conn.execute(
            "INSERT INTO meter(module, operation, amount_uusdc, ref_id,"
            " created_at) VALUES (?,?,?,?,?)",
            ("oracle", "check", CHECK_TOLL_UUSDC,
             payload["attestation_id"], now),
        )
        conn.commit()
    finally:
        conn.close()
    return envelope


def get_attestations(artifact_hash, *, jwks, db_path=None):
    """All verified attestation payloads for an artifact hash, oldest first.

    Each payload is signature-verified; corrupt rows raise EnvelopeError.
    """
    import json
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT envelope_json FROM attestations WHERE artifact_hash=?"
            " ORDER BY checked_at ASC",
            (artifact_hash,),
        ).fetchall()
    finally:
        conn.close()
    return [verify(json.loads(r[0]), jwks) for r in rows]
