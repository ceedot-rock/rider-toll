#!/usr/bin/env python3
"""tollkeeper.identity — Module A, part 1: credential verification.

`verify_credential(jwt)` checks a Rider ES256 JWT (15-min, clearance L0–L4)
against a JWKS and returns {agent_id, clearance, expires, valid}.

Accepted claim shape (mirrors the live Rider issuer):
    header:  {"alg": "ES256", "kid": ..., "typ": "JWT"}
    payload: {"iss": "agentrider.dev", "agent_id": "…", "clearance": "L2",
              "exp": …, "iat": …}
`agent_id` may also arrive as `sub`. Clearance defaults to L0 when absent
but must be one of L0..L4 when present.

Toll: 0.5¢ per verification query — metered here (query counts in
`verify_queries`), NOT charged. Charging is the billing module's job.

SPEC GAP FILLED: the live issuer is the authority for real credentials.
For local/dev use, pass jwks=lab_jwks() and expected_iss="tollkeeper.dev"
(or your own issuer); minting helper `mint_test_credential` is provided.
"""

import time

from . import store
from .envelope import (EnvelopeError, b64u_decode, lab_jwks,
                       verify_raw_signature)

CLEARANCES = ("L0", "L1", "L2", "L3", "L4")
IAT_LEEWAY_SEC = 60
DEFAULT_ISSUERS = ("agentrider.dev", "tollkeeper.dev")


def _b64u_json(seg):
    import json
    return json.loads(b64u_decode(seg).decode("utf-8"))


def verify_credential(token, jwks=None, expected_iss=DEFAULT_ISSUERS,
                     now=None, meter=True):
    """Verify a Rider ES256 JWT.

    Returns {"agent_id", "clearance", "expires", "valid", "reason"} —
    valid is False (never raises) on any failure; reason names it.
    """
    now = int(now if now is not None else time.time())
    jwks = lab_jwks() if jwks is None else jwks

    def refuse(reason, agent_id=None):
        if meter:
            _meter(agent_id, False, reason)
        return {"agent_id": agent_id, "clearance": None, "expires": None,
                "valid": False, "reason": reason}

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return refuse("malformed token")
        header = _b64u_json(parts[0])
        payload = _b64u_json(parts[1])
        sig_raw = b64u_decode(parts[2])
    except EnvelopeError as exc:
        return refuse("decode error: %s" % exc)
    except Exception as exc:
        return refuse("decode error: %s" % exc)

    if header.get("alg") != "ES256":
        return refuse("unexpected alg %r" % header.get("alg"))

    kid = header.get("kid")
    jwk = None
    for k in jwks.get("keys", []):
        if k.get("kid") == kid and k.get("kty") == "EC" and k.get("crv") == "P-256":
            jwk = k
            break
    if jwk is None:
        return refuse("unknown kid %r" % kid)

    if len(sig_raw) != 64:
        return refuse("bad signature length")
    try:
        x = int.from_bytes(b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(b64u_decode(jwk["y"]), "big")
    except Exception:
        return refuse("bad JWK coordinates")
    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    msg = ("%s.%s" % (parts[0], parts[1])).encode("ascii")
    if not verify_raw_signature(x, y, msg, r, s):
        return refuse("signature invalid")

    iss = payload.get("iss")
    if expected_iss is not None and iss not in expected_iss:
        return refuse("unexpected iss %r" % iss)

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or exp <= now:
        return refuse("token expired")
    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + IAT_LEEWAY_SEC:
        return refuse("iat in the future")

    agent_id = payload.get("agent_id") or payload.get("sub")
    if not agent_id or not isinstance(agent_id, str):
        return refuse("no agent_id/sub claim")

    clearance = payload.get("clearance", "L0")
    if clearance not in CLEARANCES:
        return refuse("bad clearance %r" % clearance)

    if meter:
        _meter(agent_id, True, None)
    return {"agent_id": agent_id, "clearance": clearance,
            "expires": int(exp), "valid": True, "reason": None}


def _meter(agent_id, valid, reason):
    con = store.connect()
    try:
        con.execute(
            "INSERT INTO verify_queries(agent_id, valid, reason, created_at)"
            " VALUES (?,?,?,?)",
            (agent_id, 1 if valid else 0, reason, store.now()))
        con.commit()
    finally:
        con.close()


def query_count(agent_id=None):
    """Toll accounting: how many verification queries have been metered."""
    con = store.connect()
    try:
        if agent_id:
            row = con.execute(
                "SELECT COUNT(*) c FROM verify_queries WHERE agent_id=?",
                (agent_id,)).fetchone()
        else:
            row = con.execute("SELECT COUNT(*) c FROM verify_queries").fetchone()
        return row["c"]
    finally:
        con.close()


def mint_test_credential(agent_id, clearance="L0", key=None,
                         iss="tollkeeper.dev", ttl=900, now=None):
    """Mint a test Rider-shaped JWT. TEST ONLY — signed by the dev lab key
    (or the given keypair dict), never a real issuer key."""
    import json
    from .envelope import generate_keypair
    from . import envelope as _env
    now = int(now if now is not None else time.time())
    key = key or _env.dev_lab_keypair()
    header = {"alg": "ES256", "typ": "JWT", "kid": key["kid"]}
    payload = {"iss": iss, "agent_id": agent_id, "clearance": clearance,
               "exp": now + ttl, "iat": now}
    h_b64 = _env._b64u_encode(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    p_b64 = _env._b64u_encode(json.dumps(
        payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    msg = ("%s.%s" % (h_b64, p_b64)).encode("ascii")
    r, s = _env._es256_sign(key["d"], msg)
    sig = _env._b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return "%s.%s.%s" % (h_b64, p_b64, sig)
