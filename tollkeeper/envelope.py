"""Signed envelope: the one attestation format for the whole toll-keeper platform.

Format: canonical JSON -> SHA-256 -> ES256 (ECDSA P-256) sign (lab key)
  envelope = {"payload": {...}, "sig": base64url(r||s), "kid": str, "alg": "ES256"}

Canonical JSON: json.dumps(payload, sort_keys=True, separators=(",", ":"),
ensure_ascii=True).encode("utf-8"). Money is NEVER float inside a payload:
amounts are integer micro-USDC ("uusdc", 1 USDC = 1_000_000 uusdc).

Pure-stdlib P-256 ECDSA with RFC 6979 deterministic nonces (mirrors the
vendored-crypto approach of the x402 server's ethsig.py). Test/dev keys only.

Public API:
    generate_keypair(kid="dev-1") -> {"kid","d","x","y"}
    jwk_public(keypair) -> JWK dict
    jwks_from(keypairs) -> {kid: jwk}
    sign(payload_dict, key) -> envelope dict
    verify(envelope, jwks) -> payload dict (raises EnvelopeError)
    canonical(payload_dict) -> bytes
"""

import base64
import hashlib
import hmac
import json
import secrets

ALG = "ES256"

# ---------------------------------------------------------------------------
# secp256r1 (NIST P-256) domain parameters
# ---------------------------------------------------------------------------
_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = (_P - 3) % _P
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (_GX, _GY)
_INF = None  # point at infinity


class EnvelopeError(Exception):
    """Raised when an envelope is malformed, has an unknown kid, or fails
    signature verification."""


# ---------------------------------------------------------------------------
# field / curve arithmetic
# ---------------------------------------------------------------------------
def _inv(a, m):
    return pow(a % m, m - 2, m)


def _padd(p1, p2):
    if p1 is _INF:
        return p2
    if p2 is _INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return _INF
        # doubling
        lam = (3 * x1 * x1 + _A) * _inv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pmul(k, point):
    k = k % _N
    result = _INF
    addend = point
    while k:
        if k & 1:
            result = _padd(result, addend)
        addend = _padd(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# RFC 6979 deterministic nonce (HMAC-SHA256)
# ---------------------------------------------------------------------------
def _rfc6979(priv, h1):
    x = priv.to_bytes(32, "big")
    h = h1[:32].rjust(32, b"\x00")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        t = b""
        while len(t) < 32:
            v = hmac.new(k, v, hashlib.sha256).digest()
            t += v
        cand = int.from_bytes(t[:32], "big")
        if 1 <= cand < _N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _b64u_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int_to_b64u(n, length=32):
    return _b64u_encode(n.to_bytes(length, "big"))


# ---------------------------------------------------------------------------
# canonical JSON
# ---------------------------------------------------------------------------
def canonical(payload):
    """Deterministic bytes for a payload dict. Raises EnvelopeError on
    non-JSON-safe content (floats are refused: use integer uusdc)."""
    _reject_floats(payload)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _reject_floats(obj):
    if isinstance(obj, float):
        raise EnvelopeError("floats forbidden in envelope payloads; use integer uusdc")
    if isinstance(obj, dict):
        for v in obj.values():
            _reject_floats(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_floats(v)


def envelope_id(envelope):
    """Content id of a signed envelope (sha256 of its canonical form)."""
    raw = json.dumps(
        {"payload": envelope["payload"], "sig": envelope["sig"],
         "kid": envelope["kid"], "alg": envelope["alg"]},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------
def generate_keypair(kid="dev-1"):
    """TEST/DEV ONLY keypair. Never use for production signing."""
    d = secrets.randbelow(_N - 1) + 1
    x, y = _pmul(d, _G)
    return {"kid": kid, "d": d, "x": x, "y": y}


def jwk_public(keypair):
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64u(keypair["x"]),
        "y": _int_to_b64u(keypair["y"]),
        "kid": keypair["kid"],
    }


def jwks_from(keypairs):
    """{kid: jwk} lookup table."""
    return {kp["kid"]: jwk_public(kp) for kp in keypairs}


# ---------------------------------------------------------------------------
# sign / verify
# ---------------------------------------------------------------------------
def _es256_sign(priv_d, msg):
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    k = _rfc6979(priv_d, hashlib.sha256(msg).digest())
    r_pt = _pmul(k, _G)
    r = r_pt[0] % _N
    if r == 0:
        raise EnvelopeError("signing failure (r=0)")
    s = (_inv(k, _N) * (e + r * priv_d)) % _N
    if s == 0:
        raise EnvelopeError("signing failure (s=0)")
    if s > _N // 2:  # low-S normalization
        s = _N - s
    return r, s


def _es256_verify(pub_xy, msg, r, s):
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = _inv(s, _N)
    u1 = (e * w) % _N
    u2 = (r * w) % _N
    x = _padd(_pmul(u1, _G), _pmul(u2, pub_xy))
    if x is _INF:
        return False
    return (x[0] % _N) == r


def sign(payload_dict, key):
    """Sign a payload dict with a keypair dict (must carry 'd' and 'kid').

    Returns the envelope {"payload","sig","kid","alg"}.
    """
    if not isinstance(payload_dict, dict):
        raise EnvelopeError("payload must be a dict")
    if "d" not in key or "kid" not in key:
        raise EnvelopeError("key must carry 'd' and 'kid'")
    msg = canonical(payload_dict)
    r, s = _es256_sign(key["d"], msg)
    sig = _b64u_encode(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return {"payload": payload_dict, "sig": sig, "kid": key["kid"], "alg": ALG}


def _lookup_jwk(jwks, kid):
    if isinstance(jwks, dict) and "keys" in jwks:
        for jwk in jwks["keys"]:
            if jwk.get("kid") == kid:
                return jwk
        return None
    if isinstance(jwks, dict):
        return jwks.get(kid)
    return None


def verify(envelope, jwks):
    """Verify an envelope against a JWKS. Returns the payload dict.

    Raises EnvelopeError on any failure: malformed envelope, unknown kid,
    wrong alg, bad JWK, or signature mismatch.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope must be a dict")
    for field in ("payload", "sig", "kid", "alg"):
        if field not in envelope:
            raise EnvelopeError("envelope missing field: %s" % field)
    if envelope["alg"] != ALG:
        raise EnvelopeError("unsupported alg: %r" % envelope["alg"])
    jwk = _lookup_jwk(jwks, envelope["kid"])
    if jwk is None:
        raise EnvelopeError("unknown kid: %r" % envelope["kid"])
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise EnvelopeError("JWK is not a P-256 EC key")
    try:
        x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
        raw = _b64u_decode(envelope["sig"])
    except Exception as exc:
        raise EnvelopeError("base64 decode failed: %s" % exc)
    if len(raw) != 64:
        raise EnvelopeError("bad signature length")
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    msg = canonical(envelope["payload"])
    if not _es256_verify((x, y), msg, r, s):
        raise EnvelopeError("signature verification failed")
    return envelope["payload"]


# ---------------------------------------------------------------------------
# Dev lab key + lab JWKS — TEST ONLY.
#
# The platform verifies everything against "the lab JWKS". In production that
# JWKS is published by the lab and the signing key lives in a vault. For this
# local build the lab key is a throwaway P-256 keypair generated in-memory,
# once per process, never persisted and never a real key.
# ---------------------------------------------------------------------------
_DEV_LAB_KEYPAIR = None


def dev_lab_keypair():
    """Return the throwaway dev lab keypair (dict with kid/d/x/y).

    TEST ONLY — in-memory, per-process, never persisted, never real."""
    global _DEV_LAB_KEYPAIR
    if _DEV_LAB_KEYPAIR is None:
        _DEV_LAB_KEYPAIR = generate_keypair(kid="dev-lab-1")
    return _DEV_LAB_KEYPAIR


def lab_jwks():
    """The lab JWKS for this build: {"keys": [dev lab public JWK]}."""
    return {"keys": [jwk_public(dev_lab_keypair())]}


def seal_with_lab(payload_dict):
    """Sign a payload with the dev lab key. TEST ONLY."""
    return sign(payload_dict, dev_lab_keypair())


def verify_ok(envelope, jwks):
    """Non-raising verify. Returns (True, payload) or (False, reason)."""
    try:
        return True, verify(envelope, jwks)
    except EnvelopeError as exc:
        return False, str(exc)


def b64u_decode(s):
    """Decode unpadded base64url to bytes. Raises EnvelopeError on bad input."""
    try:
        return _b64u_decode(s)
    except Exception as exc:
        raise EnvelopeError("base64url decode failed: %s" % exc)


def verify_raw_signature(x, y, msg, r, s):
    """Verify a raw (r, s) ES256 signature over msg with P-256 point (x, y).

    Used for Rider JWTs, whose signature is raw r||s over the ASCII
    'header.payload' — not an envelope. Returns bool, never raises.
    """
    return _es256_verify((x, y), msg, r, s)
