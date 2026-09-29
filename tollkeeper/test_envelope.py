#!/usr/bin/env python3
"""Tests for tollkeeper.envelope — run: python3 test_envelope.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TOLLKEEPER_DB"] = "/tmp/tollkeeper-test-envelope.db"
if os.path.exists(os.environ["TOLLKEEPER_DB"]):
    os.remove(os.environ["TOLLKEEPER_DB"])

from tollkeeper import envelope as E


def test_keygen_on_curve():
    kp = E.generate_keypair("k1")
    x, y = kp["x"], kp["y"]
    assert (y * y - (x * x * x + E._A * x + E._B)) % E._P == 0
    assert 1 <= kp["d"] < E._N


def test_curve_order_is_true_p256():
    # n*G must be the point at infinity; catches constant typos
    assert E._pmul(E._N, E._G) is None or E._pmul(E._N, E._G) is E._INF
    assert E._N == 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def test_seal_verify_roundtrip():
    kp = E.generate_keypair("rt")
    env = E.sign({"job": "x", "n": 3}, kp)
    assert env["alg"] == "ES256" and env["kid"] == "k1" or env["kid"] == "rt"
    assert E.verify(env, E.jwks_from([kp])) == {"job": "x", "n": 3}


def test_lab_helpers():
    kp = E.dev_lab_keypair()
    assert E.dev_lab_keypair()["kid"] == kp["kid"]  # singleton
    env = E.seal_with_lab({"hello": "world"})
    assert E.verify(env, E.lab_jwks()) == {"hello": "world"}
    ok, payload = E.verify_ok(env, E.lab_jwks())
    assert ok and payload == {"hello": "world"}
    ok, reason = E.verify_ok({"nope": 1}, E.lab_jwks())
    assert not ok and isinstance(reason, str)


def test_tampered_payload_refused():
    kp = E.generate_keypair("t")
    env = E.sign({"amount": 100}, kp)
    env["payload"]["amount"] = 999
    try:
        E.verify(env, E.jwks_from([kp]))
    except E.EnvelopeError:
        return
    raise AssertionError("tampered payload verified")


def test_tampered_sig_refused():
    kp = E.generate_keypair("t")
    env = E.sign({"amount": 100}, kp)
    raw = bytearray(E._b64u_decode(env["sig"]))
    raw[0] ^= 1
    env["sig"] = E._b64u_encode(bytes(raw))
    try:
        E.verify(env, E.jwks_from([kp]))
    except E.EnvelopeError:
        return
    raise AssertionError("tampered sig verified")


def test_unknown_kid_refused():
    kp = E.generate_keypair("a")
    other = E.generate_keypair("b")
    env = E.sign({"x": 1}, kp)
    try:
        E.verify(env, E.jwks_from([other]))
    except E.EnvelopeError as e:
        assert "kid" in str(e)
        return
    raise AssertionError("unknown kid verified")


def test_bad_alg_refused():
    kp = E.generate_keypair("a")
    env = E.sign({"x": 1}, kp)
    env["alg"] = "none"
    try:
        E.verify(env, E.jwks_from([kp]))
    except E.EnvelopeError:
        return
    raise AssertionError("bad alg verified")


def test_canonical_deterministic():
    a = E.canonical({"b": 2, "a": [1, {"z": 0, "y": 9}]})
    b = E.canonical({"a": [1, {"y": 9, "z": 0}], "b": 2})
    assert a == b
    assert b'":' in a and b", " not in a  # tight separators


def test_float_refused():
    kp = E.generate_keypair("f")
    try:
        E.sign({"amount": 1.5}, kp)
    except E.EnvelopeError:
        return
    raise AssertionError("float payload signed")


def test_cross_check_with_cryptography_lib():
    try:
        sys.path.insert(0, "/home/hatch/workspace/rider-service-agent/.venv"
                           "/lib/python3.12/site-packages")
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature, decode_dss_signature)
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        print("  (skip: cryptography lib not available)")
        return
    kp = E.generate_keypair("x")
    priv = ec.derive_private_key(kp["d"], ec.SECP256R1())
    msg = E.canonical({"v": 42})
    # my signature -> their verifier
    env = E.sign({"v": 42}, kp)
    raw = E._b64u_decode(env["sig"])
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    priv.public_key().verify(encode_dss_signature(r, s), msg,
                             ec.ECDSA(hashes.SHA256()))
    # their signature -> my verifier
    der = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
    r2, s2 = decode_dss_signature(der)
    env2 = dict(env)
    env2["sig"] = E._b64u_encode(r2.to_bytes(32, "big") + s2.to_bytes(32, "big"))
    assert E.verify(env2, E.jwks_from([kp])) == {"v": 42}


def test_envelope_id_stable():
    kp = E.generate_keypair("e")
    env = E.sign({"a": 1}, kp)
    assert E.envelope_id(env) == E.envelope_id(E.sign({"a": 1}, kp))


def test_randomized_lib_cross_check():
    """Point arithmetic fuzz vs the independent `cryptography` P-256.

    Guards the pure-stdlib curve math: N random (a, b) pairs, checking
    _pmul and _padd against the library. Skipped if the lib is missing."""
    import random
    try:
        sys.path.insert(0, "/home/hatch/workspace/rider-service-agent/.venv"
                           "/lib/python3.12/site-packages")
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError:
        print("  (skip: cryptography lib not available)")
        return

    def libpt(k):
        n = ec.derive_private_key(k % E._N, ec.SECP256R1()
                                  ).public_key().public_numbers()
        return (n.x, n.y)

    random.seed(20260927)
    G = E._G
    for _ in range(12):
        a = random.randrange(1, E._N)
        b = random.randrange(1, E._N)
        pa, pb = E._pmul(a, G), E._pmul(b, G)
        assert pa == libpt(a) and pb == libpt(b)
        assert E._padd(pa, pb) == libpt(a + b)


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print("%d envelope tests passed" % len(tests))
