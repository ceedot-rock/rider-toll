"""Tests for Module F — portable memory (tollkeeper.memory).

Temp DB + temp blob dir per test run. Export is free; transfers meter 2c.
"""
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.expanduser("~/workspace/rider-toll"))

from tollkeeper.envelope import (
    generate_keypair, jwks_from, sign, verify, canonical, envelope_id,
    EnvelopeError,
)
from tollkeeper.memory import (
    MemoryStore, MemoryError, export_memory, verify_export,
    SCHEMA_VERSION, TRANSFER_FEE_UUSDC,
)


def make_store():
    tmp = tempfile.mkdtemp(prefix="memory-test-")
    key = generate_keypair("test-lab-1")
    jwks = jwks_from([key])
    store = MemoryStore(key, jwks,
                        db_path=os.path.join(tmp, "t.db"),
                        blob_dir=os.path.join(tmp, "blobs"))
    return store, key, jwks, tmp


MEMORIES = [
    {"kind": "fact", "text": "principal prefers USDC on Base", "confidence": 9},
    {"kind": "episode", "text": "completed job j-123, delivered_ok=true",
     "job_id": "j-123"},
]


def test_export_and_verify():
    store, key, jwks, _ = make_store()
    env = export_memory("agent:a", MEMORIES, key, weights_ref="sha256:abc123")
    payload = verify_export(env, jwks)
    assert payload["type"] == "memory_export"
    assert payload["agent_id"] == "agent:a"
    assert payload["schema_version"] == SCHEMA_VERSION == 1
    assert payload["memories"] == MEMORIES
    assert payload["weights_ref"] == "sha256:abc123"
    assert "exported_at" in payload
    # export is free: no meter rows
    assert store.meter_total("agent:a") == 0
    print("test_export_and_verify PASS")


def test_export_refusals():
    store, key, jwks, _ = make_store()
    for args, why in [
        (("", MEMORIES), "empty agent_id"),
        (("agent:a", "not-a-list"), "memories not a list"),
        (("agent:a", ["not-a-dict"]), "memory not a dict"),
        (("agent:a", [{1: "x"}]), "non-string memory key"),
    ]:
        try:
            export_memory(args[0], args[1], key)
        except MemoryError:
            pass
        else:
            raise AssertionError("export accepted: " + why)
    print("test_export_refusals PASS")


def test_verify_export_refusals():
    store, key, jwks, _ = make_store()
    other = generate_keypair("attacker")
    env = export_memory("agent:a", MEMORIES, key)
    # tampered payload -> signature fails
    tampered = json.loads(json.dumps(env))
    tampered["payload"]["memories"] = [{"kind": "fact", "text": "lie"}]
    try:
        verify_export(tampered, jwks)
    except EnvelopeError:
        pass
    else:
        raise AssertionError("verify accepted tampered envelope")
    # wrong kid -> unknown
    env2 = export_memory("agent:a", MEMORIES, other)
    try:
        verify_export(env2, jwks)
    except EnvelopeError:
        pass
    else:
        raise AssertionError("verify accepted unknown kid")
    # bad schema version
    bad = sign({"type": "memory_export", "agent_id": "agent:a",
                "schema_version": 2, "memories": []}, key)
    try:
        verify_export(bad, jwks)
    except MemoryError:
        pass
    else:
        raise AssertionError("verify accepted schema_version 2")
    # wrong envelope type
    notmem = sign({"type": "bond_stake", "agent_id": "agent:a",
                   "schema_version": 1, "memories": []}, key)
    try:
        verify_export(notmem, jwks)
    except MemoryError:
        pass
    else:
        raise AssertionError("verify accepted non-memory envelope")
    print("test_verify_export_refusals PASS")


def test_store_blob_and_receipt():
    store, key, jwks, tmp = make_store()
    env = export_memory("agent:a", MEMORIES, key)
    blob_hash, receipt = store.store_blob(env, "agent:a", "host:fly-ewr-1")
    # content-addressed: sha256 of canonical envelope
    assert blob_hash == hashlib.sha256(canonical(env)).hexdigest()
    assert len(blob_hash) == 64
    # receipt verifies and proves chain of custody
    rp = store.verify_receipt(receipt)
    assert rp["type"] == "memory_transfer_receipt"
    assert rp["blob_hash"] == blob_hash
    assert rp["from_agent"] == "agent:a"
    assert rp["to_host"] == "host:fly-ewr-1"
    assert rp["envelope_id"] == envelope_id(env)
    assert "transferred_at" in rp
    # 2c metered to from_agent
    assert store.meter_total("agent:a") == TRANSFER_FEE_UUSDC == 20_000
    # fetch round-trips bit-identical
    assert store.fetch_blob(blob_hash) == env
    print("test_store_blob_and_receipt PASS")


def test_store_blob_idempotent():
    store, key, jwks, tmp = make_store()
    env = export_memory("agent:a", MEMORIES, key)
    h1, _ = store.store_blob(env, "agent:a", "host:x")
    h2, _ = store.store_blob(env, "agent:a", "host:x")
    assert h1 == h2  # same content -> same address
    print("test_store_blob_idempotent PASS")


def test_store_blob_refusals():
    store, key, jwks, tmp = make_store()
    env = export_memory("agent:a", MEMORIES, key)
    # from_agent must match the envelope's agent_id
    try:
        store.store_blob(env, "agent:mallory", "host:x")
    except MemoryError:
        pass
    else:
        raise AssertionError("store accepted from_agent mismatch")
    # unknown blob
    try:
        store.fetch_blob("0" * 64)
    except MemoryError:
        pass
    else:
        raise AssertionError("fetch accepted unknown hash")
    print("test_store_blob_refusals PASS")


def test_blob_tamper_evident():
    store, key, jwks, tmp = make_store()
    env = export_memory("agent:a", MEMORIES, key)
    blob_hash, _ = store.store_blob(env, "agent:a", "host:x")
    path = os.path.join(tmp, "blobs", blob_hash)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"payload": {"type": "memory_export", "agent_id": "agent:a",
                               "schema_version": 1, "memories": [{"evil": 1}]},
                   "sig": "x", "kid": "y", "alg": "ES256"}, fh)
    try:
        store.fetch_blob(blob_hash)
    except MemoryError:
        pass
    else:
        raise AssertionError("fetch accepted tampered blob")
    print("test_blob_tamper_evident PASS")


if __name__ == "__main__":
    test_export_and_verify()
    test_export_refusals()
    test_verify_export_refusals()
    test_store_blob_and_receipt()
    test_store_blob_idempotent()
    test_store_blob_refusals()
    test_blob_tamper_evident()
    print("ALL MEMORY TESTS PASS")
