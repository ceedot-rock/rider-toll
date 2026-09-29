"""Module F — portable memory.

An agent's memory as a signed, schema-versioned envelope it can carry
anywhere: export is free and verifiable offline with the lab JWKS. Hosted
transfer moves the envelope into content-addressed blob storage and yields a
signed transfer receipt proving chain of custody (which matters the moment a
memory is evidence in a dispute — modules B/E).

Tolls (metered, no real charge):
  - export_memory: free
  - store_blob (hosted transfer): 2c per transfer, metered to from_agent

Export schema v1 payload:
  {"type": "memory_export", "agent_id", "schema_version": 1,
   "memories": [...], "weights_ref", "exported_at"}
"""

import hashlib
import json
import os
import sqlite3
import time

from . import store
from .envelope import sign, verify, canonical, envelope_id, EnvelopeError

SCHEMA_VERSION = 1
TRANSFER_FEE_UUSDC = 20_000  # 2c


class MemoryError(Exception):
    pass


def utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_blob_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "blobs")


SCHEMA = """
CREATE TABLE IF NOT EXISTS memory_transfers(
  blob_hash TEXT PRIMARY KEY,
  from_agent TEXT NOT NULL,
  to_host TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
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
"""


def _validate_memories(memories):
    if not isinstance(memories, list):
        raise MemoryError("memories must be a list")
    for i, m in enumerate(memories):
        if not isinstance(m, dict):
            raise MemoryError("memories[%d] must be a dict" % i)
        for k in m.keys():
            if not isinstance(k, str):
                raise MemoryError("memories[%d] has non-string key" % i)
    return memories


def export_memory(agent_id, memories, key, weights_ref=None):
    """Build the signed portable-memory envelope (schema v1). Free."""
    if not agent_id or not isinstance(agent_id, str):
        raise MemoryError("agent_id must be a non-empty string")
    _validate_memories(memories)
    payload = {
        "type": "memory_export",
        "agent_id": agent_id,
        "schema_version": SCHEMA_VERSION,
        "memories": memories,
        "weights_ref": weights_ref,
        "exported_at": utcnow(),
    }
    return sign(payload, key)


def verify_export(envelope, jwks):
    """Offline verification of a memory export envelope. Returns the payload
    dict; raises EnvelopeError on bad signature, MemoryError on schema
    violations."""
    payload = verify(envelope, jwks)  # raises EnvelopeError
    if payload.get("type") != "memory_export":
        raise MemoryError("not a memory_export envelope")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise MemoryError("unsupported schema_version %r (want %r)"
                          % (payload.get("schema_version"), SCHEMA_VERSION))
    if not payload.get("agent_id"):
        raise MemoryError("memory_export missing agent_id")
    _validate_memories(payload.get("memories", []))
    return payload


class MemoryStore:
    """Hosted, content-addressed blob store + signed transfer receipts."""

    def __init__(self, key, jwks, db_path=None, blob_dir=None):
        if "d" not in key or "kid" not in key:
            raise MemoryError("key must be a keypair dict with 'd' and 'kid'")
        self.key = key
        self.jwks = jwks
        self.db_path = db_path or store.db_path()
        self.blob_dir = blob_dir or _default_blob_dir()
        os.makedirs(self.blob_dir, exist_ok=True)
        self.db = sqlite3.connect(self.db_path)
        self.db.executescript(SCHEMA)
        self.db.commit()

    def _meter(self, module, operation, amount_uusdc, ref_id):
        """Platform-shared meter table. Metered only — no real charge."""
        self.db.execute(
            "INSERT INTO meter(module, operation, amount_uusdc, ref_id, created_at)"
            " VALUES(?,?,?,?,?)",
            (module, operation, amount_uusdc, ref_id, int(time.time())))

    def meter_total(self, agent_id):
        """Total metered transfer tolls for an agent (2c per transfer)."""
        cur = self.db.execute(
            "SELECT COALESCE(SUM(m.amount_uusdc),0) FROM meter m"
            " WHERE m.module='memory' AND m.operation='transfer'"
            " AND m.ref_id IN (SELECT blob_hash FROM memory_transfers"
            " WHERE from_agent=?)", (agent_id,))
        return cur.fetchone()[0]

    def store_blob(self, envelope, from_agent, to_host):
        """Store a (verified) memory-export envelope under its SHA-256 and
        return (blob_hash, transfer_receipt_envelope). 2c metered."""
        payload = verify_export(envelope, self.jwks)  # verifies sig + schema
        if payload["agent_id"] != from_agent:
            raise MemoryError("envelope agent_id %r != from_agent %r"
                              % (payload["agent_id"], from_agent))
        blob_hash = hashlib.sha256(canonical(envelope)).hexdigest()
        path = os.path.join(self.blob_dir, blob_hash)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(envelope, fh, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=True)
        receipt_payload = {
            "type": "memory_transfer_receipt",
            "blob_hash": blob_hash,
            "from_agent": from_agent,
            "to_host": to_host,
            "envelope_id": envelope_id(envelope),
            "transferred_at": utcnow(),
        }
        receipt = sign(receipt_payload, self.key)
        self.db.execute(
            "INSERT OR REPLACE INTO memory_transfers"
            "(blob_hash, from_agent, to_host, receipt_json, envelope_json, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (blob_hash, from_agent, to_host, json.dumps(receipt),
             json.dumps(envelope), receipt_payload["transferred_at"]))
        self._meter("memory", "transfer", TRANSFER_FEE_UUSDC, blob_hash)
        self.db.commit()
        return blob_hash, receipt

    def fetch_blob(self, blob_hash):
        """Retrieve a stored envelope by content hash. Raises MemoryError if
        missing or if content doesn't match the hash (tamper-evident)."""
        path = os.path.join(self.blob_dir, blob_hash)
        if not os.path.exists(path):
            raise MemoryError("unknown blob_hash %r" % blob_hash)
        with open(path, encoding="utf-8") as fh:
            envelope = json.load(fh)
        if hashlib.sha256(canonical(envelope)).hexdigest() != blob_hash:
            raise MemoryError("blob content does not match its hash (tampered)")
        return envelope

    def verify_receipt(self, receipt_envelope):
        """Verify a transfer receipt's signature; returns its payload."""
        payload = verify(receipt_envelope, self.jwks)
        if payload.get("type") != "memory_transfer_receipt":
            raise MemoryError("not a memory_transfer_receipt envelope")
        return payload
