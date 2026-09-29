#!/usr/bin/env python3
"""tollkeeper.store — one file-local SQLite database for the whole platform.

DB path: ~/workspace/rider-toll/tollkeeper.db by default, overridable with
the TOLLKEEPER_DB environment variable (tests use a temp file).

Schema is created idempotently; every module owns its tables.
"""

import json
import os
import sqlite3
import time

DEFAULT_DB = os.path.expanduser("~/workspace/rider-toll/tollkeeper.db")


def db_path():
    return os.environ.get("TOLLKEEPER_DB", DEFAULT_DB)


def now():
    return int(time.time())


def connect(path=None):
    con = sqlite3.connect(path or db_path())
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    _init(con)
    return con


def _init(con):
    # --- module A: identity metering -------------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS verify_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT,
        valid INTEGER NOT NULL,
        reason TEXT,
        created_at INTEGER NOT NULL
    )""")
    # --- module A: reputation receipts ------------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL UNIQUE,
        agent_id TEXT NOT NULL,
        payer TEXT NOT NULL,
        tx_hash TEXT NOT NULL,
        paid_amount INTEGER NOT NULL,
        delivered_ok INTEGER NOT NULL,
        latency_ms INTEGER NOT NULL,
        note TEXT NOT NULL DEFAULT '',
        envelope TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    con.execute("""CREATE INDEX IF NOT EXISTS idx_receipts_agent
                   ON receipts(agent_id)""")
    # --- module B: mocked settlement ledger --------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS transfers (
        tx_hash TEXT PRIMARY KEY,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        amount INTEGER NOT NULL,
        memo TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    )""")
    # --- module B: budgets ---------------------------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS budgets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        cap INTEGER NOT NULL,
        spent INTEGER NOT NULL DEFAULT 0,
        window TEXT NOT NULL,
        window_start INTEGER NOT NULL,
        categories TEXT NOT NULL DEFAULT '[]',
        active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
    )""")
    con.execute("""CREATE INDEX IF NOT EXISTS idx_budgets_agent
                   ON budgets(agent_id, active)""")
    # --- module B: escrow ----------------------------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS escrows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT NOT NULL UNIQUE,
        payer TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        amount INTEGER NOT NULL,
        fee INTEGER NOT NULL,
        job_spec_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'locked',
        lock_tx TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        timeout_at INTEGER NOT NULL,
        settled_at INTEGER
    )""")
    # --- module B: disputes --------------------------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS disputes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        escrow_id INTEGER NOT NULL REFERENCES escrows(id),
        opener TEXT NOT NULL,
        evidence TEXT NOT NULL DEFAULT '',
        response TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        fee INTEGER NOT NULL,
        fee_tx TEXT NOT NULL,
        opener_won INTEGER,
        resolution TEXT,
        created_at INTEGER NOT NULL,
        resolved_at INTEGER
    )""")
    # --- module B: payment receipts ------------------------------------------
    con.execute("""CREATE TABLE IF NOT EXISTS payment_receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tx_hash TEXT NOT NULL UNIQUE,
        envelope TEXT NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    con.commit()


def dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def loads(s):
    return json.loads(s) if s else None
