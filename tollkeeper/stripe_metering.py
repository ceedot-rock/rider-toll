#!/usr/bin/env python3
"""tollkeeper.stripe_metering — report paid toll usage to Stripe billing meters.

Dark-by-default: report_toll() is a no-op for any gate not in GATES_LIVE.
Nothing here flips a gate live; flips need CoS smoke + Corey's go.

Gate 1's 100-free-queries rule is enforced HERE in lab code (Stripe only
ever sees billable usage): per-customer free counters live in the
tollkeeper SQLite store.

Stripe API: POST https://api.stripe.com/v1/billing/meter_events
  event_name, payload[stripe_customer_id], payload[value], identifier
`identifier` is the idempotency key. Pass a stable dedup_key when
retrying; otherwise a random one is generated (at-most-once delivery
only holds when the caller supplies its own key).

Auth: STRIPE_SECRET_KEY env, or explicit api_key param. The key is never
logged or persisted by this module.
"""

import os
import time
import json
import uuid
import urllib.error
import urllib.parse
import urllib.request

from . import store
from . import stripe_config as sc

STRIPE_API = "https://api.stripe.com"


class MeteringError(Exception):
    """Config/auth/shape problems. Never raised for dark gates."""


def _api_key(explicit=None):
    key = (explicit or os.environ.get("STRIPE_SECRET_KEY", "")).strip()
    if not key:
        raise MeteringError(
            "no Stripe key: set STRIPE_SECRET_KEY env or pass api_key")
    return key


def _meter_entry(gate, kind=None):
    """Resolve (meter_event, meter_id) for a gate. Gate 4 needs kind."""
    if gate == 4:
        if kind not in ("issue", "check"):
            raise MeteringError("gate 4 needs kind='issue' or kind='check'")
        half = sc.GATE_STRIPE[4][kind]
        return half["meter_event"], half["meter_id"]
    g = sc.GATE_STRIPE.get(gate)
    if not g or "meter_event" not in g:
        raise MeteringError("no Stripe meter configured for gate %r" % (gate,))
    return g["meter_event"], g["meter_id"]


def _gate_live(gate):
    return bool(sc.GATES_LIVE.get(gate))


def _free_remaining(customer_id, gate):
    """Billable-free queries left for this customer on this gate."""
    free = sc.GATE_STRIPE.get(gate, {}).get("free_allotment", 0)
    if free <= 0:
        return 0
    con = store.connect()
    try:
        con.execute("""CREATE TABLE IF NOT EXISTS stripe_free_quota (
            customer_id TEXT NOT NULL, gate INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (customer_id, gate))""")
        row = con.execute(
            "SELECT used FROM stripe_free_quota WHERE customer_id=? AND gate=?",
            (customer_id, gate)).fetchone()
        used = row["used"] if row else 0
        return max(0, free - used)
    finally:
        con.close()


def _consume_free(customer_id, gate, n):
    con = store.connect()
    try:
        con.execute("""CREATE TABLE IF NOT EXISTS stripe_free_quota (
            customer_id TEXT NOT NULL, gate INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (customer_id, gate))""")
        con.execute("""INSERT INTO stripe_free_quota
            (customer_id, gate, used, updated_at) VALUES (?,?,?,?)
            ON CONFLICT(customer_id, gate) DO UPDATE SET
            used=used+excluded.used, updated_at=excluded.updated_at""",
            (customer_id, gate, n, store.now()))
        con.commit()
    finally:
        con.close()


def _post_meter_event(api_key, event_name, customer_id, value, identifier):
    body = urllib.parse.urlencode({
        "event_name": event_name,
        "payload[stripe_customer_id]": customer_id,
        "payload[value]": str(int(value)),
        "identifier": identifier,
    }).encode()
    req = urllib.request.Request(
        STRIPE_API + "/v1/billing/meter_events", data=body, method="POST")
    req.add_header("Authorization", "Bearer " + api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise MeteringError("Stripe meter_events HTTP %s: %s"
                            % (e.code, e.read()[:300]))


def report_toll(gate, stripe_customer_id, value=1, kind=None,
                api_key=None, dedup_key=None):
    """Report one paid toll to the gate's Stripe billing meter.

    gate: 1, 2, 4, 5, 7 (gate 4 also needs kind="issue"/"check").
    Returns {"reported": bool, ...}. A dark gate returns
    {"reported": False, "reason": "gate-dark"} and sends nothing.
    Gate 1 consumes the 100-free quota first and only reports the
    billable remainder.
    """
    if not stripe_customer_id:
        raise MeteringError("stripe_customer_id is required")
    value = int(value)
    if value <= 0:
        raise MeteringError("value must be a positive int")
    if not _gate_live(gate):
        return {"reported": False, "reason": "gate-dark", "gate": gate}

    meter_event, meter_id = _meter_entry(gate, kind)

    billable = value
    free_used = 0
    if gate == 1:
        free = _free_remaining(stripe_customer_id, 1)
        free_used = min(free, value)
        if free_used:
            _consume_free(stripe_customer_id, 1, free_used)
        billable = value - free_used
        if billable <= 0:
            return {"reported": False, "reason": "free-quota",
                    "gate": gate, "free_used": free_used}

    key = _api_key(api_key)
    identifier = dedup_key or ("toll-%s-%s" % (meter_event, uuid.uuid4().hex))
    resp = _post_meter_event(key, meter_event, stripe_customer_id,
                             billable, identifier)
    return {"reported": True, "gate": gate, "meter_event": meter_event,
            "meter_id": meter_id, "value": billable, "free_used": free_used,
            "identifier": identifier,
            "stripe_ref": resp.get("identifier") or resp.get("id")}
