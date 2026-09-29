#!/usr/bin/env python3
"""tollkeeper.stripe_webhook — Stripe webhook endpoint, framework-agnostic.

Ship deploys this behind an HTTPS POST route. It:
  1. Verifies the Stripe-Signature header (HMAC-SHA256, timestamp tolerance).
  2. Dispatches subscription-lifecycle events.
  3. Keeps the Stripe-customer <-> lab-payer-key map in the tollkeeper DB.

Handled: checkout.session.completed, customer.subscription.created,
customer.subscription.updated, customer.subscription.deleted,
invoice.paid, invoice.payment_failed.
Unknown types -> 200 {"received": True, "handled": False}: never make
Stripe retry an event we don't understand.

Secrets: STRIPE_WEBHOOK_SECRET env (or explicit param). The route MUST pass
the RAW request body — parsed-then-reserialized JSON breaks the signature.

handle_webhook() returns (http_status, response_dict); the route just
serializes that. No framework imports here on purpose.
"""

import hashlib
import hmac
import json
import os
import time

from . import store
from . import stripe_config as sc

TOLERANCE = 300  # seconds of clock skew allowed on the signature timestamp


def _price_to_gate():
    """Reverse map: Stripe price_id -> gate key (from stripe_config)."""
    out = {}
    for gk, g in sc.GATE_STRIPE.items():
        if not isinstance(g, dict):
            continue
        if "price_id" in g:
            out[g["price_id"]] = gk
        for sub in ("issue", "check"):
            half = g.get(sub)
            if isinstance(half, dict) and "price_id" in half:
                out[half["price_id"]] = (gk, sub)
    return out


_PRICE_TO_GATE = _price_to_gate()


def _parse_sig_header(sig_header):
    """Split 't=...,v1=...,v1=...' into (timestamp_str, [v1,...])."""
    ts, sigs = None, []
    for item in (sig_header or "").split(","):
        k, _, v = item.partition("=")
        k, v = k.strip(), v.strip()
        if k == "t" and ts is None:
            ts = v
        elif k == "v1" and v:
            sigs.append(v)
    return ts, sigs


def verify_signature(raw_body, sig_header, secret, tolerance=TOLERANCE,
                     now=None):
    """True iff the Stripe-Signature header checks out. No exceptions."""
    if not raw_body or not sig_header or not secret:
        return False
    ts, sigs = _parse_sig_header(sig_header)
    if not ts or not sigs:
        return False
    try:
        ts_int = int(ts)
    except (TypeError, ValueError):
        return False
    now = int(time.time()) if now is None else now
    if abs(now - ts_int) > tolerance:
        return False
    signed = str(ts_int).encode() + b"." + bytes(raw_body)
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(digest, s) for s in sigs)


def _ensure_tables(con):
    con.execute("""CREATE TABLE IF NOT EXISTS stripe_customers (
        stripe_customer_id TEXT PRIMARY KEY,
        payer_key TEXT,
        status TEXT NOT NULL DEFAULT 'unknown',
        price_id TEXT,
        gate_key TEXT,
        subscription_id TEXT,
        updated_at INTEGER NOT NULL)""")


def _upsert_customer(con, customer_id, payer_key=None, status=None,
                     price_id=None, gate_key=None, subscription_id=None):
    _ensure_tables(con)
    row = con.execute(
        "SELECT payer_key, status, price_id, gate_key, subscription_id"
        " FROM stripe_customers WHERE stripe_customer_id=?",
        (customer_id,)).fetchone()
    if row:
        payer_key = payer_key or row["payer_key"]
        status = status or row["status"]
        price_id = price_id or row["price_id"]
        gate_key = gate_key if gate_key is not None else row["gate_key"]
        subscription_id = subscription_id or row["subscription_id"]
        con.execute("""UPDATE stripe_customers SET payer_key=?, status=?,
            price_id=?, gate_key=?, subscription_id=?, updated_at=?
            WHERE stripe_customer_id=?""",
            (payer_key, status, price_id, str(gate_key),
             subscription_id, store.now(), customer_id))
    else:
        con.execute("""INSERT INTO stripe_customers
            (stripe_customer_id, payer_key, status, price_id, gate_key,
             subscription_id, updated_at) VALUES (?,?,?,?,?,?,?)""",
            (customer_id, payer_key, status or "unknown", price_id,
             str(gate_key), subscription_id, store.now()))
    con.commit()


def get_customer(customer_id):
    """Local subscription state for a Stripe customer (or None)."""
    con = store.connect()
    try:
        _ensure_tables(con)
        row = con.execute(
            "SELECT * FROM stripe_customers WHERE stripe_customer_id=?",
            (customer_id,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()


def _subscription_gate(sub):
    """(gate_key, price_id) from a subscription object, best effort."""
    try:
        price_id = sub["items"]["data"][0]["price"]["id"]
    except (KeyError, IndexError, TypeError):
        return None, None
    return _PRICE_TO_GATE.get(price_id), price_id


def _handle_checkout_completed(obj):
    customer = obj.get("customer")
    payer = obj.get("client_reference_id") or (obj.get("metadata") or {}).get("payer_key")
    sub_id = obj.get("subscription")
    if not customer:
        return {"action": "ignored", "reason": "no customer on session"}
    con = store.connect()
    try:
        _upsert_customer(con, customer, payer_key=payer,
                         status="checkout_complete", subscription_id=sub_id)
    finally:
        con.close()
    return {"action": "customer_recorded", "customer": customer,
            "payer_key": payer, "subscription": sub_id}


def _handle_subscription(obj, deleted=False):
    customer = obj.get("customer")
    if not customer:
        return {"action": "ignored", "reason": "no customer on subscription"}
    status = "canceled" if deleted else obj.get("status", "unknown")
    gate_key, price_id = _subscription_gate(obj)
    con = store.connect()
    try:
        _upsert_customer(con, customer, status=status, price_id=price_id,
                         gate_key=gate_key,
                         subscription_id=obj.get("id"))
    finally:
        con.close()
    return {"action": "subscription_" + ("canceled" if deleted else "updated"),
            "customer": customer, "status": status,
            "gate_key": gate_key, "price_id": price_id}


def _handle_invoice(obj, paid):
    customer = obj.get("customer")
    if customer:
        con = store.connect()
        try:
            _ensure_tables(con)
            row = con.execute(
                "SELECT 1 FROM stripe_customers WHERE stripe_customer_id=?",
                (customer,)).fetchone()
            if not row:
                _upsert_customer(con, customer,
                                 status="invoiced",
                                 subscription_id=obj.get("subscription"))
        finally:
            con.close()
    return {"action": "invoice_paid" if paid else "invoice_failed_dunning",
            "customer": customer, "invoice": obj.get("id"),
            "amount_due": obj.get("amount_due")}


_DISPATCH = {
    "checkout.session.completed": _handle_checkout_completed,
    "customer.subscription.created": lambda o: _handle_subscription(o),
    "customer.subscription.updated": lambda o: _handle_subscription(o),
    "customer.subscription.deleted": lambda o: _handle_subscription(o, deleted=True),
    "invoice.paid": lambda o: _handle_invoice(o, paid=True),
    "invoice.payment_failed": lambda o: _handle_invoice(o, paid=False),
}


def handle_webhook(raw_body, sig_header, webhook_secret=None):
    """Verify + dispatch one Stripe webhook delivery.

    Returns (http_status, response_dict). The route serializes the dict.
    """
    secret = (webhook_secret or os.environ.get("STRIPE_WEBHOOK_SECRET", "")).strip()
    if not secret:
        return 500, {"error": "webhook secret not configured"}
    if not verify_signature(raw_body, sig_header, secret):
        return 400, {"error": "bad signature"}
    try:
        event = json.loads(bytes(raw_body).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return 400, {"error": "bad json"}
    etype = event.get("type", "")
    handler = _DISPATCH.get(etype)
    if handler is None:
        return 200, {"received": True, "handled": False, "type": etype}
    try:
        obj = (event.get("data") or {}).get("object") or {}
        action = handler(obj)
    except Exception as e:  # never 500 on a dispatch bug; log via response
        return 200, {"received": True, "handled": False, "type": etype,
                     "error": "handler failed: %s" % str(e)[:200]}
    return 200, {"received": True, "handled": True, "type": etype,
                 "action": action}
