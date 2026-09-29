#!/usr/bin/env python3
"""tollkeeper.server — deployable HTTP surface for the tollkeeper.

Routes:
  GET  /health            liveness probe
  GET  /v1/tolls/status   gate flags, pricing status, Stripe mode (read-only)
  POST /webhooks/stripe   Stripe webhook deliveries (raw body preserved)

The webhook route passes the RAW request body to
tollkeeper.stripe_webhook.handle_webhook, which verifies the
Stripe-Signature header (STRIPE_WEBHOOK_SECRET env) and dispatches
checkout.session.completed, customer.subscription.created/updated/deleted,
invoice.paid, invoice.payment_failed.

Env:
  PORT                  listen port (default 8080)
  TOLLKEEPER_DB         SQLite path (see tollkeeper.store)
  STRIPE_WEBHOOK_SECRET Stripe webhook signing secret. The webhook route
                        returns 500 without it; set it from the Stripe
                        dashboard (Developers > Webhooks) at deploy time.
  STRIPE_SECRET_KEY     Stripe secret key. Only needed if/when this service
                        reports meter events; not required for the webhook.

Stdlib only. Nothing here flips a gate, and nothing here charges anything.
"""
import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import stripe_config as sc
from . import stripe_webhook as wh

VERSION = "0.1.0"


class Handler(BaseHTTPRequestHandler):
    server_version = "tollkeeper/" + VERSION

    def _send(self, code, obj):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # quieter logs
        pass

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/health":
            return self._send(200, {"ok": True, "service": "tollkeeper",
                                    "version": VERSION})
        if p == "/v1/tolls/status":
            return self._send(200, {
                "gates_live": sc.GATES_LIVE,
                "pricing_status": sc.PRICING_STATUS,
                "stripe_mode": sc.STRIPE_MODE,
                "webhook_configured": bool(
                    os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()),
                "note": ("Read-only. Gates flip live only with CoS smoke + "
                         "Corey's explicit go; nothing here charges."),
            })
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p != "/webhooks/stripe":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(length) if length > 0 else b""
        sig_header = self.headers.get("Stripe-Signature", "")
        status, resp = wh.handle_webhook(raw_body, sig_header)
        return self._send(status, resp)


def make_server(port=0):
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("tollkeeper %s on :%d" % (VERSION, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
