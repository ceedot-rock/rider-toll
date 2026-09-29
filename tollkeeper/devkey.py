"""TEST/DEV-ONLY key management for the toll-keeper local build.

Generates a P-256 keypair on first use and keeps it at
~/workspace/rider-toll/tollkeeper/.devkey.json (mode 600).

This key is for local development and tests ONLY. It must never sign
anything production-facing, and must never leave this machine.
"""

import json
import os

from .envelope import generate_keypair, jwks_from

DEVKEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".devkey.json")


def get_dev_key(kid="lab-dev-1"):
    """Load the dev keypair, creating it on first use."""
    if os.path.exists(DEVKEY_PATH):
        with open(DEVKEY_PATH, encoding="utf-8") as fh:
            key = json.load(fh)
        return key
    key = generate_keypair(kid)
    # ints don't survive JSON; store as hex
    stored = {"kid": key["kid"], "d": format(key["d"], "064x"),
              "x": format(key["x"], "064x"), "y": format(key["y"], "064x")}
    with open(DEVKEY_PATH, "w", encoding="utf-8") as fh:
        json.dump(stored, fh)
    os.chmod(DEVKEY_PATH, 0o600)
    return {"kid": stored["kid"], "d": key["d"], "x": key["x"], "y": key["y"]}


def load_dev_key():
    """Load the dev keypair from disk (raises if absent)."""
    with open(DEVKEY_PATH, encoding="utf-8") as fh:
        stored = json.load(fh)
    return {"kid": stored["kid"], "d": int(stored["d"], 16),
            "x": int(stored["x"], 16), "y": int(stored["y"], 16)}


def dev_jwks():
    return jwks_from([load_dev_key()])
