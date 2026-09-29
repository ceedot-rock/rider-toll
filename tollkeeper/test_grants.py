"""Tests for module C (grants.py). Run:
    cd ~/workspace/rider-toll && python3 -m unittest tollkeeper.test_grants -v
Local only; dev keypair generated in-memory; temp SQLite db per test.
"""

import copy
import sqlite3
import tempfile
import time
import unittest

from tollkeeper.envelope import (
    EnvelopeError, generate_keypair, jwks_from, verify,
)
from tollkeeper import grants
from tollkeeper.grants import (
    GrantError, issue_grant, revoke_grant, record_spend, spent_total,
    get_grant, is_revoked, check_grant, usdc_to_uusdc,
    ISSUE_TOLL_UUSDC, CHECK_TOLL_UUSDC,
)


def _meter_total(db_path):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_uusdc),0) FROM meter").fetchone()
        return int(row[0])
    finally:
        conn.close()


class GrantsTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        self.key = generate_keypair("test-grants-1")
        self.jwks = jwks_from([self.key])
        self.now = int(time.time())

    def _grant(self, **kw):
        args = dict(
            grantor="principal-1",
            agent_id="agent-7",
            scope=["compress", "decompress"],
            cap_uusdc=2_000_000,          # $2.00
            not_before=self.now - 10,
            not_after=self.now + 3600,
            key=self.key,
            db_path=self.db,
            issued_at=self.now,
        )
        args.update(kw)
        return issue_grant(**args)

    # -- issuance ------------------------------------------------------
    def test_issue_returns_verifiable_envelope(self):
        env = self._grant()
        payload = verify(env, self.jwks)
        self.assertEqual(payload["type"], "delegation-grant")
        self.assertEqual(payload["grantor"], "principal-1")
        self.assertEqual(payload["scope"], ["compress", "decompress"])
        self.assertEqual(payload["cap_uusdc"], 2_000_000)
        self.assertTrue(payload["revocable"])
        self.assertTrue(payload["grant_id"].startswith("gr_"))
        # persisted
        self.assertIsNotNone(get_grant(payload["grant_id"], db_path=self.db))
        # 1c issuance metered
        self.assertEqual(_meter_total(self.db), ISSUE_TOLL_UUSDC)

    def test_issue_rejects_bad_inputs(self):
        with self.assertRaises(GrantError):
            self._grant(scope=[])
        with self.assertRaises(GrantError):
            self._grant(cap_uusdc=0)
        with self.assertRaises(GrantError):
            self._grant(cap_uusdc=1.5)          # floats refused
        with self.assertRaises(GrantError):
            self._grant(not_after=self.now - 20)  # window inverted

    # -- checks ---------------------------------------------------------
    def test_check_ok(self):
        env = self._grant()
        allowed, reason = check_grant(env, "compress", 500_000,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (True, "ok"))

    def test_scope_miss(self):
        env = self._grant()
        allowed, reason = check_grant(env, "launch-missiles", 1,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (False, "scope_miss"))

    def test_cap_exceeded(self):
        env = self._grant()
        gid = env["payload"]["grant_id"]
        record_spend(gid, 1_800_000, "compress", db_path=self.db)
        self.assertEqual(spent_total(gid, db_path=self.db), 1_800_000)
        allowed, reason = check_grant(env, "compress", 500_000,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (False, "cap_exceeded"))
        # but a smaller amount still fits
        allowed, reason = check_grant(env, "compress", 200_000,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (True, "ok"))

    def test_expired(self):
        env = self._grant(not_after=self.now - 1)
        allowed, reason = check_grant(env, "compress", 1,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (False, "expired"))

    def test_not_yet_valid(self):
        env = self._grant(not_before=self.now + 600,
                          not_after=self.now + 3600)
        allowed, reason = check_grant(env, "compress", 1,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (False, "not_yet_valid"))

    def test_revoked(self):
        env = self._grant()
        gid = env["payload"]["grant_id"]
        renv = revoke_grant(gid, revoker="principal-1", key=self.key,
                            db_path=self.db, revoked_at=self.now)
        verify(renv, self.jwks)  # revocation is a signed envelope
        self.assertTrue(is_revoked(gid, db_path=self.db))
        allowed, reason = check_grant(env, "compress", 1,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (False, "revoked"))

    def test_stale_revocation_check_fails_closed(self):
        env = self._grant()
        allowed, reason = check_grant(
            env, "compress", 1, jwks=self.jwks, db_path=self.db,
            now=self.now, revocation_checked_at=self.now - 400)
        self.assertEqual((allowed, reason),
                         (False, "revocation_check_stale"))
        # fresh snapshot passes
        allowed, reason = check_grant(
            env, "compress", 1, jwks=self.jwks, db_path=self.db,
            now=self.now, revocation_checked_at=self.now - 60)
        self.assertEqual((allowed, reason), (True, "ok"))

    def test_tampered_envelope_refused(self):
        env = self._grant()
        evil = copy.deepcopy(env)
        evil["payload"]["scope"].append("launch-missiles")
        with self.assertRaises(EnvelopeError):
            verify(evil, self.jwks)
        allowed, reason = check_grant(evil, "compress", 1,
                                      jwks=self.jwks, db_path=self.db,
                                      now=self.now)
        self.assertEqual((allowed, reason), (False, "bad_signature"))

    def test_wrong_key_refused(self):
        env = self._grant()
        other = generate_keypair("attacker")
        allowed, reason = check_grant(env, "compress", 1,
                                      jwks=jwks_from([other]),
                                      db_path=self.db, now=self.now)
        self.assertEqual((allowed, reason), (False, "bad_signature"))

    def test_check_metered(self):
        env = self._grant()
        check_grant(env, "compress", 1, jwks=self.jwks,
                    db_path=self.db, now=self.now)
        check_grant(env, "nope", 1, jwks=self.jwks,
                    db_path=self.db, now=self.now)
        # 1c issue + 2 x 0.5c checks
        self.assertEqual(_meter_total(self.db),
                         ISSUE_TOLL_UUSDC + 2 * CHECK_TOLL_UUSDC)

    def test_usdc_to_uusdc(self):
        self.assertEqual(usdc_to_uusdc("2"), 2_000_000)
        self.assertEqual(usdc_to_uusdc("0.005"), 5_000)
        with self.assertRaises(GrantError):
            usdc_to_uusdc("-1")


if __name__ == "__main__":
    unittest.main()
