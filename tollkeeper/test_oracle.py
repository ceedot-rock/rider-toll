"""Tests for module D (oracle.py). Run:
    cd ~/workspace/rider-toll && python3 -m unittest tollkeeper.test_oracle -v
Local only; dev keypair generated in-memory; temp SQLite db per test.
"""

import sqlite3
import tempfile
import time
import unittest

from tollkeeper.envelope import (
    EnvelopeError, generate_keypair, jwks_from, verify,
)
from tollkeeper import oracle
from tollkeeper.oracle import (
    OracleError, submit_check, get_attestations, artifact_hash_of,
    default_exactness, set_exactness_fn, POLICY_REF,
    CHECK_TOLL_UUSDC, _simulate_seat_stdout,
)


def _meter_total(db_path):
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(amount_uusdc),0) FROM meter").fetchone()
        return int(row[0])
    finally:
        conn.close()


class OracleTest(unittest.TestCase):
    def setUp(self):
        self.db = tempfile.mktemp(suffix=".db")
        self.key = generate_keypair("test-oracle-1")
        self.jwks = jwks_from([self.key])
        self.now = int(time.time())
        self.artifact = {"program": "dice", "input": "seed=7"}
        self.good_stdout = _simulate_seat_stdout(self.artifact, "seat-a")

    def tearDown(self):
        set_exactness_fn(None)

    def _submit(self, claim, **kw):
        args = dict(key=self.key, db_path=self.db, now=self.now)
        args.update(kw)
        return submit_check(self.artifact, claim, **args)

    # -- stub exactness --------------------------------------------------
    def test_pass(self):
        env = self._submit({"stdout": self.good_stdout})
        payload = verify(env, self.jwks)
        self.assertEqual(payload["type"], "exactness-attestation")
        self.assertEqual(payload["result"], "pass")
        self.assertEqual(payload["policy_ref"], POLICY_REF)
        self.assertEqual(payload["artifact_hash"],
                         artifact_hash_of(self.artifact))
        self.assertEqual(payload["seats"], ["seat-a", "seat-b"])
        self.assertTrue(payload["attestation_id"].startswith("at_"))
        self.assertEqual(payload["oracle"], "tollkeeper-oracle/v1")

    def test_refuse_on_mismatch(self):
        env = self._submit({"stdout": "tampered-output"})
        payload = verify(env, self.jwks)
        self.assertEqual(payload["result"], "refuse")

    def test_default_exactness_shape(self):
        res = default_exactness(self.artifact, {"stdout": self.good_stdout})
        self.assertEqual(res["result"], "pass")
        self.assertTrue(res["detail"]["seats_agree"])
        res = default_exactness(self.artifact, {"stdout": "nope"})
        self.assertEqual(res["result"], "refuse")

    # -- query -----------------------------------------------------------
    def test_get_attestations(self):
        env1 = self._submit({"stdout": self.good_stdout})
        env2 = self._submit({"stdout": "wrong"})
        got = get_attestations(artifact_hash_of(self.artifact),
                               jwks=self.jwks, db_path=self.db)
        self.assertEqual(len(got), 2)
        self.assertEqual(
            [p["attestation_id"] for p in got],
            [env1["payload"]["attestation_id"],
             env2["payload"]["attestation_id"]])
        self.assertEqual([p["result"] for p in got], ["pass", "refuse"])
        # unknown hash -> empty
        self.assertEqual(
            get_attestations("0" * 64, jwks=self.jwks, db_path=self.db), [])

    # -- pluggable gate ---------------------------------------------------
    def test_custom_exactness_fn_per_call(self):
        def cuni_gate(artifact, claim):
            return {"result": "pass" if claim.get("ok") else "refuse",
                    "seats": ["cuni-py", "cuni-rs", "cuni-js"],
                    "detail": {"gate": "cuni-stub"}}
        env = self._submit({"ok": True}, exactness_fn=cuni_gate)
        payload = verify(env, self.jwks)
        self.assertEqual(payload["result"], "pass")
        self.assertEqual(payload["seats"], ["cuni-py", "cuni-rs", "cuni-js"])

    def test_global_exactness_fn(self):
        set_exactness_fn(lambda a, c: {"result": "refuse",
                                       "seats": ["gate"],
                                       "detail": {}})
        env = self._submit({"stdout": self.good_stdout})
        self.assertEqual(verify(env, self.jwks)["result"], "refuse")

    def test_bad_gate_result_rejected(self):
        with self.assertRaises(OracleError):
            self._submit({"stdout": self.good_stdout},
                         exactness_fn=lambda a, c: {"result": "maybe"})
        with self.assertRaises(OracleError):
            self._submit({"nope": 1})  # malformed claim

    # -- metering ----------------------------------------------------------
    def test_check_metered(self):
        self._submit({"stdout": self.good_stdout})
        self._submit({"stdout": "wrong"})
        self.assertEqual(_meter_total(self.db), 2 * CHECK_TOLL_UUSDC)

    # -- tamper evidence ----------------------------------------------------
    def test_tampered_attestation_fails_verify(self):
        import copy
        env = self._submit({"stdout": self.good_stdout})
        evil = copy.deepcopy(env)
        evil["payload"]["result"] = "pass"  # flip a refuse? it's pass; flip seats
        evil["payload"]["seats"] = ["evil-seat"]
        with self.assertRaises(EnvelopeError):
            verify(evil, self.jwks)


if __name__ == "__main__":
    unittest.main()
