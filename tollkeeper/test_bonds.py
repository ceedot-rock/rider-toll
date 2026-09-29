"""Tests for Module E — bonding & insurance primitives (tollkeeper.bonds).

All settlement mocked. Temp DB per test run; nothing touches real money.
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.expanduser("~/workspace/rider-toll"))

from tollkeeper.envelope import (
    generate_keypair, jwks_from, sign, verify, envelope_id, EnvelopeError,
)
from tollkeeper.bonds import (
    BondLedger, BondsError, TRIGGER_ATTESTATION,
    AUDIT_EXPORT_FEE_UUSDC, RECOURSE_POOL,
)


def make_ledger():
    tmp = tempfile.mkdtemp(prefix="bonds-test-")
    key = generate_keypair("test-lab-1")
    jwks = jwks_from([key])
    ledger = BondLedger(key, jwks, db_path=os.path.join(tmp, "t.db"))
    return ledger, key, jwks, tmp


CONDS = [
    {"on": "dispute_upheld", "slash_pct": 50},
    {"on": "oracle_refuse", "slash_pct": 100},
]


def test_stake_ok():
    ledger, key, jwks, _ = make_ledger()
    ledger.fund("agent:a", 100.0)
    res = ledger.stake_bond("agent:a", 10.0, CONDS)
    assert res["bond_id"].startswith("bnd_")
    assert res["toll_uusdc"] == 10_000_000 // 100  # 1% of 10 USDC
    # stake envelope verifies and carries integer money
    payload = verify(res["envelope"], jwks)
    assert payload["type"] == "bond_stake"
    assert payload["amount_uusdc"] == 10_000_000
    assert payload["conditions"] == CONDS
    # funds locked: 90 free
    assert ledger.balance_of("agent:a") == 90_000_000
    # metered 1%
    assert ledger.meter_total("agent:a") == 100_000
    print("test_stake_ok PASS")


def test_stake_refusals():
    ledger, key, jwks, _ = make_ledger()
    ledger.fund("agent:a", 5.0)
    for bad_conds, why in [
        ([{"on": "nope", "slash_pct": 50}], "unknown trigger"),
        ([{"on": "dispute_upheld", "slash_pct": 0}], "zero pct"),
        ([{"on": "dispute_upheld", "slash_pct": 101}], "pct > 100"),
        ([{"on": "dispute_upheld", "slash_pct": 50},
          {"on": "dispute_upheld", "slash_pct": 10}], "duplicate trigger"),
        ([], "empty conditions"),
    ]:
        try:
            ledger.stake_bond("agent:a", 1.0, bad_conds)
        except BondsError:
            pass
        else:
            raise AssertionError("stake accepted bad conditions: " + why)
    try:
        ledger.stake_bond("agent:a", 0.0, CONDS)
    except BondsError:
        pass
    else:
        raise AssertionError("stake accepted zero amount")
    try:
        ledger.stake_bond("agent:a", 6.0, CONDS)  # only 5 funded
    except BondsError:
        pass
    else:
        raise AssertionError("stake accepted without funds")
    print("test_stake_refusals PASS")


def _evidence(key, bond_id, attestation_type, verdict_field, verdict, pay_to=None):
    payload = {"attestation_type": attestation_type, "bond_id": bond_id,
               verdict_field: verdict}
    if pay_to:
        payload["pay_to"] = pay_to
    return sign(payload, key)


def test_slash_dispute():
    ledger, key, jwks, _ = make_ledger()
    ledger.fund("agent:a", 100.0)
    bond_id = ledger.stake_bond("agent:a", 10.0, CONDS)["bond_id"]
    ev = _evidence(key, bond_id, "dispute_resolution", "outcome", "upheld",
                   pay_to="agent:counterparty")
    res = ledger.slash(bond_id, "dispute_upheld", ev)
    assert res["slashed_uusdc"] == 5_000_000  # 50% of 10 USDC
    assert res["recipient"] == "agent:counterparty"
    assert res["remaining_uusdc"] == 5_000_000
    assert ledger.balance_of("agent:counterparty") == 5_000_000
    payload = verify(res["envelope"], jwks)
    assert payload["type"] == "bond_slash"
    assert payload["evidence_id"] == envelope_id(ev)
    print("test_slash_dispute PASS")


def test_slash_oracle_exhausts():
    ledger, key, jwks, _ = make_ledger()
    ledger.fund("agent:a", 100.0)
    bond_id = ledger.stake_bond("agent:a", 10.0, CONDS)["bond_id"]
    ev = _evidence(key, bond_id, "exactness_attestation", "verdict", "refuse")
    res = ledger.slash(bond_id, "oracle_refuse", ev)
    assert res["slashed_uusdc"] == 10_000_000  # 100%
    assert res["recipient"] == RECOURSE_POOL  # default when no pay_to
    assert res["remaining_uusdc"] == 0
    # exhausted bond refuses further slash/release
    for fn in (lambda: ledger.slash(bond_id, "oracle_refuse", ev),
               lambda: ledger.release(bond_id)):
        try:
            fn()
        except BondsError:
            pass
        else:
            raise AssertionError("exhausted bond allowed movement")
    print("test_slash_oracle_exhausts PASS")


def test_slash_refusals():
    ledger, key, jwks, _ = make_ledger()
    other_key = generate_keypair("attacker")
    ledger.fund("agent:a", 100.0)
    bond_id = ledger.stake_bond("agent:a", 10.0, CONDS)["bond_id"]
    good_ev = _evidence(key, bond_id, "dispute_resolution", "outcome", "upheld")
    # trigger with no matching condition on this bond
    try:
        ledger.slash(bond_id, "timeout_default", good_ev)
    except BondsError:
        pass
    else:
        raise AssertionError("slash allowed trigger without condition")
    # evidence for a different bond
    ev_other = _evidence(key, "bnd_deadbeef", "dispute_resolution", "outcome", "upheld")
    try:
        ledger.slash(bond_id, "dispute_upheld", ev_other)
    except BondsError:
        pass
    else:
        raise AssertionError("slash accepted evidence for another bond")
    # evidence signed by unknown key
    ev_bad = _evidence(other_key, bond_id, "dispute_resolution", "outcome", "upheld")
    try:
        ledger.slash(bond_id, "dispute_upheld", ev_bad)
    except BondsError:
        pass
    else:
        raise AssertionError("slash accepted forged evidence")
    # wrong attestation type for the trigger
    ev_wrong = _evidence(key, bond_id, "exactness_attestation", "verdict", "refuse")
    try:
        ledger.slash(bond_id, "dispute_upheld", ev_wrong)
    except BondsError:
        pass
    else:
        raise AssertionError("slash accepted mismatched attestation type")
    # unknown bond
    try:
        ledger.slash("bnd_nope", "dispute_upheld", good_ev)
    except BondsError:
        pass
    else:
        raise AssertionError("slash accepted unknown bond")
    print("test_slash_refusals PASS")


def test_release():
    ledger, key, jwks, _ = make_ledger()
    ledger.fund("agent:a", 100.0)
    bond_id = ledger.stake_bond("agent:a", 10.0, CONDS)["bond_id"]
    res = ledger.release(bond_id)
    assert res["released_uusdc"] == 10_000_000
    assert ledger.balance_of("agent:a") == 100_000_000  # full refund
    payload = verify(res["envelope"], jwks)
    assert payload["type"] == "bond_release"
    try:
        ledger.release(bond_id)
    except BondsError:
        pass
    else:
        raise AssertionError("double release allowed")
    print("test_release PASS")


def test_audit_trail():
    ledger, key, jwks, _ = make_ledger()
    ledger.fund("agent:a", 100.0)
    bond_id = ledger.stake_bond("agent:a", 10.0, CONDS)["bond_id"]
    ev = _evidence(key, bond_id, "dispute_resolution", "outcome", "upheld")
    ledger.slash(bond_id, "dispute_upheld", ev)
    ledger.release(bond_id)  # releases the remaining 5
    trail = ledger.export_audit_trail("agent:a")
    payload = verify(trail, jwks)
    assert payload["type"] == "audit_trail"
    assert payload["agent_id"] == "agent:a"
    assert payload["envelope_count"] == 3
    kinds = [verify(e, jwks)["type"] for e in payload["chain"]]
    assert kinds == ["bond_stake", "bond_slash", "bond_release"], kinds
    # every envelope in the chain verifies against the lab JWKS
    for e in payload["chain"]:
        verify(e, jwks)
    # metering: 1% of 10 USDC + 5c export
    assert ledger.meter_total("agent:a") == 100_000 + AUDIT_EXPORT_FEE_UUSDC
    assert AUDIT_EXPORT_FEE_UUSDC == 50_000
    print("test_audit_trail PASS")


def test_audit_trail_empty_agent():
    ledger, key, jwks, _ = make_ledger()
    trail = ledger.export_audit_trail("agent:ghost")
    payload = verify(trail, jwks)
    assert payload["envelope_count"] == 0 and payload["chain"] == []
    print("test_audit_trail_empty_agent PASS")


if __name__ == "__main__":
    test_stake_ok()
    test_stake_refusals()
    test_slash_dispute()
    test_slash_oracle_exhausts()
    test_slash_refusals()
    test_release()
    test_audit_trail()
    test_audit_trail_empty_agent()
    print("ALL BONDS TESTS PASS")
