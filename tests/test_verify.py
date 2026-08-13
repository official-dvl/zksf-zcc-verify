"""A checker that passes everything is worth nothing, so most of these tests
tamper with a valid record and assert that the tampering is caught."""
from __future__ import annotations

import copy

import pytest

from zcc_verify import verify

# A real ZCC-v0.1 certificate: 12-qubit GHZ on the MPS engine with a measured
# discarded-weight bound. Fetched from api.zksf.org/certify/fe529e21d7404ff3/json.
MPS = {
    "cert_id": "fe529e21d7404ff3",
    "engine": "mps.quimb.cpu",
    "method": "MPS (quimb), rigorous discarded-weight bound",
    "shots": 512,
    "circuit_sha256": "0c1e6d9a6f4b5f2e8a3d7c5b1e9f4a2d6c8b0e3f7a1d5c9b2e6f0a4d8c3b7e1f",
    "created_at": "2026-07-09T13:20:03+00:00",
    "verify_url": "https://api.zksf.org/certify/fe529e21d7404ff3",
    "top_outcomes": [["000000000000", 268], ["111111111111", 244]],
    "protocol": "ZCC-v0.1",
    "certificate_type": "Simulation Accuracy",
    "exact": False,
    "truncation_weight": 2.220446049250313e-16,
    "error_bound": 2.1073424255447017e-08,
    "converged": True,
    "certified": True,
}

# A real ZHF-v0.1 certificate: Bell state on IonQ Forte-1 hardware.
HARDWARE = {
    "cert_id": "df1d4c698a954051",
    "engine": "qpu.ionq",
    "method": "quantum hardware (IonQ Forte-1 (trapped ion))",
    "shots": 100,
    "circuit_sha256": "3b3e9bc07d222a2ef79e6f3f4cb0f34332e355d68c3b5e194171e1ba13c80447",
    "created_at": "2026-07-09T14:29:29+00:00",
    "verify_url": "https://api.zksf.org/certify/df1d4c698a954051",
    "top_outcomes": [["00", 54], ["11", 44], ["01", 2]],
    "protocol": "ZHF-v0.1",
    "certificate_type": "Hardware Fidelity",
    "device": "Forte-1",
    "fidelity": 0.977442,
    "fidelity_mode": "direct",
}

PAULI = {
    "cert_id": "5b8b2c4309d44d41",
    "engine": "pauli.cpu",
    "method": "Pauli propagation (Heisenberg picture)",
    "shots": 1000,
    "circuit_sha256": "a" * 64,
    "created_at": "2026-07-12T20:58:18+00:00",
    "verify_url": "https://api.zksf.org/certify/5b8b2c4309d44d41",
    "protocol": "ZCC-v0.1",
    "certificate_type": "Simulation Accuracy",
    "exact": False,
    "truncated_coefficient_mass": 0.0,
    "error_bound": 0.0,
    "converged": True,
    "certified": True,
    "expectation": 1.0,
}


def failed(rec) -> list[str]:
    return [c.name for c in verify(rec).failures]


def tampered(base: dict, **changes) -> dict:
    rec = copy.deepcopy(base)
    rec.update(changes)
    return rec


# --------------------------------------------------------------- valid records

@pytest.mark.parametrize("rec", [MPS, HARDWARE, PAULI], ids=["mps", "hardware", "pauli"])
def test_real_certificates_are_consistent(rec):
    assert verify(rec).ok, failed(rec)


def test_exact_run_with_no_bound_is_consistent():
    rec = tampered(MPS, exact=True, truncation_weight=0.0, error_bound=0.0)
    assert verify(rec).ok, failed(rec)


def test_hardware_may_decline_to_claim_a_fidelity():
    """Too large to simulate classically is an honest answer, provided no
    figure is invented to fill the gap."""
    rec = tampered(HARDWARE, fidelity_mode="unavailable", fidelity=None)
    assert verify(rec).ok, failed(rec)


# ------------------------------------------------------------ caught tampering

def test_bound_that_does_not_follow_from_the_weight_is_rejected():
    """The load-bearing check: a bound quietly shrunk to look better."""
    rec = tampered(MPS, error_bound=1e-12)
    assert "bound recomputed from the measurement" in failed(rec)


def test_weight_altered_without_the_bound_is_rejected():
    rec = tampered(MPS, truncation_weight=1e-4)
    assert "bound recomputed from the measurement" in failed(rec)


def test_pauli_bound_must_equal_the_discarded_mass():
    rec = tampered(PAULI, truncated_coefficient_mass=1e-3, error_bound=1e-9)
    assert "bound recomputed from the measurement" in failed(rec)


def test_exact_claim_with_a_nonzero_bound_is_rejected():
    rec = tampered(MPS, exact=True)
    assert "exact run declares no approximation error" in failed(rec)


def test_bound_above_one_is_rejected():
    """A bound on a probability cannot exceed 1: two distributions differ by
    at most that much."""
    rec = tampered(MPS, error_bound=1.5)
    assert "bound is a probability" in failed(rec)


def test_converged_flag_is_checked_against_the_bound():
    rec = tampered(MPS, truncation_weight=0.5, error_bound=1.0, converged=True)
    assert "converged flag consistent with the bound" in failed(rec)


def test_pauli_uses_its_own_convergence_threshold():
    """1e-8 is converged for MPS but not for Pauli propagation, so a checker
    applying one threshold to both would miss this."""
    rec = tampered(PAULI, truncated_coefficient_mass=1e-8, error_bound=1e-8, converged=True)
    assert "converged flag consistent with the bound" in failed(rec)


def test_account_data_is_rejected():
    rec = tampered(MPS, user_sub="us-east-1:9f3c", charged_micro=4200)
    assert "carries no account or circuit data" in failed(rec)


def test_embedded_circuit_is_rejected():
    """The circuit is the user's, and a certificate identifies it by hash."""
    rec = tampered(MPS, qasm2="OPENQASM 2.0; qreg q[12];")
    assert "carries no account or circuit data" in failed(rec)


def test_bad_digest_is_rejected():
    assert "circuit identified by SHA-256" in failed(tampered(MPS, circuit_sha256="deadbeef"))


def test_unknown_protocol_is_not_waved_through():
    """A later revision may carry invariants this version cannot check, so it
    is reported rather than assumed sound."""
    assert "protocol recognised" in failed(tampered(MPS, protocol="ZCC-v9.9"))


def test_missing_required_field_is_rejected():
    rec = copy.deepcopy(MPS)
    del rec["verify_url"]
    assert "required fields present" in failed(rec)


def test_unparseable_timestamp_is_rejected():
    assert "issued-at timestamp parses" in failed(tampered(MPS, created_at="last Tuesday"))


def test_fidelity_outside_the_unit_interval_is_rejected():
    assert "fidelity within [0, 1]" in failed(tampered(HARDWARE, fidelity=1.4))


def test_fidelity_claimed_without_a_reference_is_rejected():
    """Declaring verification unavailable and then reporting a number anyway
    is the specific dishonesty ZHF-v0.1 exists to prevent."""
    rec = tampered(HARDWARE, fidelity_mode="unavailable", fidelity=0.99)
    assert "no fidelity claimed without a reference" in failed(rec)


def test_unknown_fidelity_mode_is_rejected():
    assert "fidelity mode declared" in failed(tampered(HARDWARE, fidelity_mode="trust me"))


def test_outcomes_exceeding_the_shot_count_are_rejected():
    rec = tampered(HARDWARE, top_outcomes=[["00", 900], ["11", 400]])
    assert "measured outcomes" in failed(rec)


def test_non_bitstring_outcome_labels_are_rejected():
    assert "measured outcomes" in failed(tampered(HARDWARE, top_outcomes=[["yes", 54]]))


def test_negative_shot_count_is_rejected():
    assert "shot count" in failed(tampered(MPS, shots=-1))
