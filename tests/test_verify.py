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

# The records below were issued by the ZKSF service's own certificate code,
# run in-process on 27 Oct 2026 with no account and nothing published, so
# their verify_url does not resolve. They are exactly what a live run emits.

# ZQEC-v0.1 suppression: surface code at distances 3, 5 and 7, p = 3e-3.
SCALING = {
    "cert_id": "02997abac7d04dc9",
    "engine": "exact.cpu",
    "method": "exact.cpu",
    "shots": 20000,
    "circuit_sha256": "fe50077da7d47815c474b831bdb55dbb4b7ea3c4d5f77c472ae66fc807bc7841",
    "hash_subject": "Code and noise model",
    "created_at": "2026-10-27T10:56:27+00:00",
    "verify_url": "https://api.zksf.org/certify/02997abac7d04dc9",
    "top_outcomes": [],
    "expectation": None,
    "protocol": "ZQEC-v0.1",
    "certificate_type": "Logical Error Suppression",
    "code": "surface",
    "physical_error": 0.003,
    "decoder": "minimum-weight perfect matching (pymatching)",
    "measured_points": [
        {"distance": 3, "rounds": 3, "logical_errors": 133, "shots": 20000, "logical_error_rate": 0.00665,
         "confidence_interval_95": [0.005614465219510906, 0.007875016757047527]},
        {"distance": 5, "rounds": 5, "logical_errors": 65, "shots": 20000, "logical_error_rate": 0.00325,
         "confidence_interval_95": [0.0025509199970575078, 0.004139867824682438]},
        {"distance": 7, "rounds": 7, "logical_errors": 27, "shots": 20000, "logical_error_rate": 0.00135,
         "confidence_interval_95": [0.0009280055236101935, 0.00196351203514295]},
    ],
    "excluded_points": [],
    "suppression_factor": 2.2194427061597977,
    "suppression_prefactor": 0.03365720697711047,
    "suppression_factor_range": [1.5932845440573196, 3.0916799791341676],
    "suppression_factor_range_confidence": 0.95,
}

# The same at p = 1.5e-3 and 10,000 shots: distance 7 saw no failure, so it is
# bounded and left out of the fit, which then rests on two distances.
SCALING_EXCLUDED = {
    "cert_id": "cf49372b22be4654",
    "engine": "exact.cpu",
    "method": "exact.cpu",
    "shots": 10000,
    "circuit_sha256": "033da1d6ac45b7a613626c4ee648010cc79d9a94201e7a30a46b9a6145bf42f4",
    "hash_subject": "Code and noise model",
    "created_at": "2026-10-27T10:56:28+00:00",
    "verify_url": "https://api.zksf.org/certify/cf49372b22be4654",
    "top_outcomes": [],
    "expectation": None,
    "protocol": "ZQEC-v0.1",
    "certificate_type": "Logical Error Suppression",
    "code": "surface",
    "physical_error": 0.0015,
    "decoder": "minimum-weight perfect matching (pymatching)",
    "measured_points": [
        {"distance": 3, "rounds": 3, "logical_errors": 17, "shots": 10000, "logical_error_rate": 0.0017,
         "confidence_interval_95": [0.0010617073611205118, 0.0027209854150957833]},
        {"distance": 5, "rounds": 5, "logical_errors": 9, "shots": 10000, "logical_error_rate": 0.0009,
         "confidence_interval_95": [0.00047357706058500574, 0.0017097301130243718]},
    ],
    "excluded_points": [
        {"distance": 7, "rounds": 7, "logical_errors": 0, "shots": 10000, "logical_error_rate": 0.0,
         "confidence_interval_95": [2.710505431213761e-20, 0.00038399837067659573]},
    ],
    "suppression_factor": 1.8888888888888895,
    "suppression_prefactor": 0.006065432098765437,
    "suppression_factor_range": [0.5320588239162175, 6.705839794754968],
    "suppression_factor_range_confidence": 0.95,
}

# ZQEC-v0.1 for one memory experiment: surface code, distance 3, p = 1e-3.
QEC = {
    "cert_id": "295ceece05cf4fc8",
    "engine": "exact.cpu",
    "method": "exact.cpu",
    "shots": 2000,
    "circuit_sha256": "a7438c0be96708e1e09832638e1f0cbe5f0cddb3a31d804524d47a96748f783b",
    "hash_subject": "Code and noise model",
    "created_at": "2026-10-27T10:56:28+00:00",
    "verify_url": "https://api.zksf.org/certify/295ceece05cf4fc8",
    "top_outcomes": [],
    "expectation": None,
    "protocol": "ZQEC-v0.1",
    "certificate_type": "Logical Error Rate",
    "logical_error_rate": 0.0005,
    "confidence_interval_95": [8.826773070546787e-05, 0.0028268625032662133],
    "logical_errors": 1,
    "code": "surface",
    "distance": 3,
    "rounds": 3,
    "physical_error": 0.001,
    "decoder": "minimum-weight perfect matching (pymatching)",
    "detectors": 24,
}

# ZCC-Estimate-v0.2 for a neural ground state: a 4-spin transverse-field Ising
# chain, with a ceiling and a Weinstein floor on the true ground energy.
NNQS = {
    "cert_id": "d4161de3800a4697",
    "engine": "neural.cpu",
    "method": "nnqs.vmc",
    "evaluations": None,
    "iterations": None,
    "circuit_sha256": "8f6b429414a1eb15e018aef564f139a338ecbc294c94bdfa88931b6abb43c12d",
    "hash_subject": "Hamiltonian",
    "created_at": "2026-10-27T10:56:40+00:00",
    "verify_url": "https://api.zksf.org/certify/d4161de3800a4697",
    "top_outcomes": [],
    "expectation": None,
    "protocol": "ZCC-Estimate-v0.2",
    "certificate_type": "Simulation Accuracy",
    "exact": False,
    "ground_state_ceiling": -4.758672071025785,
    "ground_state_floor": -4.759443094038029,
    "floor_method": "weinstein",
    "floor_is_conditional": True,
    "energy_variance": 1.7520289833015598e-07,
    "energy": -4.758786511029796,
    "energy_stderr": 2.2888000802176876e-05,
    "certifiable": True,
}

# ZCC-Estimate-v0.2 for zero-noise extrapolation, which shares the protocol with
# the neural record above and states something else entirely: an extrapolated
# value with a one-sigma uncertainty, and no bound.
ZNE = {
    "cert_id": "7bf1f4bc25e24310",
    "engine": "noisy.cpu",
    "method": "noisy simulation (superconducting) + ZNE mitigation",
    "shots": 512,
    "circuit_sha256": "6b7b3834ac03f548056f314b9fdfd882969b7ec02bb19fa8ad13cd957ab04768",
    "hash_subject": "Circuit",
    "created_at": "2026-10-27T10:56:34+00:00",
    "verify_url": "https://api.zksf.org/certify/7bf1f4bc25e24310",
    "top_outcomes": [["10", 208], ["01", 117], ["00", 114], ["11", 73]],
    "expectation": -0.28729511,
    "protocol": "ZCC-Estimate-v0.2",
    "certificate_type": "Simulation Accuracy",
    "exact": False,
    "error_bound": 0.05145061,
    "certified": False,
    "estimated": True,
    "mitigated_expectation": -0.28729511,
    "raw_expectation": -0.27385804,
    "technique": "zero-noise extrapolation (linear primary)",
    "sigma_level": 1,
    "uncertainty_is": "one standard error (1 sigma), not a worst case",
    "measured_coverage": {"simulator": 0.624, "hardware": 0.637, "runs": 3312, "multiplier_for_95_percent": 2.31},
}

# A circuit with two classical registers: the service writes its outcomes with
# a space between the registers.
TWO_REGISTERS = {
    "cert_id": "7f19c9bcf61a4d90",
    "engine": "exact.cpu",
    "method": "exact statevector",
    "shots": 100,
    "circuit_sha256": "3825f05bab75c7febfd01b033d94d1c66f9f16dcd46417065cfb86c4a7a3a986",
    "hash_subject": "Circuit",
    "created_at": "2026-10-27T10:56:28+00:00",
    "verify_url": "https://api.zksf.org/certify/7f19c9bcf61a4d90",
    "top_outcomes": [["01 00", 55], ["01 11", 45]],
    "expectation": None,
    "protocol": "ZCC-v0.1",
    "certificate_type": "Simulation Accuracy",
    "exact": True,
}

# A photonic hardware record, in the shape the service writes one. Made up for
# this test, not issued: outcomes are Fock states (photons per mode), and the
# fidelity is conditioned on the shots that detected every photon.
PHOTONIC = {
    "cert_id": "example-photonic",
    "engine": "qpu.quandela.belenos",
    "method": "photonic hardware (qpu:belenos)",
    "shots": 10000,
    "circuit_sha256": "b" * 64,
    "created_at": "2026-10-27T12:00:00+00:00",
    "verify_url": "https://api.zksf.org/certify/example-photonic",
    "top_outcomes": [["|1,0,0>", 4900], ["|0,1,0>", 4800], ["|1,1,0>", 250], ["|2,0,0>", 50]],
    "protocol": "ZHF-v0.1",
    "certificate_type": "Hardware Fidelity",
    "device": "Belenos",
    "fidelity": 0.95,
    "fidelity_mode": "direct, conditioned on full photon detection",
    "fidelity_raw_unconditioned": 0.03,
    "coincidence_events": 300,
    "coincidence_fraction": 0.03,
    "photons_sent": 2,
}


def failed(rec) -> list[str]:
    return [c.name for c in verify(rec).failures]


def checked(rec) -> list[str]:
    return [c.name for c in verify(rec).checks]


def tampered(base: dict, **changes) -> dict:
    rec = copy.deepcopy(base)
    rec.update(changes)
    return rec


# --------------------------------------------------------------- valid records

@pytest.mark.parametrize(
    "rec",
    [MPS, HARDWARE, PAULI, SCALING, SCALING_EXCLUDED, QEC, NNQS, ZNE, TWO_REGISTERS, PHOTONIC],
    ids=["mps", "hardware", "pauli", "scaling", "scaling-excluded", "qec", "nnqs", "zne",
         "two-registers", "photonic"],
)
def test_valid_certificates_are_consistent(rec):
    assert verify(rec).ok, failed(rec)


def test_a_circuit_that_measured_no_bits_has_an_empty_outcome():
    """0.1.0 accepted the empty label and a stored certificate carries one, so
    0.2.0 must not start failing it."""
    rec = tampered(MPS, top_outcomes=[["", 512]])
    assert verify(rec).ok, failed(rec)


def test_zne_gets_the_estimate_checks_not_the_neural_ones():
    """Both share ZCC-Estimate-v0.2. A ZNE record sent down the neural path would
    skip as "no bounds recorded" and never have its own claims checked."""
    names = checked(ZNE)
    assert "estimate does not claim to be certified" in names
    assert "uncertainty stated at one sigma" in names
    assert "energy bounds recomputed" not in names


def test_neural_record_from_before_bounds_were_written_is_skipped_not_failed():
    rec = {k: v for k, v in NNQS.items()
           if k not in ("ground_state_ceiling", "ground_state_floor", "floor_method",
                        "floor_is_conditional", "energy_variance", "energy", "energy_stderr")}
    report = verify(rec)
    assert report.ok, failed(rec)
    assert any(c.name == "energy bounds recomputed" and c.status == "skip" for c in report.checks)


def test_temple_floor_is_accepted_below_the_widened_energy():
    below = NNQS["energy"] - 5.0 * NNQS["energy_stderr"]
    rec = tampered(NNQS, floor_method="temple", ground_state_floor=below - 1e-4)
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


@pytest.mark.parametrize("label", ["|1,0", "1,0,0>", "|a,0>", "0101 ", " 0101", "01  10"])
def test_malformed_fock_and_register_labels_are_rejected(label):
    assert "measured outcomes" in failed(tampered(PHOTONIC, top_outcomes=[[label, 10]]))


# --------------------------------------------------- error correction (ZQEC-v0.1)

def _point(rec, i, **changes) -> dict:
    """A copy of rec with measured point i changed."""
    out = copy.deepcopy(rec)
    out["measured_points"][i].update(changes)
    return out


def test_suppression_factor_quietly_improved_is_rejected():
    """The load-bearing check for a scaling run: a better-looking lambda."""
    assert "suppression factor recomputed" in failed(tampered(SCALING, suppression_factor=3.5))


def test_prefactor_altered_is_rejected():
    assert "prefactor recomputed" in failed(tampered(SCALING, suppression_prefactor=0.01))


def test_suppression_range_narrowed_is_rejected():
    rec = tampered(SCALING, suppression_factor_range=[2.0, 2.5])
    assert "suppression factor range recomputed" in failed(rec)


def test_failure_count_altered_is_rejected():
    """Fewer failures at the largest distance would steepen the fit; the count
    no longer matches its own rate and interval."""
    assert "distance 7: rate and 95% interval recomputed" in failed(_point(SCALING, 2, logical_errors=10))


def test_measured_interval_narrowed_is_rejected():
    rec = _point(SCALING, 0, confidence_interval_95=[0.0065, 0.0068])
    assert "distance 3: rate and 95% interval recomputed" in failed(rec)


def test_excluded_point_must_have_no_failures():
    rec = copy.deepcopy(SCALING_EXCLUDED)
    rec["excluded_points"][0].update(logical_errors=1, logical_error_rate=1e-4)
    assert "distance 7 (no failures): rate and 95% interval recomputed" in failed(rec)


def test_single_rate_interval_narrowed_is_rejected():
    rec = tampered(QEC, confidence_interval_95=[0.0004, 0.0006])
    assert "logical error rate: rate and 95% interval recomputed" in failed(rec)


def test_more_failures_than_shots_is_rejected():
    rec = tampered(QEC, logical_errors=3000, logical_error_rate=1.5)
    assert "logical error rate: failures within the shots" in failed(rec)


def test_unknown_error_correction_type_is_rejected():
    rec = tampered(QEC, certificate_type="Logical Error Elimination")
    assert "error-correction certificate type" in failed(rec)


# ---------------------------------------------- neural ground state (ZCC-Estimate-v0.2)

def test_ceiling_lowered_is_rejected():
    """The ceiling is unconditional, so it is the one a reader leans on."""
    rec = tampered(NNQS, ground_state_ceiling=NNQS["energy"])
    assert "ceiling recomputed" in failed(rec)


def test_floor_raised_past_weinstein_is_rejected():
    rec = tampered(NNQS, ground_state_floor=NNQS["energy"] - 5.0 * NNQS["energy_stderr"])
    assert "Weinstein floor consistent" in failed(rec)


def test_floor_presented_as_unconditional_is_rejected():
    assert "floor stated as conditional" in failed(tampered(NNQS, floor_is_conditional=False))


def test_unknown_floor_method_is_rejected():
    assert "floor method" in failed(tampered(NNQS, floor_method="intuition"))


# ------------------------------------------- zero-noise extrapolation (ZCC-Estimate-v0.2)

def test_estimate_marked_certified_is_rejected():
    assert "estimate does not claim to be certified" in failed(tampered(ZNE, certified=True))


def test_estimate_uncertainty_not_at_one_sigma_is_rejected():
    assert "uncertainty stated at one sigma" in failed(tampered(ZNE, sigma_level=2))


def test_negative_uncertainty_is_rejected():
    assert "uncertainty is not negative" in failed(tampered(ZNE, error_bound=-0.05))


# ------------------------------------------------------------ photonic hardware

def test_coincidence_fraction_altered_is_rejected():
    assert "coincidence fraction recomputed" in failed(tampered(PHOTONIC, coincidence_fraction=0.3))


def test_more_coincidences_than_shots_is_rejected():
    assert "coincidence events within the shots" in failed(tampered(PHOTONIC, coincidence_events=20000))


def test_unconditioned_fidelity_outside_the_unit_interval_is_rejected():
    rec = tampered(PHOTONIC, fidelity_raw_unconditioned=1.2)
    assert "unconditioned fidelity within [0, 1]" in failed(rec)
