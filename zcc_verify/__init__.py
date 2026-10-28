"""Independent checker for ZKSF certificates: ZCC-v0.1, ZHF-v0.1, ZCC-Estimate-v0.1/v0.2 and ZQEC-v0.1.

    from zcc_verify import fetch, verify
    print(verify(fetch("fe529e21d7404ff3")))

What this establishes, and what it does not, stated plainly because the
distinction is the whole point of the format:

**It checks that a certificate is well formed and internally consistent.** The
declared error bound is recomputed from the measured quantity the certificate
reports, and the two must agree. A certificate whose stated bound does not
follow from its own stated inputs fails here, whoever issued it.

**It does not establish that the measurement was honest.** The discarded weight
in an MPS certificate, or the coefficient mass in a Pauli one, is produced by
whoever ran the simulation. No amount of arithmetic on the record can confirm
that the number reported is the number that was measured. Verifying a
certificate is not the same as trusting the issuer.

The specification is published at
https://doi.org/10.5281/zenodo.21851381, and the protocol reference is
https://github.com/official-dvl/zksf/blob/main/docs/CERTIFICATION.md.

Standard library only, on purpose: a validator that a third party has to install
a dependency tree to run is one they will not run. Vendor this file if it helps.
"""
from __future__ import annotations

import json
import math
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from statistics import NormalDist

__version__ = "0.2.1"

DEFAULT_BASE_URL = "https://api.zksf.org"

# Protocols this checker understands. An unknown protocol is reported rather
# than assumed to be fine: a future protocol may carry invariants this version
# knows nothing about, and silently passing it would be the wrong answer.
# 0.2.0 adds ZCC-Estimate-v0.2 (neural ground states and zero-noise
# extrapolation) and ZQEC-v0.1 (error correction), both of which the platform
# was already issuing.
KNOWN_PROTOCOLS = {"ZCC-v0.1", "ZHF-v0.1", "ZCC-Estimate-v0.1", "ZCC-Estimate-v0.2", "ZQEC-v0.1"}

#: Outcome labels: bitstrings, with a space between classical registers when a
#: circuit has more than one ("1000110 1000010"), the empty string when a circuit
#: measured no bits (0.1.0 accepted it, and a certificate stores one), or Fock
#: states from a photonic run ("|2,0,0>": photons per mode).
_BITSTRING_RE = re.compile(r"\A([01]+( [01]+)*)?\Z")
_FOCK_RE = re.compile(r"\A\|\d+(,\d+)*>\Z")

#: Two-sided 95%, as the platform uses for every interval it certifies.
_Z95 = 1.959963984540054

#: ZCC-Estimate-v0.2 widens the energy by this many standard errors before
#: stating a bound (ZKSF backend/nnqs/bound.py, K_SIGMA).
_K_SIGMA = 5.0

REQUIRED_FIELDS = (
    "cert_id",
    "protocol",
    "certificate_type",
    "engine",
    "method",
    "circuit_sha256",
    "created_at",
    "verify_url",
)

# Fields that must never appear. A certificate is meant to be publishable
# without exposing the account that produced it or the circuit that was run,
# so a third party should be able to confirm that for themselves.
FORBIDDEN_FIELDS = (
    "user_sub",
    "charged_micro",
    "qasm2",
    "email",
    "balance_usd",
    "braket_task_arn",
    "runpod_job_id",
)

PASS, FAIL, SKIP = "pass", "fail", "skip"

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str = ""

    def __str__(self) -> str:
        mark = {PASS: "ok  ", FAIL: "FAIL", SKIP: "  - "}[self.status]
        return f"[{mark}] {self.name}" + (f": {self.detail}" if self.detail else "")


@dataclass
class Report:
    cert_id: str
    protocol: str
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.status != FAIL for c in self.checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == FAIL]

    def __str__(self) -> str:
        head = f"certificate {self.cert_id} ({self.protocol})"
        body = "\n".join(f"  {c}" for c in self.checks)
        tail = (
            "  consistent: the stated bound follows from the stated measurement"
            if self.ok
            else f"  INCONSISTENT: {len(self.failures)} check(s) failed"
        )
        return f"{head}\n{body}\n{tail}"


def fetch(cert_id: str, base_url: str = DEFAULT_BASE_URL, timeout: float = 30.0) -> dict:
    """Read a public certificate record. No authentication, no account."""
    url = f"{base_url.rstrip('/')}/certify/{cert_id}/json"
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
        return json.load(resp)


def _close(a: float, b: float) -> bool:
    # Both sides come from the same float arithmetic, so exact agreement is the
    # normal case; the tolerance is for records that made a round trip through
    # a JSON encoder that shortened the representation.
    return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-15)


def verify(rec: dict) -> Report:
    """Check a certificate record against the invariants of its own protocol."""
    report = Report(
        cert_id=str(rec.get("cert_id", "<missing>")),
        protocol=str(rec.get("protocol", "<missing>")),
    )
    add = report.checks.append

    missing = [f for f in REQUIRED_FIELDS if not rec.get(f)]
    add(
        Check("required fields present", FAIL, f"missing {', '.join(missing)}")
        if missing
        else Check("required fields present", PASS)
    )

    protocol = rec.get("protocol")
    add(
        Check("protocol recognised", PASS, str(protocol))
        if protocol in KNOWN_PROTOCOLS
        else Check(
            "protocol recognised",
            FAIL,
            f"{protocol!r} is not one of {sorted(KNOWN_PROTOCOLS)}; this checker "
            f"cannot confirm invariants it does not know",
        )
    )

    leaked = [f for f in FORBIDDEN_FIELDS if f in rec]
    add(
        Check("carries no account or circuit data", FAIL, f"found {', '.join(leaked)}")
        if leaked
        else Check("carries no account or circuit data", PASS)
    )

    digest = rec.get("circuit_sha256", "")
    add(
        Check("circuit identified by SHA-256", PASS)
        if _SHA256_RE.match(str(digest))
        else Check("circuit identified by SHA-256", FAIL, f"not a SHA-256 digest: {digest!r}")
    )

    try:
        datetime.fromisoformat(str(rec.get("created_at", "")))
        add(Check("issued-at timestamp parses", PASS, str(rec.get("created_at"))))
    except ValueError:
        add(Check("issued-at timestamp parses", FAIL, repr(rec.get("created_at"))))

    shots = rec.get("shots")
    if shots is None:
        add(Check("shot count", SKIP, "no shots recorded (expectation-value run)"))
    elif isinstance(shots, int) and shots > 0:
        add(Check("shot count", PASS, str(shots)))
    else:
        add(Check("shot count", FAIL, f"not a positive integer: {shots!r}"))

    _check_outcomes(rec, add)

    if protocol == "ZHF-v0.1":
        _check_hardware(rec, add)
    elif protocol == "ZQEC-v0.1":
        _check_qec(rec, add)
    elif protocol == "ZCC-Estimate-v0.2" and not rec.get("estimated"):
        # Two kinds of run share v0.2: a zero-noise extrapolation, which marks
        # itself estimated and is checked with the other estimates below, and
        # a neural ground state, whose ceiling and floor are recomputed here.
        _check_nnqs(rec, add)
    else:
        _check_simulation(rec, add)

    return report


def _check_outcomes(rec: dict, add) -> None:
    outcomes = rec.get("top_outcomes")
    if not outcomes:
        add(Check("measured outcomes", SKIP, "none recorded"))
        return
    try:
        total = sum(int(count) for _, count in outcomes)
        labels = [str(bits) for bits, _ in outcomes]
    except (TypeError, ValueError):
        add(Check("measured outcomes", FAIL, "malformed top_outcomes"))
        return
    if any(not (_BITSTRING_RE.match(b) or _FOCK_RE.match(b)) for b in labels):
        add(Check("measured outcomes", FAIL, "outcome labels are neither bitstrings nor Fock states"))
        return
    shots = rec.get("shots")
    # top_outcomes is a truncated list, so it can hold fewer shots than were
    # taken, but never more.
    if isinstance(shots, int) and total > shots:
        add(
            Check(
                "measured outcomes",
                FAIL,
                f"reported outcomes total {total} shots but the run took {shots}",
            )
        )
        return
    add(Check("measured outcomes", PASS, f"{len(labels)} outcomes, {total} shots shown"))


def _check_hardware(rec: dict, add) -> None:
    """ZHF-v0.1: a fidelity against the exact ideal, or an explicit statement
    that direct verification was not available. Never a silent absence."""
    mode = rec.get("fidelity_mode")
    photonic = mode == "direct, conditioned on full photon detection"
    if mode not in {"direct", "unavailable"} and not photonic:
        add(Check("fidelity mode declared", FAIL, f"unexpected mode {mode!r}"))
        return
    add(Check("fidelity mode declared", PASS, str(mode)))
    if photonic:
        _check_photonic(rec, add)

    fidelity = rec.get("fidelity")
    if mode == "unavailable":
        # The honest case: too large to verify classically. It must then decline
        # to report a figure rather than produce one.
        if fidelity is None:
            add(Check("no fidelity claimed without a reference", PASS, str(rec.get("note", ""))[:80]))
        else:
            add(
                Check(
                    "no fidelity claimed without a reference",
                    FAIL,
                    f"mode is 'unavailable' yet a fidelity of {fidelity} is reported",
                )
            )
        return

    if not isinstance(fidelity, (int, float)):
        add(Check("fidelity is a number", FAIL, repr(fidelity)))
    elif 0.0 <= fidelity <= 1.0:
        add(Check("fidelity within [0, 1]", PASS, f"{fidelity}"))
    else:
        add(Check("fidelity within [0, 1]", FAIL, f"{fidelity} is outside the valid range"))


def _check_simulation(rec: dict, add) -> None:
    """ZCC-v0.1: recompute the declared bound from the measured quantity.

    This is the check that does real work. Everything else confirms the record
    is well formed; this one confirms the arithmetic it asserts.
    """
    bound = rec.get("error_bound")

    if rec.get("exact"):
        # An exact engine approximates nothing, so a nonzero bound would
        # contradict the claim being made.
        if bound in (None, 0, 0.0):
            add(Check("exact run declares no approximation error", PASS))
        else:
            add(
                Check(
                    "exact run declares no approximation error",
                    FAIL,
                    f"claims to be exact yet reports an error bound of {bound}",
                )
            )
        return

    if rec.get("estimated"):
        # ZCC-Estimate: an extrapolated value with an uncertainty. There is no
        # closed-form relation to recompute, by construction. What it must
        # declare about itself is checkable: it is not a certified bound, its
        # uncertainty is one standard deviation, and that uncertainty is not negative.
        if rec.get("certified") is not None:
            add(Check("estimate does not claim to be certified", PASS if rec.get("certified") is False else FAIL,
                      "" if rec.get("certified") is False else "an extrapolated estimate is marked certified"))
        if rec.get("sigma_level") is not None:
            add(Check("uncertainty stated at one sigma", PASS if rec.get("sigma_level") == 1 else FAIL,
                      f"sigma_level {rec.get('sigma_level')!r}"))
        if bound is not None:
            ok = isinstance(bound, (int, float)) and bound >= 0
            add(Check("uncertainty is not negative", PASS if ok else FAIL, f"{bound!r}"))
        add(
            Check(
                "bound recomputed from the measurement",
                SKIP,
                "extrapolated estimate: an uncertainty, not a derived bound",
            )
        )
        return

    if bound is None:
        add(Check("bound recomputed from the measurement", SKIP, "no bound reported"))
    elif not isinstance(bound, (int, float)) or not 0.0 <= bound <= 1.0:
        add(
            Check(
                "bound is a probability",
                FAIL,
                f"{bound!r} is not a value in [0, 1]; a bound on an outcome "
                f"probability cannot exceed 1",
            )
        )
        return
    else:
        add(Check("bound is a probability", PASS, f"{bound}"))

    weight = rec.get("truncation_weight")
    mass = rec.get("truncated_coefficient_mass")

    if weight is not None:
        # MPS: bound = min(1, sqrt(2*eps)), eps read off the unnormalized state.
        expected = min(1.0, math.sqrt(2.0 * float(weight)))
        if bound is not None and _close(float(bound), expected):
            add(
                Check(
                    "bound recomputed from the measurement",
                    PASS,
                    f"sqrt(2 x {weight:g}) = {expected:g}",
                )
            )
        else:
            add(
                Check(
                    "bound recomputed from the measurement",
                    FAIL,
                    f"discarded weight {weight!r} implies a bound of {expected:g}, "
                    f"but {bound!r} is reported",
                )
            )
        _check_converged(rec, add, threshold=1e-6)

    elif mass is not None:
        # Pauli propagation: the bound is the discarded mass itself, by the
        # triangle inequality over the truncated terms.
        if bound is not None and _close(float(bound), float(mass)):
            add(
                Check(
                    "bound recomputed from the measurement",
                    PASS,
                    f"discarded coefficient mass {mass:g}, additive",
                )
            )
        else:
            add(
                Check(
                    "bound recomputed from the measurement",
                    FAIL,
                    f"discarded mass is {mass!r} but the bound is reported as {bound!r}",
                )
            )
        _check_converged(rec, add, threshold=1e-9)

    elif rec.get("convergence_deviation") is not None:
        add(
            Check(
                "bound recomputed from the measurement",
                SKIP,
                "convergence check, which is evidence of accuracy rather than a bound",
            )
        )
    else:
        add(
            Check(
                "bound recomputed from the measurement",
                SKIP,
                "no measured quantity published to recompute from",
            )
        )


def _check_photonic(rec: dict, add) -> None:
    """A photonic hardware fidelity is conditioned on the shots where every photon
    was detected, so the record states how many those were. Recompute the share."""
    events, shots = rec.get("coincidence_events"), rec.get("shots")
    if not isinstance(events, int) or not isinstance(shots, int) or not 0 <= events <= shots:
        add(Check("coincidence events within the shots", FAIL, f"{events!r} of {shots!r}"))
        return
    add(Check("coincidence events within the shots", PASS, f"{events} of {shots}"))
    fraction, expected = rec.get("coincidence_fraction"), round(events / shots, 6)
    add(Check("coincidence fraction recomputed", PASS if isinstance(fraction, (int, float)) and _close(float(fraction), expected) else FAIL,
              f"{events}/{shots} = {expected}" + ("" if isinstance(fraction, (int, float)) and _close(float(fraction), expected)
                                                  else f", but {fraction!r} is reported")))
    raw = rec.get("fidelity_raw_unconditioned")
    if raw is not None:
        ok = isinstance(raw, (int, float)) and 0.0 <= raw <= 1.0
        add(Check("unconditioned fidelity within [0, 1]", PASS if ok else FAIL, f"{raw!r}"))


def _wilson(errors: int, shots: int, z: float = _Z95) -> tuple[float, float]:
    """Wilson's score interval, the one the platform states for every failure rate."""
    n = float(shots)
    p = errors / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, centre - half), min(1.0, centre + half)


def _check_rate(label: str, point: dict, add, *, zero: bool = False) -> bool:
    """One measured failure rate: the count, the rate it implies, its interval."""
    errors, shots = point.get("logical_errors"), point.get("shots")
    rate, interval = point.get("logical_error_rate"), point.get("confidence_interval_95")
    if not isinstance(errors, int) or not isinstance(shots, int) or shots <= 0 or not 0 <= errors <= shots:
        add(Check(f"{label}: failures within the shots", FAIL, f"{errors!r} of {shots!r}"))
        return False
    problems = []
    if zero and errors != 0:
        problems.append(f"a point left out of the fit must have no failures, has {errors}")
    if not isinstance(rate, (int, float)) or not _close(float(rate), errors / shots):
        problems.append(f"rate {rate!r} is not {errors}/{shots}")
    lo, hi = _wilson(errors, shots)
    if not (isinstance(interval, (list, tuple)) and len(interval) == 2
            and _close(float(interval[0]), lo) and _close(float(interval[1]), hi)):
        problems.append(f"interval {interval!r}, Wilson gives [{lo:.6g}, {hi:.6g}]")
    add(Check(f"{label}: rate and 95% interval recomputed", FAIL if problems else PASS,
              "; ".join(problems) or f"{errors} of {shots}, [{lo:.3g}, {hi:.3g}]"))
    return not problems


def _fit(points: list[tuple[float, float]]) -> tuple[float, float]:
    """Least squares of ln(rate) on (d + 1) / 2: the suppression factor and its prefactor."""
    xs, ys = [x for x, _ in points], [math.log(r) for _, r in points]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return math.exp(-slope), math.exp(my - slope * mx)


def _check_qec(rec: dict, add) -> None:
    """ZQEC-v0.1: every number is a measured failure rate with its interval, or is
    fitted to those rates and labelled as fitted. Each is recomputed."""
    kind = rec.get("certificate_type")
    if kind == "Logical Error Rate":
        _check_rate("logical error rate", {**rec, "shots": rec.get("shots")}, add)
        return
    if kind != "Logical Error Suppression":
        add(Check("error-correction certificate type", FAIL, f"unknown type {kind!r}"))
        return
    measured, excluded = rec.get("measured_points") or [], rec.get("excluded_points") or []
    ok = all([_check_rate(f"distance {p.get('distance')}", p, add) for p in measured]
             + [_check_rate(f"distance {p.get('distance')} (no failures)", p, add, zero=True) for p in excluded])
    lam, prefactor, span = rec.get("suppression_factor"), rec.get("suppression_prefactor"), rec.get("suppression_factor_range")
    if len(measured) < 2 or not ok:
        add(Check("suppression factor recomputed", SKIP if ok else FAIL,
                  "fewer than two measured distances" if ok else "the measured points did not check out"))
        return
    xs = [(p["distance"] + 1) / 2 for p in measured]
    want_lam, want_pre = _fit([(x, float(p["logical_error_rate"])) for x, p in zip(xs, measured)])
    good = isinstance(lam, (int, float)) and _close(float(lam), want_lam)
    add(Check("suppression factor recomputed", PASS if good else FAIL,
              f"least squares gives {want_lam:.6g}" + ("" if good else f", but {lam!r} is reported")))
    if prefactor is not None:
        good = _close(float(prefactor), want_pre)
        add(Check("prefactor recomputed", PASS if good else FAIL,
                  f"least squares gives {want_pre:.6g}" + ("" if good else f", but {prefactor!r} is reported")))
    # The range: every least-squares line through rates inside each distance's
    # interval, each widened to 1 - 0.05/k so all k hold together at 95%.
    k = len(measured)
    z = NormalDist().inv_cdf(1 - 0.025 / k)
    ends = [_wilson(p["logical_errors"], p["shots"], z) for p in measured]
    mx = sum(xs) / k
    low = _fit([(x, hi if x > mx else lo) for x, (lo, hi) in zip(xs, ends)])[0]
    high = _fit([(x, lo if x > mx else hi) for x, (lo, hi) in zip(xs, ends)])[0]
    good = (isinstance(span, (list, tuple)) and len(span) == 2
            and _close(float(span[0]), low) and _close(float(span[1]), high))
    add(Check("suppression factor range recomputed", PASS if good else FAIL,
              f"[{low:.4g}, {high:.4g}] at joint 95%" + ("" if good else f", but {span!r} is reported")))
    if good and isinstance(lam, (int, float)):
        inside = low <= float(lam) <= high
        add(Check("fitted factor lies inside its range", PASS if inside else FAIL, f"{lam:.4g}"))


def _check_nnqs(rec: dict, add) -> None:
    """ZCC-Estimate-v0.2: a variational energy with a ceiling and a floor on the true
    ground energy. The ceiling is the energy widened by K_SIGMA standard errors; the
    floor is Weinstein's or Temple's, both below the widened energy."""
    energy, stderr = rec.get("energy"), rec.get("energy_stderr")
    ceiling, floor = rec.get("ground_state_ceiling"), rec.get("ground_state_floor")
    if ceiling is None and floor is None:
        add(Check("energy bounds recomputed", SKIP, "no bounds recorded (a record from before they were written)"))
        return
    if not isinstance(energy, (int, float)) or not isinstance(stderr, (int, float)) or stderr < 0:
        add(Check("energy and its standard error", FAIL, f"energy {energy!r}, stderr {stderr!r}"))
        return
    widened = energy + _K_SIGMA * stderr
    good = isinstance(ceiling, (int, float)) and _close(float(ceiling), widened)
    add(Check("ceiling recomputed", PASS if good else FAIL,
              f"{energy:.6g} + {_K_SIGMA:g} x {stderr:.3g} = {widened:.6g}" + ("" if good else f", but {ceiling!r} is reported")))
    if floor is None:
        add(Check("floor", SKIP, f"no floor ({rec.get('floor_method')!r})"))
        return
    method, variance = rec.get("floor_method"), rec.get("energy_variance")
    below = energy - _K_SIGMA * stderr
    if method == "weinstein" and isinstance(variance, (int, float)) and variance >= 0:
        # Weinstein widens the variance too, so the floor sits at or below this.
        limit = below - math.sqrt(variance)
        add(Check("Weinstein floor consistent", PASS if floor <= limit + 1e-12 * max(1.0, abs(limit)) else FAIL,
                  f"{floor:.6g} <= {limit:.6g}"))
    elif method == "temple":
        add(Check("Temple floor consistent", PASS if floor <= below + 1e-12 * max(1.0, abs(below)) else FAIL,
                  f"{floor:.6g} <= {below:.6g}"))
    else:
        add(Check("floor method", FAIL, f"unknown or incomplete: {method!r}, variance {variance!r}"))
    add(Check("floor below ceiling", PASS if isinstance(ceiling, (int, float)) and floor <= ceiling else FAIL,
              f"{floor:.6g} <= {ceiling!r}"))
    add(Check("floor stated as conditional", PASS if rec.get("floor_is_conditional") is True else FAIL,
              repr(rec.get("floor_is_conditional"))))


def _check_converged(rec: dict, add, threshold: float) -> None:
    """The converged flag is derived, so it is checkable. The two engines use
    different thresholds, which is why the caller passes one in."""
    converged = rec.get("converged")
    bound = rec.get("error_bound")
    if converged is None or bound is None:
        add(Check("converged flag consistent with the bound", SKIP))
        return
    expected = float(bound) < threshold
    add(
        Check("converged flag consistent with the bound", PASS, f"{converged}")
        if bool(converged) is expected
        else Check(
            "converged flag consistent with the bound",
            FAIL,
            f"bound {bound:g} against a {threshold:g} threshold implies "
            f"converged={expected}, but {converged} is recorded",
        )
    )


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="zcc-verify",
        description=(
            "Check a ZKSF certificate (ZCC-v0.1, ZHF-v0.1, ZCC-Estimate-v0.1/v0.2, "
            "ZQEC-v0.1) for internal consistency."
        ),
        epilog=(
            "Confirms that a certificate's stated bound follows from its own stated "
            "measurement. Does not, and cannot, confirm that the measurement itself "
            "was honestly made."
        ),
    )
    parser.add_argument("target", help="a certificate id, or a path to a JSON record")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args(argv)

    import pathlib

    path = pathlib.Path(args.target)
    if path.is_file():
        rec = json.loads(path.read_text(encoding="utf-8"))
    else:
        rec = fetch(args.target, base_url=args.base_url)

    report = verify(rec)
    print(report)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
