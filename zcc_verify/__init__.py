"""Independent checker for ZCC-v0.1 / ZHF-v0.1 accuracy certificates.

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

__version__ = "0.1.0"

DEFAULT_BASE_URL = "https://api.zksf.org"

# Protocols this checker understands. An unknown protocol is reported rather
# than assumed to be fine: a future ZCC-v0.2 may carry invariants this version
# knows nothing about, and silently passing it would be the wrong answer.
KNOWN_PROTOCOLS = {"ZCC-v0.1", "ZHF-v0.1", "ZCC-Estimate-v0.1"}

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
    if any(not set(b) <= {"0", "1"} for b in labels):
        add(Check("measured outcomes", FAIL, "outcome labels are not bitstrings"))
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
    if mode not in {"direct", "unavailable"}:
        add(Check("fidelity mode declared", FAIL, f"unexpected mode {mode!r}"))
        return
    add(Check("fidelity mode declared", PASS, str(mode)))

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
        # closed-form relation to recompute, by construction.
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
        description="Check a ZCC-v0.1 / ZHF-v0.1 certificate for internal consistency.",
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
