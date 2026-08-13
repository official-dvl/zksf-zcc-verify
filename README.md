# zcc-verify

[![CI](https://github.com/official-dvl/zksf-zcc-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/official-dvl/zksf-zcc-verify/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zcc-verify.svg?v=2)](https://pypi.org/project/zcc-verify/)
[![Python](https://img.shields.io/pypi/pyversions/zcc-verify.svg?v=2)](https://pypi.org/project/zcc-verify/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21851381-blue.svg)](https://doi.org/10.5281/zenodo.21851381)

Independent consistency checker for **ZCC-v0.1** and **ZHF-v0.1** quantum simulation
accuracy certificates.

No dependencies. Python 3.10+.

```bash
pip install zcc-verify
zcc-verify fe529e21d7404ff3
```

```
certificate fe529e21d7404ff3 (ZCC-v0.1)
  [ok  ] required fields present
  [ok  ] protocol recognised: ZCC-v0.1
  [ok  ] carries no account or circuit data
  [ok  ] circuit identified by SHA-256
  [ok  ] issued-at timestamp parses: 2026-07-09T13:20:03+00:00
  [ok  ] shot count: 512
  [ok  ] measured outcomes: 2 outcomes, 512 shots shown
  [ok  ] bound is a probability: 2.1073424255447017e-08
  [ok  ] bound recomputed from the measurement: sqrt(2 x 2.22045e-16) = 2.10734e-08
  [ok  ] converged flag consistent with the bound: True
  consistent: the stated bound follows from the stated measurement
```

Exit status is 0 when every check passes and 1 when any fails, so it drops into CI.

## Why this exists

Classical simulation of quantum circuits is exact only in a narrow regime. Exact
statevector methods terminate near 30 to 32 qubits, because state size grows as `2^n`.
Beyond that every practical method is approximate: tensor networks truncate the bond
dimension, Pauli propagation truncates operator weight, and real hardware substitutes
device noise for the ideal distribution.

An approximate result without an error statement is not a measurement, it is an
assertion. **ZCC-v0.1** and **ZHF-v0.1** are small versioned protocols that attach a
machine-checkable accuracy statement to a result. This tool is the checker: it takes a
certificate and confirms the claim it makes follows from the measurement it reports.

The protocols are specified in a citable paper:

> Reporting the Accuracy of Approximate Quantum Circuit Simulation: A Machine-Checkable
> Certificate Format. [doi.org/10.5281/zenodo.21851381](https://doi.org/10.5281/zenodo.21851381)

## What this establishes

The load-bearing check recomputes the declared bound from the measured quantity the
certificate itself reports, and requires the two to agree:

| Method | Reported quantity | Bound must equal |
|---|---|---|
| Matrix product state | discarded SVD weight `eps` | `min(1, sqrt(2 * eps))` |
| Pauli propagation | discarded coefficient mass | the mass itself (additive) |
| Exact / stabilizer | nothing discarded | zero |
| Hardware (ZHF-v0.1) | Hellinger fidelity vs. the exact ideal | within `[0, 1]`, or explicitly declined |

It also checks that the record is well formed, that the `converged` flag agrees with the
bound (the two methods use different thresholds), that outcome counts do not exceed the
shot count, and that no account data or circuit source is present.

A certificate whose stated bound does not follow from its own stated inputs fails here,
whoever issued it.

## What this does not establish

**It does not establish that the measurement was honest.** The discarded weight in a
tensor-network certificate, and the coefficient mass in a Pauli one, are produced by
whoever ran the simulation. No arithmetic on the record can confirm that the number
reported is the number that was measured.

Verifying a certificate is not the same as trusting the issuer. What it gives you is
narrower and still worth having: the claim is well formed, self-consistent, and stated
in a form somebody else can check.

## Use as a library

```python
from zcc_verify import fetch, verify

report = verify(fetch("df1d4c698a954051"))
print(report.ok)                          # True
print([c.name for c in report.failures])  # []
```

`fetch()` reads the public record at `https://api.zksf.org/certify/<id>/json`. It needs
no authentication and no account. `verify()` takes a plain dict, so a record from any
source, including a local file or a different issuer, can be checked:

```bash
zcc-verify ./certificate.json
```

Four live certificates to try, covering every accuracy regime the protocols describe:

| Certificate | Run |
|---|---|
| `d904e28af0b441e0` | 3-qubit GHZ, exact stabilizer simulation |
| `fe529e21d7404ff3` | 12-qubit GHZ, tensor network, measured bound of 2.11e-08 |
| `5b8b2c4309d44d41` | 192-qubit GHZ, Pauli propagation |
| `df1d4c698a954051` | Bell state on IonQ Forte-1 hardware, 0.977 fidelity |

## On the limits of the bound

The certified bound is an empirical result rather than a theorem. It held across 334
runs at sizes where the exact answer is computable, 290 of them constructed specifically
to break it, approaching at closest 49 percent of its value. Above 20 qubits it cannot
be checked by direct comparison and no such evidence exists. Where a hard ceiling is
required, use an exact or stabilizer engine.

The paper is explicit about the case in which the motivating derivation does not extend:
in deep sequential circuits the accumulated truncation weight has been measured
understating the true infidelity by up to a factor of seven. It also shows, by explicit
counterexample, that a natural tightening of the bound is unsound.

## Where these certificates come from

[ZKSF (Zero Kelvin Simulation Foundry)](https://zksf.org) runs quantum circuits on
classical simulators, GPU accelerators, or real quantum processors, and attaches one of
these accuracy statements to every approximate result.

- **Python SDK** — [`qsim-sdk`](https://pypi.org/project/qsim-sdk/) on PyPI, source at
  [official-dvl/zksf](https://github.com/official-dvl/zksf), DOI
  [10.5281/zenodo.21836619](https://doi.org/10.5281/zenodo.21836619). Accepts Qiskit
  circuits directly, and Cirq, PennyLane, pyQuil or Braket circuits via an optional
  transpiler.
- **Try it without an account** — the
  [Colab quickstart](https://colab.research.google.com/github/official-dvl/zksf/blob/main/examples/quickstart.ipynb)
  reads real completed certificates from the public API before it asks you for anything.
- **Android app** — submit a circuit and read the result from a phone, including runs on
  real quantum hardware:
  [Google Play](https://play.google.com/store/apps/details?id=com.quantumcomputing.app).
- **Protocol reference** —
  [CERTIFICATION.md](https://github.com/official-dvl/zksf/blob/main/docs/CERTIFICATION.md)
- **Documentation** — [zksf.org/docs](https://zksf.org/docs)

This checker is deliberately independent of all of the above: it has no dependency on
the SDK, needs no account, and will check a certificate issued by anyone who emits the
format.

## Licence

MIT.
