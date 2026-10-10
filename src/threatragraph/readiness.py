"""Conservative, machine-readable experiment-readiness disclosure.

Passing format, review, content-integrity or pilot-count gates does *not*
authenticate publisher release dates, real-case selection, reviewer identity,
label separation or scientific reproducibility. These modules cannot verify
those independent approvals and must therefore NEVER claim research readiness.

A future signed-off research acceptance protocol needs an independent,
versioned approval gate, paired-run freeze and gold-label isolation before
any production result may report research_ready=True.
"""
from __future__ import annotations

READINESS_CONTRACT_VERSION = "research-readiness-v1"
PENDING_REASON = (
    "Structural checks passed, but independent historical source/date/rights "
    "approval, case selection, reviewer independence, temporal feature "
    "reconstruction, paired predictions and held-out evaluation have not "
    "been established by this executable."
)


def readiness_disclosure(*, development_only: bool) -> dict:
    """Disclosure for *successful* structural operations only.

    This never grants scientific approval even if a synthetic fixture matches
    the full study's case/source counts and includes fabricated review records.
    """
    if type(development_only) is not bool:
        raise ValueError("development_only must be a boolean")
    return {
        "readiness_contract_version": READINESS_CONTRACT_VERSION,
        "structural_checks_passed": True,
        "validation_mode": "development_only" if development_only else "strict_structural",
        "independent_study_approval": "not_verified",
        "empirical_evaluation": "not_performed",
        "research_ready": False,
        "reason": PENDING_REASON,
    }
