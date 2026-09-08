"""PermitMesh: deterministic capability contracts for workspace agents."""

from .conformance import run_conformance
from .policy import (
    IMPLEMENTATION_VERSION,
    Decision,
    authorize,
    contract_digest,
    operation_digest,
    validate_contract,
    verify_completion,
)

__all__ = [
    "Decision",
    "authorize",
    "contract_digest",
    "operation_digest",
    "run_conformance",
    "validate_contract",
    "verify_completion",
]
__version__ = IMPLEMENTATION_VERSION
