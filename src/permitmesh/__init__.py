"""PermitMesh: deterministic capability contracts for workspace agents."""

from .policy import (
    Decision,
    IMPLEMENTATION_VERSION,
    authorize,
    contract_digest,
    operation_digest,
    validate_contract,
    verify_completion,
)
from .conformance import run_conformance
from .buzz import authorize_buzz, compute_buzz_context_mac, validate_buzz_context

__all__ = [
    "Decision",
    "authorize",
    "authorize_buzz",
    "compute_buzz_context_mac",
    "contract_digest",
    "operation_digest",
    "run_conformance",
    "validate_buzz_context",
    "validate_contract",
    "verify_completion",
]
__version__ = IMPLEMENTATION_VERSION
