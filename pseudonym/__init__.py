"""Pseudonym stage: local HMAC patient ids, not reversible tokens."""

from pseudonym.hmac import patient_id
from pseudonym.pseudonymize import pseudonymize

__all__ = ["patient_id", "pseudonymize"]
