"""Fake patient ids from HMAC-SHA256. The secret stays in the environment.

The same normalized name always produces the same id. The id cannot be
turned back into the name without RAKSHA_SECRET.
"""

from __future__ import annotations

import hashlib
import hmac
import os

_ENV = "RAKSHA_SECRET"


def patient_id(canonical: str) -> str:
    """Return PSN- plus the first 6 hex characters of the HMAC.

    canonical is the normalized name for one person, not the raw record.
    """
    if not canonical.strip():
        raise ValueError("cannot build a patient id from an empty name")
    secret = os.environ.get(_ENV, "").strip()
    if not secret:
        raise ValueError("RAKSHA_SECRET is not set")
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "PSN-" + digest[:6]
