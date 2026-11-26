"""Replace direct identifiers with local, non-reversible pseudonyms."""

from __future__ import annotations


def pseudonymize(records: list[dict], policy: dict) -> list[dict]:
    """Apply hmac-sha256 pseudonyms. Not implemented yet."""
    del policy
    return records
