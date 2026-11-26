"""Rule-based identifier detection. No language models."""

from __future__ import annotations


def detect(records: list[dict], policy: dict) -> list[dict]:
    """Pass records onward. find_personal_info returns the PII list."""
    del policy
    return records
