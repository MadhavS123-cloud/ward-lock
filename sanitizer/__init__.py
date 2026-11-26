"""Sanitizer stage: remove names, phones, emails, and ids before writing."""

from sanitizer.sanitize import sanitize

__all__ = ["sanitize"]
