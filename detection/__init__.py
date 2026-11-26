"""Detection stage: find personal information with local rules."""

from detection.detect import detect
from detection.engine import find_personal_info

__all__ = ["detect", "find_personal_info"]
