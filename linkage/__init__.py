"""Linkage stage: cluster the same patient and assign one fake id."""

from linkage.cluster import assign_patients
from linkage.link import link

__all__ = ["assign_patients", "link"]
