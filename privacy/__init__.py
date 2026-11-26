"""Privacy stage: generalize dates and ages. Clinical fields stay put."""

from privacy.assess import assess
from privacy.generalize import generalize

__all__ = ["assess", "generalize"]
