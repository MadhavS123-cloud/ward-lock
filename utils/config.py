"""Load the local submission file and privacy policy."""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

PROJECT_ROOT_NAME = "ward-lock"


def load_raksha(path: Path) -> dict:
    """Read raksha.toml. It only names the local submission entrypoint."""
    config_path = path.resolve()
    if not config_path.is_file():
        raise FileNotFoundError(f"raksha config not found: {config_path}")

    with config_path.open("rb") as handle:
        config = tomllib.load(handle)

    submission = _section(config, "submission")
    if submission.get("name") != PROJECT_ROOT_NAME:
        raise ValueError("raksha.toml [submission].name must be 'ward-lock'")
    return config


def load_policy(path: Path) -> dict:
    """Read the privacy policy and require the same offline limits."""
    policy_path = path.resolve()
    if not policy_path.is_file():
        raise FileNotFoundError(f"policy not found: {policy_path}")

    loaded = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("policy.yaml must be a mapping")

    if loaded.get("offline") is not True or loaded.get("cpu_only") is not True:
        raise ValueError("policy.yaml must set offline: true and cpu_only: true")
    if loaded.get("llm") is not False:
        raise ValueError("policy.yaml must set llm: false")
    if loaded.get("scope") != "synthetic_indian_hospital_records":
        raise ValueError("policy.yaml scope must be synthetic_indian_hospital_records")

    _string_list(loaded, "direct_identifiers")
    _string_list(loaded, "quasi_identifiers")

    pseudonym = loaded.get("pseudonym")
    if not isinstance(pseudonym, dict):
        raise ValueError("policy.yaml pseudonym must be a mapping")
    if pseudonym.get("method") != "hmac-sha256" or pseudonym.get("reversible") is not False:
        raise ValueError("pseudonyms must be local hmac-sha256 and non-reversible")

    privacy = loaded.get("privacy")
    if not isinstance(privacy, dict):
        raise ValueError("policy.yaml privacy must be a mapping")
    k_value = privacy.get("k_anonymity")
    if not isinstance(k_value, int) or isinstance(k_value, bool) or k_value < 2:
        raise ValueError("policy.yaml privacy.k_anonymity must be an integer >= 2")
    if privacy.get("suppress_below_k") is not True:
        raise ValueError("policy.yaml privacy.suppress_below_k must be true")

    sanitizer = loaded.get("sanitizer")
    if not isinstance(sanitizer, dict):
        raise ValueError("policy.yaml sanitizer must be a mapping")
    for key in ("direct_identifiers", "unclassified_spans"):
        if sanitizer.get(key) != "redact":
            raise ValueError(f"policy.yaml sanitizer.{key} must be 'redact'")

    return loaded


def _section(config: dict, name: str) -> dict:
    section = config.get(name)
    if not isinstance(section, dict):
        raise ValueError(f"raksha.toml is missing [{name}]")
    return section


def _string_list(policy: dict, key: str) -> None:
    values = policy.get(key)
    if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values):
        raise ValueError(f"policy.yaml {key} must be a non-empty list of names")
