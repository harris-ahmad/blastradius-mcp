"""User control over what gets captured and what gets injected.

Two things need governing. Injection spends context on every matching read, so
it must be tunable — an infrastructure team may want Terraform noise and not npm
noise, and a quiet repo should be able to opt out entirely.

And capture writes repository names, file paths and artifact identifiers to
disk. Those are usually dull, but an internal registry hostname or a private
repo name is not nothing, so exclusions are first-class rather than an
afterthought.

Everything has a working default. An absent config file behaves exactly as
BlastRadius did before this module existed.
"""
from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(
    os.environ.get("BLASTRADIUS_CONFIG", Path.home() / ".blastradius" / "config.json")
)

ALL_TYPES = ("docker_image", "terraform_module", "github_action", "helm_chart", "npm_package")
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0, "none": 0}


@dataclass
class InjectConfig:
    enabled: bool = True
    max_artifacts: int = 8
    max_consumers: int = 5
    types: tuple[str, ...] = ALL_TYPES
    # Stay silent unless another repository shares the artifact. Turning this
    # off also surfaces CVEs on artifacts only this repo uses.
    only_when_shared: bool = True
    # Advisories below this are not worth spending injected context on.
    min_cve_severity: str = "low"
    # "compact" drops the repeated trailing instruction and inlines consumers.
    # "verbose" is the original prose form.
    format: str = "compact"
    # A repeat is only a repeat for so long. Session ids are not reliably
    # unique, so suppression expires rather than lasting forever.
    dedupe_minutes: int = 120


@dataclass
class ExcludeConfig:
    repositories: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()

    def _matches(self, value: str, patterns: tuple[str, ...]) -> bool:
        return any(fnmatch.fnmatch(value, p) for p in patterns)

    def repository(self, name: str) -> bool:
        return self._matches(name, self.repositories)

    def path(self, file_path: str) -> bool:
        return self._matches(file_path, self.paths)

    def artifact(self, identifier: str) -> bool:
        return self._matches(identifier, self.artifacts)


@dataclass
class Config:
    inject: InjectConfig = field(default_factory=InjectConfig)
    exclude: ExcludeConfig = field(default_factory=ExcludeConfig)
    slack_webhook_url: str | None = None
    notify_min_severity: str = "high"

    def severity_at_least(self, severity: str, threshold: str) -> bool:
        return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(threshold, 0)


def _as_tuple(value: Any, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return default


def load(path: Path | None = None) -> Config:
    """Read the config, falling back to defaults for anything absent or invalid.

    A broken config must never break a hook — the worst outcome is a session
    that fails on every file read because of a stray comma.
    """
    path = path or CONFIG_PATH
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return Config()
    if not isinstance(raw, dict):
        return Config()

    inject_raw = raw.get("inject") if isinstance(raw.get("inject"), dict) else {}
    defaults = InjectConfig()
    inject = InjectConfig(
        enabled=bool(inject_raw.get("enabled", defaults.enabled)),
        max_artifacts=int(inject_raw.get("max_artifacts", defaults.max_artifacts) or 0) or 1,
        max_consumers=int(inject_raw.get("max_consumers", defaults.max_consumers) or 0) or 1,
        types=tuple(t for t in _as_tuple(inject_raw.get("types"), ALL_TYPES) if t in ALL_TYPES)
        or ALL_TYPES,
        only_when_shared=bool(inject_raw.get("only_when_shared", defaults.only_when_shared)),
        min_cve_severity=str(inject_raw.get("min_cve_severity", defaults.min_cve_severity)),
        format=("verbose" if str(inject_raw.get("format", defaults.format)) == "verbose"
                else "compact"),
        dedupe_minutes=max(0, int(inject_raw.get("dedupe_minutes",
                                                 defaults.dedupe_minutes) or 0)),
    )

    exclude_raw = raw.get("exclude") if isinstance(raw.get("exclude"), dict) else {}
    exclude = ExcludeConfig(
        repositories=_as_tuple(exclude_raw.get("repositories")),
        paths=_as_tuple(exclude_raw.get("paths")),
        artifacts=_as_tuple(exclude_raw.get("artifacts")),
    )

    webhook = raw.get("slack_webhook_url")
    return Config(
        inject=inject,
        exclude=exclude,
        slack_webhook_url=str(webhook) if webhook else None,
        notify_min_severity=str(raw.get("notify_min_severity", "high")),
    )


EXAMPLE = {
    "inject": {
        "enabled": True,
        "max_artifacts": 8,
        "max_consumers": 5,
        "types": list(ALL_TYPES),
        "only_when_shared": True,
        "min_cve_severity": "low",
        "format": "compact",
        "dedupe_minutes": 120,
    },
    "exclude": {
        "repositories": ["acme/internal-*"],
        "paths": ["vendor/**", "examples/**"],
        "artifacts": ["registry.internal.*"],
    },
    "slack_webhook_url": None,
    "notify_min_severity": "high",
}
