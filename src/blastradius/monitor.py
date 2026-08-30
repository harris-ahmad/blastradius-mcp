"""The watch lane.

An agent answers when asked. This notices while nobody is asking — which is the
one thing a request-response model structurally cannot do, and the reason to
keep BlastRadius installed after the novelty wears off.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Callable

import httpx

from .osv import OsvClient
from .store import Store

logger = logging.getLogger("blastradius.monitor")

CONFIG_PATH = Path.home() / ".blastradius" / "config.json"
DEFAULT_INTERVAL_HOURS = 6
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def load_config() -> dict:
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def check(
    store: Store,
    client: OsvClient | None = None,
    first_run_is_silent: bool = True,
) -> list[dict]:
    """One monitoring cycle. Returns alerts that are new *and* worth reporting.

    On a first run against an existing index every historical CVE looks new, so
    they are recorded silently rather than dumped on the user at once.
    """
    client = client or OsvClient()
    artifacts = store.monitorable_artifacts()
    if not artifacts:
        return []

    by_id = {a["id"]: a for a in artifacts}
    is_first_run = store.stats()["open_alerts"] == 0 and first_run_is_silent

    try:
        discovered = client.discover(artifacts)
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("OSV discovery failed: %s", exc)
        return []

    new_alerts: list[dict] = []
    for artifact_id, osv_ids in discovered.items():
        seen = store.seen_osv_ids(artifact_id)
        for osv_id in osv_ids:
            if osv_id in seen:
                continue
            try:
                cve = client.fetch(osv_id)
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("Could not fetch %s: %s", osv_id, exc)
                continue
            if store.add_alert(artifact_id, cve) and not is_first_run:
                artifact = by_id[artifact_id]
                # Explicit fields, not a dict merge: the artifact's integer `id`
                # would silently overwrite the advisory's OSV id.
                new_alerts.append({
                    **cve,
                    "artifact_id": artifact_id,
                    "identifier": artifact["identifier"],
                    "type": artifact["type"],
                })

    new_alerts.sort(key=lambda a: -_SEVERITY_ORDER.get(a["severity"], 0))
    return new_alerts


def format_alerts(alerts: list[dict]) -> str:
    lines = [f"BlastRadius: {len(alerts)} new advisory(ies) affecting your indexed repos", ""]
    for alert in alerts:
        ident = alert.get("cve_id") or alert["id"]
        score = f" ({alert['cvss_score']})" if alert.get("cvss_score") is not None else ""
        lines.append(f"  [{alert['severity'].upper()}{score}] {alert['identifier']} — {ident}")
        if alert.get("summary"):
            lines.append(f"      {alert['summary'][:140]}")
        if alert.get("url"):
            lines.append(f"      {alert['url']}")
    return "\n".join(lines)


def notify(alerts: list[dict], config: dict | None = None) -> None:
    """Report new alerts. Always to stdout; to Slack if a webhook is configured.

    The alerts are in the index either way — the inject hook will surface them
    the next time an agent opens a file that references the artifact.
    """
    if not alerts:
        return
    config = config if config is not None else load_config()
    print(format_alerts(alerts))

    webhook = config.get("slack_webhook_url")
    minimum = _SEVERITY_ORDER.get(config.get("notify_min_severity", "high"), 3)
    worth_sending = [a for a in alerts if _SEVERITY_ORDER.get(a["severity"], 0) >= minimum]
    if webhook and worth_sending:
        try:
            httpx.post(webhook, json={"text": format_alerts(worth_sending)}, timeout=10.0)
        except httpx.HTTPError as exc:
            logger.warning("Slack notification failed: %s", exc)


def watch(
    interval_hours: float = DEFAULT_INTERVAL_HOURS,
    store: Store | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    iterations: int | None = None,
) -> None:
    """Poll forever. `iterations` bounds the loop, for tests."""
    store = store or Store()
    config = load_config()
    count = 0
    while iterations is None or count < iterations:
        try:
            notify(check(store), config)
        except Exception as exc:  # a daemon must not die on one bad cycle
            logger.exception("Monitor cycle failed: %s", exc)
        count += 1
        if iterations is not None and count >= iterations:
            break
        sleeper(interval_hours * 3600)
