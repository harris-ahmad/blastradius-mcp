"""blastradius — entry point for the MCP server, the hooks, and the daemon."""
from __future__ import annotations

import argparse
import json
import signal
import sys


def main() -> None:
    # `blastradius cost | head` closes the pipe early, and the default Python
    # handler turns that into a traceback on a command that worked fine.
    # Restoring the default disposition makes the process end quietly, the way
    # every other command-line tool does.
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    parser = argparse.ArgumentParser(prog="blastradius")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("serve", help="Run the MCP server on stdio.")

    hook = sub.add_parser("hook", help="Run a hook handler (reads JSON on stdin).")
    hook.add_argument("name", choices=["inject", "capture"])

    install_cmd = sub.add_parser("install", help="Wire the hooks and MCP server into Claude Code.")
    install_cmd.add_argument("--dry-run", action="store_true",
                             help="Print the merged settings instead of writing them.")
    link_cmd = sub.add_parser("link", help="Put the CLI on PATH so it works without the venv.")
    link_cmd.add_argument("--to", default=None, help="Directory to link into.")
    sub.add_parser("uninstall", help="Remove the hooks and MCP server registration.")

    service_cmd = sub.add_parser("service",
                                 help="Run the watcher in the background, across reboots.")
    service_cmd.add_argument(
        "action", choices=["install", "start", "stop", "status", "uninstall"])
    service_cmd.add_argument("--interval-hours", type=float, default=6.0)
    sub.add_parser("doctor", help="Check the wiring and prove the hooks run.")

    index_cmd = sub.add_parser(
        "index",
        help="Fill the index from repositories you already have on disk.")
    index_cmd.add_argument("directory",
                           help="Directory containing your repositories, e.g. ~/code")
    index_cmd.add_argument("--dry-run", action="store_true",
                           help="List what would be indexed, start no sessions.")
    index_cmd.add_argument("--limit", type=int, default=None,
                           help="Index at most this many repositories.")
    index_cmd.add_argument("--force", action="store_true",
                           help="Re-run even for repositories already fully indexed.")
    index_cmd.add_argument("--timeout", type=int, default=300,
                           help="Seconds to allow each session (default: 300).")

    sub.add_parser("stats", help="Show what is currently indexed.")
    check_cmd = sub.add_parser("check", help="Run one CVE check against OSV now.")
    check_cmd.add_argument("--refresh", action="store_true",
                           help="Clear recorded alerts and re-evaluate them. Use after "
                                "the applicability rules change — already-seen advisories "
                                "are otherwise skipped before the filter sees them.")

    consumers = sub.add_parser("consumers", help="Who uses an artifact, and where.")
    consumers.add_argument("identifier")
    consumers.add_argument("--type", default=None)

    hygiene_cmd = sub.add_parser("hygiene", help="Pinning report, worst first.")
    hygiene_cmd.add_argument("--type", default=None)
    hygiene_cmd.add_argument("--min-consumers", type=int, default=1)

    sub.add_parser("repos", help="List indexed repositories.")

    cost_cmd = sub.add_parser("cost", help="What injection has spent on context.")
    cost_cmd.add_argument("--days", type=int, default=None,
                          help="Limit to the last N days (default: all time).")

    config_cmd = sub.add_parser("config", help="Show or create the config file.")
    config_cmd.add_argument("--init", action="store_true",
                            help="Write a commented example config, without overwriting.")

    resolve_cmd = sub.add_parser(
        "resolve",
        help="Read lockfiles for already-indexed repos, so CVE matching is exact.")
    resolve_cmd.add_argument("paths", nargs="*",
                             help="Repository directories (default: ~/br-fixtures/*).")

    alerts_cmd = sub.add_parser("alerts", help="Open CVE alerts, and which pins they hit.")
    alerts_cmd.add_argument("--severity", default=None,
                            choices=["critical", "high", "medium", "low", "unknown"])
    alerts_cmd.add_argument("--artifact", default=None)

    watch_cmd = sub.add_parser("watch", help="Poll OSV on an interval, forever.")
    watch_cmd.add_argument("--interval-hours", type=float, default=6.0)

    args = parser.parse_args()

    if args.command == "serve":
        from .server import main as serve
        serve()

    elif args.command == "hook":
        from .hooks import run
        run(args.name)

    elif args.command == "install":
        from .install import install
        sys.exit(install(dry_run=args.dry_run))

    elif args.command == "link":
        from .install import link
        sys.exit(link(args.to))

    elif args.command == "uninstall":
        from .install import uninstall
        sys.exit(uninstall())

    elif args.command == "service":
        from . import service
        if args.action == "install":
            sys.exit(service.install(args.interval_hours))
        if args.action == "uninstall":
            sys.exit(service.uninstall())
        if args.action == "stop":
            sys.exit(service.stop())
        if args.action == "start":
            sys.exit(service.start())
        sys.exit(service.status())

    elif args.command == "doctor":
        from .install import doctor
        sys.exit(doctor())

    elif args.command == "index":
        from .bootstrap import index
        sys.exit(index(args.directory, dry_run=args.dry_run, limit=args.limit,
                       timeout=args.timeout, force=args.force))

    elif args.command == "stats":
        from .store import Store
        json.dump(Store().stats(), sys.stdout, indent=2)
        sys.stdout.write("\n")

    elif args.command == "consumers":
        from .server import blast_radius
        json.dump(blast_radius(args.identifier, type=args.type), sys.stdout, indent=2)
        sys.stdout.write("\n")

    elif args.command == "hygiene":
        from .server import hygiene
        json.dump(hygiene(type=args.type, min_consumers=args.min_consumers),
                  sys.stdout, indent=2)
        sys.stdout.write("\n")

    elif args.command == "repos":
        from .store import Store
        seen: dict[str, int] = {}
        for row in Store().all_dependencies():
            seen[row["repository"]] = seen.get(row["repository"], 0) + 1
        for name, count in sorted(seen.items()):
            print(f"{count:5d}  {name}")
        if not seen:
            print("Nothing indexed yet.")

    elif args.command == "cost":
        from .store import Store
        stats = Store().injection_stats(args.days)
        if not stats["sent"] and not stats["suppressed"]:
            print("No injections recorded yet.")
            return

        # Claude's tokenizer is not available locally, so this is an estimate.
        # ~3.8 chars/token suits this content — paths, versions and punctuation
        # tokenize denser than prose.
        def tok(chars): return round(chars / 3.8)

        window = f"last {args.days} day(s)" if args.days else "all time"
        print(f"Injection cost, {window}\n")
        print(f"  {stats['sent']} injection(s) across {stats['sessions']} session(s)")
        print(f"  {stats['characters']:,} characters  ≈ {tok(stats['characters']):,} tokens")
        if stats["sent"]:
            per = stats["characters"] / stats["sent"]
            print(f"  {per:.0f} characters each  ≈ {tok(per):.0f} tokens")
        if stats["suppressed"]:
            saved = stats["sent"] and (stats["characters"] / stats["sent"]) * stats["suppressed"]
            print(f"\n  {stats['suppressed']} repeat(s) suppressed within a session")
            print(f"  ≈ {tok(saved):,.0f} tokens not spent re-telling the same thing")

        if stats["by_repository"]:
            print("\n  By repository")
            for row in stats["by_repository"]:
                print(f"    {row['chars']:>8,} ch  ≈{tok(row['chars']):>6,} tok  "
                      f"{row['sent']:>3}x  {row['repository']}")
        if stats["by_file"]:
            print("\n  Most expensive files")
            for row in stats["by_file"][:5]:
                print(f"    {row['chars']:>8,} ch  {row['sent']:>3}x  "
                      f"{row['repository']}:{row['file_path']}")
        print("\n  Token counts are estimates — Claude's tokenizer is not "
              "available locally.")
        print("  Tune with: blastradius config  (max_artifacts, max_consumers, types)")

    elif args.command == "config":
        from .config import CONFIG_PATH, EXAMPLE, load
        if args.init:
            if CONFIG_PATH.exists():
                print(f"{CONFIG_PATH} already exists — not overwriting.")
            else:
                CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
                CONFIG_PATH.write_text(json.dumps(EXAMPLE, indent=2) + "\n")
                print(f"Wrote {CONFIG_PATH}")
            return
        active = load()
        print(f"# {CONFIG_PATH}"
              f"{'' if CONFIG_PATH.exists() else '  (absent — showing defaults)'}")
        json.dump({
            "inject": {
                "enabled": active.inject.enabled,
                "max_artifacts": active.inject.max_artifacts,
                "max_consumers": active.inject.max_consumers,
                "types": list(active.inject.types),
                "only_when_shared": active.inject.only_when_shared,
                "min_cve_severity": active.inject.min_cve_severity,
                "format": active.inject.format,
                "dedupe_minutes": active.inject.dedupe_minutes,
            },
            "exclude": {
                "repositories": list(active.exclude.repositories),
                "paths": list(active.exclude.paths),
                "artifacts": list(active.exclude.artifacts),
            },
            "notify_min_severity": active.notify_min_severity,
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")

    elif args.command == "resolve":
        from pathlib import Path
        from .lockfile import npm_resolved_versions
        from .repo import resolve_repository
        from .store import Store

        store = Store()
        paths = [Path(p) for p in args.paths] or sorted(
            p for p in (Path.home() / "br-fixtures").glob("*") if (p / ".git").exists()
        )
        if not paths:
            print("No repositories given, and nothing found in ~/br-fixtures.")
            return
        total = 0
        for path in paths:
            name = resolve_repository(path)
            resolved = npm_resolved_versions(path)
            if not resolved:
                # Name what was looked for: the usual causes are a pnpm project
                # (unsupported), a repo with no JS at all, or dependencies that
                # were never installed.
                print(f"  {name}: no package-lock.json or yarn.lock under {path}")
                if (path / "pnpm-lock.yaml").exists():
                    print("     found pnpm-lock.yaml, which is not supported yet")
                continue
            updated = store.apply_resolved_versions(name, resolved)
            total += updated
            print(f"  {name}: {updated} reference(s) pinned from "
                  f"{len(resolved)} lockfile entry(ies)")
        if total:
            print(f"\n{total} reference(s) now carry a resolved version.")
            print("Re-evaluate the alerts against them:  blastradius check --refresh")

    elif args.command == "alerts":
        from .store import Store
        store = Store()
        rows = store.list_alerts(severity=args.severity, identifier=args.artifact)
        if not rows:
            print("No open alerts.")
            return
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

        # OSV often carries several advisory records for one CVE — a later
        # re-analysis alongside the original. Collapse them, but keep the union
        # of the pins they reach: the records can disagree about whether a fix
        # exists, and that disagreement is the useful part.
        grouped: dict[tuple[str, str], dict] = {}
        for row in rows:
            key = (row["identifier"], row["cve_id"] or row["osv_id"])
            entry = grouped.get(key)
            if entry is None:
                grouped[key] = {**row, "records": 1,
                                "reaches": set((row["applies_to"] or "").split(", ")) - {""}}
                continue
            entry["records"] += 1
            entry["reaches"] |= set((row["applies_to"] or "").split(", ")) - {""}
            if order.get(row["severity"], 4) < order.get(entry["severity"], 4):
                entry["severity"] = row["severity"]
                entry["summary"] = row["summary"]

        consumer_cache: dict[tuple[str, str], list] = {}
        merged = sorted(grouped.values(),
                        key=lambda r: (order.get(r["severity"], 4), r["identifier"]))
        for row in merged:
            ident = row["cve_id"] or row["osv_id"]
            extra = f"  ({row['records']} advisory records)" if row["records"] > 1 else ""
            print(f"[{row['severity'].upper():8}] {row['identifier']:<22} {ident}{extra}")
            print(f"           {row['summary'][:88]}")
            reaches = sorted(row["reaches"])
            # Which repositories are actually exposed. Without this the listing
            # names a version spec and leaves you to go look up who pins it —
            # in a cross-repo tool that is the wrong half of the answer.
            key = (row["identifier"], row["type"])
            if key not in consumer_cache:
                consumer_cache[key] = store.consumers(row["identifier"], row["type"])
            # Match on the same label the filter used: a lockfile-resolved
            # version where one exists, the spec otherwise. Comparing against
            # the spec alone drops any repo whose alert was matched by its
            # resolved version — under-reporting who is exposed.
            exposed = sorted({
                c["repository"] for c in consumer_cache[key]
                if not reaches
                or (c.get("resolved_version") or c["version_spec"] or "(unpinned)") in reaches
            })
            label = ", ".join(reaches) or "(recorded before filtering)"
            exact = all(not any(ch in r for ch in "^~><*") for r in reaches) if reaches else False
            print(f"           reaches: {label}"
                  f"{'  (installed version)' if exact and reaches else ''}")
            if exposed:
                print(f"           in:      {', '.join(exposed)}")

        counts: dict[str, int] = {}
        for row in merged:
            counts[row["severity"]] = counts.get(row["severity"], 0) + 1
        print("\n" + "  ".join(f"{k}: {v}" for k, v in
                                sorted(counts.items(), key=lambda kv: order.get(kv[0], 4))))
        if len(rows) != len(merged):
            print(f"{len(rows)} advisory record(s) covering {len(merged)} distinct "
                  f"vulnerability(ies)")

    elif args.command == "check":
        from .monitor import check, notify
        from .store import Store
        alerts = check(Store(), verbose=True, refresh=args.refresh)
        if alerts:
            notify(alerts)
        else:
            print("No new advisories.")

    elif args.command == "watch":
        import logging
        from .monitor import watch
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
        watch(interval_hours=args.interval_hours)


if __name__ == "__main__":
    main()
