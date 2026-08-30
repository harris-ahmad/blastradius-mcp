"""blastradius — entry point for the MCP server, the hooks, and the daemon."""
from __future__ import annotations

import argparse
import json
import sys


def main() -> None:
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
    sub.add_parser("doctor", help="Check the wiring and prove the hooks run.")

    sub.add_parser("stats", help="Show what is currently indexed.")
    sub.add_parser("check", help="Run one CVE check against OSV now.")

    consumers = sub.add_parser("consumers", help="Who uses an artifact, and where.")
    consumers.add_argument("identifier")
    consumers.add_argument("--type", default=None)

    hygiene_cmd = sub.add_parser("hygiene", help="Pinning report, worst first.")
    hygiene_cmd.add_argument("--type", default=None)
    hygiene_cmd.add_argument("--min-consumers", type=int, default=1)

    sub.add_parser("repos", help="List indexed repositories.")

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

    elif args.command == "doctor":
        from .install import doctor
        sys.exit(doctor())

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

    elif args.command == "check":
        from .monitor import check, notify
        from .store import Store
        alerts = check(Store())
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
