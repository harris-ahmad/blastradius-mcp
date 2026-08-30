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

    sub.add_parser("stats", help="Show what is currently indexed.")

    args = parser.parse_args()

    if args.command == "serve":
        from .server import main as serve
        serve()
    elif args.command == "hook":
        from .hooks import run
        run(args.name)
    elif args.command == "stats":
        from .store import Store
        json.dump(Store().stats(), sys.stdout, indent=2)
        sys.stdout.write("\n")


if __name__ == "__main__":
    main()
