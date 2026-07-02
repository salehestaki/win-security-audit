from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from win_security_audit import __version__, utils
from win_security_audit.audit import run_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="SecurityAudit",
        description="Windows security audit and lightweight incident-response report generator.",
    )
    parser.add_argument("--output-dir", default="reports", help="Directory for HTML and JSON reports.")
    parser.add_argument("--quick", action="store_true", help="Use faster limits for slower collectors.")
    parser.add_argument("--max-file-scan", type=int, default=4000, help="Maximum candidate files to inspect in user-writable locations.")
    parser.add_argument("--no-open", action="store_true", help="Do not open the HTML report after completion.")
    parser.add_argument("--no-elevate", action="store_true", help="Do not request Administrator rights automatically.")
    parser.add_argument("--elevated-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--no-sysinternals", action="store_true", help="Skip optional Sysinternals integration.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if utils.is_windows() and not args.no_elevate and not args.elevated_child and not utils.is_admin():
        child_args = [arg for arg in argv if arg != "--elevated-child"] + ["--elevated-child"]
        if utils.relaunch_as_admin(child_args):
            print("Administrator approval requested. The elevated audit window will continue the scan.")
            return 0
        print("Could not request Administrator rights; continuing with limited access.")

    output_dir = Path(args.output_dir).expanduser().resolve()
    if args.quick and args.max_file_scan == 4000:
        args.max_file_scan = 800

    print("Starting Windows Security Audit...")
    print(f"Output directory: {output_dir}")
    print(f"Administrator: {'yes' if utils.is_admin() else 'no'}")
    report, html_path, json_path = run_audit(
        output_dir=output_dir,
        quick=args.quick,
        max_file_scan=max(0, args.max_file_scan),
        include_sysinternals=not args.no_sysinternals,
    )
    print(f"Risk score: {report.risk_score}/100")
    print(f"HTML report: {html_path}")
    print(f"JSON report: {json_path}")
    if not args.no_open:
        try:
            webbrowser.open(html_path.as_uri())
        except Exception:
            os.startfile(str(html_path)) if hasattr(os, "startfile") else None
    return 0
