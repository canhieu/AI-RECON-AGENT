#!/usr/bin/env python3
"""AI Recon Agent — Entry Point

CLI entry that parses args, validates SHINE_API_KEY, creates orchestrator per
target, and prints report summary. Supports single --target or --targets file.
Model config is in settings.yaml, not CLI, to keep scans reproducible.

Usage:
    python main.py --target example.com
    python main.py --target example.com --max-steps 50 --verbose
    python main.py --targets targets.txt --threads 3
    python main.py --target example.com --resume <session_id>
    python main.py --target example.com --passive-only
    python main.py --target example.com --no-service
"""

import argparse
import json
import os
import sys
from dotenv import load_dotenv

from orchestrator import ReconOrchestrator


def parse_args() -> argparse.Namespace:
    """Parse and validate CLI flags.

    Mutually exclusive: --target (single) or --targets (file).
    Runtime flags: --passive-only, --no-service, --max-steps, --resume, --verbose.
    --threads and --output are parsed for future compat but not fully wired yet.

    Returns:
        Parsed argparse.Namespace.
    """
    parser = argparse.ArgumentParser(
        description="AI Recon Agent — Autonomous web reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target scanme.nmap.org
  python main.py --target example.com --max-steps 30 --verbose
  python main.py --targets targets.txt --threads 2
  python main.py --target scanme.nmap.org --passive-only
  python main.py --target scanme.nmap.org --resume <session_id>
        """
    )

    # Target
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--target", help="Single target (domain/IP/URL)")
    target_group.add_argument("--targets", help="File with targets (one per line)")

    # Mode
    parser.add_argument("--resume", help="Session ID to resume")
    parser.add_argument("--passive-only", action="store_true",
                        help="Only run passive recon, no active scanning")
    parser.add_argument("--no-service", action="store_true",
                        help="Skip service interaction checks")
    # Control
    parser.add_argument("--max-steps", type=int, default=50,
                        help="Max steps per target (default: 50)")
    parser.add_argument("--threads", type=int, default=1,
                        help="Parallel targets (default: 1)")

    # Output
    parser.add_argument("--output", help="Output directory (default: outputs/{target}/)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed tool output")

    return parser.parse_args()


def load_targets(args) -> list[str]:
    """Resolve target list from CLI args.

    If --target, returns single-element list.
    If --targets, reads file, strips whitespace, skips empty/comment lines.

    Args:
        args: Parsed argparse.Namespace.

    Returns:
        List of target strings.
    """
    if args.target:
        return [args.target]
    with open(args.targets) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def print_report_summary(json_path: str, max_findings: int = 10):
    """Print final findings summary to CLI.

    Reads JSON report and prints: count by severity, tech stack, open ports,
    top findings sorted by severity, recommendations. Saves user from opening
    report files.

    Args:
        json_path: Path to recon-report.json.
        max_findings: Max findings to show in CLI (default 10).
    """
    try:
        with open(json_path) as f:
            report = json.load(f)
    except Exception as e:
        print(f"[!] Could not read JSON report: {e}")
        return

    summary = report.get("summary", {})
    counts = summary.get("by_severity", {})
    findings = report.get("findings", [])

    print("\n" + "=" * 60)
    print(f"FINAL RESULTS: {report.get('target', 'unknown')}")
    print("=" * 60)
    print(f"Total findings: {summary.get('total', len(findings))}")
    print(
        "Severity: "
        f"critical={counts.get('critical', 0)} | "
        f"high={counts.get('high', 0)} | "
        f"medium={counts.get('medium', 0)} | "
        f"low={counts.get('low', 0)} | "
        f"info={counts.get('info', 0)}"
    )

    tech = summary.get("tech_stack")
    ports = summary.get("ports") or []
    if tech:
        print(f"Tech stack: {tech}")
    if ports:
        print(f"Open ports: {', '.join(map(str, ports[:20]))}")

    if not findings:
        print("No findings saved.")

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 9))
    print(f"\nTop findings (showing {min(max_findings, len(findings))}/{len(findings)}):")
    for idx, finding in enumerate(findings[:max_findings], 1):
        sev = finding.get("severity", "info").upper()
        tool = finding.get("tool", "unknown")
        text = finding.get("summary", "")
        print(f"{idx}. [{sev}] {tool}: {text}")
        evidence = (finding.get("evidence") or "").replace("\n", " ").strip()
        if evidence:
            print(f"   Evidence: {evidence[:220]}")

    recs = report.get("recommendations")
    if recs:
        print("\n" + "-" * 60)
        print("RECOMMENDED NEXT STEPS:")
        print("-" * 60)
        for s in recs:
            print(f"  {s}")
    print(f"  \u25b6 See full report: {json_path}")


def main():
    """Main entry point.

    1. Load .env
    2. Validate SHINE_API_KEY
    3. Parse CLI args
    4. For each target: create ReconOrchestrator, run, print summary

    Current limitation: sequential targets (--threads parsed but not parallel).
    """
    load_dotenv()
    args = parse_args()

    # Validate API key
    api_key = os.getenv("SHINE_API_KEY")
    if not api_key:
        print("[!] ERROR: SHINE_API_KEY not set in .env")
        print("    Copy .env.example to .env and add your key")
        sys.exit(1)

    targets = load_targets(args)

    print(f"[*] AI Recon Agent v0.1.0")
    print(f"[*] Targets: {', '.join(targets[:3])}{' ...' if len(targets) > 3 else ''}")
    print(f"[*] Max steps: {args.max_steps} | Threads: {args.threads}")
    print()

    # Threads/output flags are parsed for future compatibility; current runtime
    # keeps one orchestrator per target and writes to outputs/<target>/.
    for target in targets:
        print(f"{'='*60}")
        print(f"[*] Scanning: {target}")
        print(f"{'='*60}")

        orchestrator = ReconOrchestrator(
            target=target,
            max_steps=args.max_steps,
            passive_only=args.passive_only,
            no_service=args.no_service,
            verbose=args.verbose,
            resume_session_id=args.resume,
        )

        report_paths = orchestrator.ui.run_textual(orchestrator.run)

        if report_paths:
            print_report_summary(report_paths["json"])
            print(f"\n[+] Report saved: {report_paths['markdown']}")
            print(f"[+] JSON saved:   {report_paths['json']}")
        print()


if __name__ == "__main__":
    main()
