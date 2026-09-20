#!/usr/bin/env python3
"""Hidden-Prompt Scanner for Documents — CLI entry point.

Usage:
    python scanner.py --file resume.pdf
    python scanner.py --dir ./documents --recursive --json report.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from detectors import SUPPORTED, scan_file

RISK_ORDER = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
COLORS = {
    "HIGH": "\033[91m", "MEDIUM": "\033[93m",
    "LOW": "\033[94m", "CLEAN": "\033[92m",
}
RESET = "\033[0m"

ZW_REPLACE = {
    "\u200b": "[ZW-SP]", "\u200c": "[ZW-NJ]", "\u200d": "[ZW-J]",
    "\ufeff": "[BOM]", "\u2060": "[WJ]", "\u180e": "[MVS]",
}


def safe(s: str) -> str:
    """Make text printable on Windows consoles (cp1252) without crashing."""
    for ch, rep in ZW_REPLACE.items():
        s = s.replace(ch, rep)
    return s.encode("cp1252", errors="replace").decode("cp1252")


def collect_targets(file: str | None, directory: str | None, recursive: bool) -> list[Path]:
    targets: list[Path] = []
    if file:
        targets.append(Path(file))
    if directory:
        root = Path(directory)
        pattern = "**/*" if recursive else "*"
        for p in root.glob(pattern):
            if p.is_file() and p.suffix.lower() in SUPPORTED:
                targets.append(p)
    return targets


def print_report(report: dict, use_color: bool = True, verbose: bool = False) -> None:
    risk = report["risk"]
    color = COLORS.get(risk, "") if use_color else ""
    reset = RESET if use_color else ""
    # Header goes through safe(): filenames with unicode/zero-width chars
    # used to crash Windows consoles (cp1252) here.
    print(safe(f"\n{color}[{risk}] {report['file']} (score={report['score']}, findings={report['finding_count']}){reset}"))
    if risk == "CLEAN" and not verbose:
        print("    No hidden prompts detected.")
        return
    for f in report["findings"]:
        print(safe(f"    - [{f.get('severity', '?').upper()}] {f['type']} @ {f['location']}"))
        print(safe(f"      {f.get('detail', '')}"))
        if f.get("excerpt"):
            print(safe(f"      > {f['excerpt'][:200]}"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan documents for hidden prompt-injection attacks.")
    ap.add_argument("--file", help="Single file to scan")
    ap.add_argument("--dir", help="Directory to scan")
    ap.add_argument("--recursive", "-r", action="store_true", help="Recurse into subdirectories")
    ap.add_argument("--json", dest="json_out", help="Write JSON report to this path")
    ap.add_argument("--min-risk", default="CLEAN",
                    choices=["CLEAN", "LOW", "MEDIUM", "HIGH"],
                    help="Only show results at/above this risk (default: CLEAN)")
    ap.add_argument("--no-color", action="store_true", help="Disable colored output")
    ap.add_argument("--verbose", "-v", action="store_true", help="Show clean files too")
    args = ap.parse_args(argv)

    if not args.file and not args.dir:
        ap.error("Provide --file and/or --dir")

    targets = collect_targets(args.file, args.dir, args.recursive)
    if not targets:
        print("No supported files found. Supported:", sorted(SUPPORTED))
        return 1

    results = []
    exit_code = 0
    for t in targets:
        if not t.exists():
            print(safe(f"[!] Not found: {t}"), file=sys.stderr)
            exit_code = 1
            continue
        try:
            report = scan_file(t)
        except Exception as e:  # never crash a batch scan on one bad file
            report = {"file": str(t), "file_type": t.suffix, "risk": "LOW",
                      "score": 1, "finding_count": 1,
                      "findings": [{"type": "error", "location": str(t),
                                    "detail": f"Scan failed: {e}", "excerpt": "",
                                    "severity": "low", "weight": 1}]}
        results.append(report)
        if RISK_ORDER[report["risk"]] >= RISK_ORDER[args.min_risk]:
            print_report(report, use_color=not args.no_color, verbose=args.verbose)
        if report["risk"] == "HIGH":
            exit_code = 2  # signal: high-risk file found

    if args.json_out:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(results),
            "summary": {r: sum(1 for x in results if x["risk"] == r)
                        for r in ("HIGH", "MEDIUM", "LOW", "CLEAN")},
            "results": results,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[+] JSON report written to {args.json_out}")

    highs = sum(1 for r in results if r["risk"] == "HIGH")
    print(f"\nScanned {len(results)} file(s). HIGH-risk: {highs}.")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
