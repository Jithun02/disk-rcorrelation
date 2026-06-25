from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core_forensics.ai.anomaly import ai_detect
from core_forensics.core.correlator import correlate
from core_forensics.core.detector import detect_anomalies, detect_hidden_processes
from core_forensics.core.timeline import build_timeline
from core_forensics.disk.disk_parser import extract_files
from core_forensics.memory.memory_parser import (
    VolatilityConfig,
    extract_dlls,
    extract_network_connections,
    extract_psscan_processes,
    extract_psxview,
    extract_processes,
)
from core_forensics.triage.yara_scanner import scan_disk_files_with_yara


def run_once(
    memory_file: str,
    disk_image: str,
    volatility_bin: str,
    enable_ai: bool,
    yara_rules: str | None = None,
    yara_scan_limit: int = 300,
) -> dict[str, Any]:
    vol_cfg = VolatilityConfig(volatility_bin=volatility_bin)

    processes = extract_processes(memory_file, vol_cfg)
    psscan_processes = extract_psscan_processes(memory_file, vol_cfg)
    psxview_processes = extract_psxview(memory_file, vol_cfg)
    dlls = extract_dlls(memory_file, vol_cfg)
    connections = extract_network_connections(memory_file, vol_cfg)
    files = extract_files(disk_image)

    correlation_result = correlate(
        processes,
        files,
        dlls=dlls,
        connections=connections,
        psxview_processes=psxview_processes,
    )
    correlated = correlation_result["correlated"]

    alerts = detect_anomalies(correlated)
    hidden_alerts = detect_hidden_processes(processes, psscan_processes, psxview_processes)
    alerts.extend(hidden_alerts)
    alerts.sort(key=lambda item: item.get("score", 0), reverse=True)

    ai_anomalies = ai_detect(correlated) if enable_ai else []
    yara_results = (
        scan_disk_files_with_yara(
            image_path=disk_image,
            files=files,
            rules_path=yara_rules,
            max_files=yara_scan_limit,
        )
        if yara_rules
        else {"enabled": False, "matches": [], "errors": []}
    )
    timeline = build_timeline(processes, files, connections)

    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "summary": correlation_result["summary"],
        "alerts": alerts,
        "hidden_process_alerts": hidden_alerts,
        "ai_anomalies": ai_anomalies,
        "yara": yara_results,
        "correlated": correlated,
        "timeline": timeline,
        "raw": {
            "processes": processes,
            "psscan_processes": psscan_processes,
            "psxview_processes": psxview_processes,
            "dlls": dlls,
            "connections": connections,
            "files": files,
        },
    }


def write_report(report: dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)


def print_summary(report: dict[str, Any]) -> None:
    print("=== CORE FORENSICS REPORT ===")
    print(f"Generated: {report.get('generated_at')}")
    print(f"Processes: {report.get('summary', {}).get('process_count', 0)}")
    print(f"Disk files: {report.get('summary', {}).get('disk_file_count', 0)}")
    print(f"Alerts: {len(report.get('alerts', []))}")
    print(f"AI anomalies: {len(report.get('ai_anomalies', []))}")
    print(f"YARA matches: {len(report.get('yara', {}).get('matches', []))}")

    for alert in report.get("alerts", [])[:10]:
        print(
            f"- [{alert.get('severity', 'n/a').upper()}] "
            f"{alert.get('type')} -> {alert.get('process')} (PID {alert.get('pid')})"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Disk + RAM Correlation Engine")
    parser.add_argument("--memory-file", required=True, help="Path to memory dump file")
    parser.add_argument("--disk-image", required=True, help="Path to disk image file")
    parser.add_argument("--volatility-bin", default="vol", help="Volatility executable (default: vol)")
    parser.add_argument("--output", default="data/report.json", help="JSON report output path")
    parser.add_argument("--enable-ai", action="store_true", help="Enable IsolationForest scoring")
    parser.add_argument("--yara-rules", help="Path to YARA rules file")
    parser.add_argument(
        "--yara-scan-limit",
        type=int,
        default=300,
        help="Maximum candidate deleted files to YARA scan",
    )
    parser.add_argument("--watch", action="store_true", help="Run continuously in near real-time")
    parser.add_argument("--interval", type=int, default=30, help="Seconds between scans in watch mode")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.watch:
        report = run_once(
            args.memory_file,
            args.disk_image,
            args.volatility_bin,
            args.enable_ai,
            yara_rules=args.yara_rules,
            yara_scan_limit=args.yara_scan_limit,
        )
        write_report(report, args.output)
        print_summary(report)
        print(f"Report written to: {args.output}")
        return

    print("Starting watch mode. Press Ctrl+C to stop.")
    previous_alert_fingerprint: set[tuple[str, int, str]] = set()

    try:
        while True:
            report = run_once(
                args.memory_file,
                args.disk_image,
                args.volatility_bin,
                args.enable_ai,
                yara_rules=args.yara_rules,
                yara_scan_limit=args.yara_scan_limit,
            )
            write_report(report, args.output)

            current_fingerprint = {
                (str(a.get("type")), int(a.get("pid", 0)), str(a.get("process")))
                for a in report.get("alerts", [])
            }
            new_alerts = current_fingerprint - previous_alert_fingerprint

            print_summary(report)
            if new_alerts:
                print("New alerts detected:")
                for alert_type, pid, process in sorted(new_alerts):
                    print(f"* {alert_type}: {process} (PID {pid})")

            previous_alert_fingerprint = current_fingerprint
            time.sleep(max(1, args.interval))
    except KeyboardInterrupt:
        print("Watch mode stopped.")


if __name__ == "__main__":
    main()
