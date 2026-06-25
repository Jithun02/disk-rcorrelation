#!/usr/bin/env python
import json
from collections import Counter

d = json.load(open('result/live_demo_report.json'))
s = d['summary']

print("\n" + "="*70)
print("CORE FORENSICS ANALYSIS REPORT")
print("="*70)
print(f"\nGenerated: {d['generated_at']}")

print("\n[SUMMARY STATISTICS]")
print(f"  Processes Extracted:     {s['process_count']}")
print(f"  Disk Files Parsed:       {s['disk_file_count']}")
print(f"  Deleted Files:           {s['deleted_file_count']}")
print(f"  Network Connections:     {s['network_connection_count']}")

print("\n[DETECTION RESULTS]")
print(f"  Rule-Based Alerts:       {len(d['alerts'])} findings")
print(f"  Hidden Process Alerts:   {len(d['hidden_process_alerts'])} mismatches")
print(f"  AI Anomalies:            {len(d['ai_anomalies'])} suspicious behaviors")
print(f"  YARA Signature Matches:  {len(d['yara'].get('matches', []))} hits")

print("\n[TOP HIGH-SEVERITY ALERTS]")
high_alerts = [a for a in d['alerts'] if a.get('severity') == 'HIGH']
for i, alert in enumerate(high_alerts[:5], 1):
    print(f"  {i}. {alert.get('alert_type', 'unknown')} -> {alert.get('process_name', 'N/A')} (PID {alert.get('pid', 'N/A')})")
    print(f"     Details: {alert.get('description', 'N/A')[:60]}...")

print("\n[HIDDEN PROCESS ANALYSIS]")
hidden_procs = Counter([a.get('process_name', 'unknown') for a in d['hidden_process_alerts']])
for proc, count in hidden_procs.most_common(5):
    print(f"  {proc}: {count} visibility mismatches")

print("\n[AI ANOMALY FINDINGS]")
for i, anom in enumerate(d['ai_anomalies'], 1):
    score = anom.get('anomaly_score', 'N/A')
    if isinstance(score, (int, float)):
        score_str = f"{score:.2f}"
    else:
        score_str = str(score)
    print(f"  {i}. {anom.get('process_name', 'unknown')} (PID {anom.get('pid', 'N/A')}) - Anomaly Score: {score_str}")

print("\n[TIMELINE OVERVIEW]")
print(f"  Total Events:            {len(d['timeline'])} forensic events")
if d['timeline']:
    print(f"  Time Range:              {d['timeline'][0].get('timestamp', 'N/A')} to {d['timeline'][-1].get('timestamp', 'N/A')}")

print("\n[CORRELATED FINDINGS]")
print(f"  Process-Disk Links:      {len(d['correlated'])} correlations")
suspicious_corr = [c for c in d['correlated'] if c.get('suspicious_path')]
print(f"  Suspicious Paths:        {len(suspicious_corr)} potential indicators")

print("\n[YARA SCAN STATUS]")
yara_info = d['yara']
print(f"  Rules Used:              {yara_info.get('rules_path', 'N/A')}")
print(f"  Scanned Candidates:      {yara_info.get('scanned_candidates', 0)} files/regions")
print(f"  Matches Found:           {len(yara_info.get('matches', []))} signatures hit")

print("\n" + "="*70)
print("Full report available at: result/live_demo_report.json")
print("="*70 + "\n")
