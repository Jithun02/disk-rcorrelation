from __future__ import annotations

import json
from pathlib import Path

import streamlit as st


st.set_page_config(page_title="CORE Forensics Dashboard", layout="wide")
st.title("Disk + RAM Correlation Engine")

report_path = st.sidebar.text_input("Report JSON Path", value="data/report.json")

path = Path(report_path)
if not path.exists():
    st.warning("Report file not found. Run main.py first to generate data/report.json")
    st.stop()

with path.open("r", encoding="utf-8") as handle:
    report = json.load(handle)

summary = report.get("summary", {})
col1, col2, col3, col4 = st.columns(4)
col1.metric("Processes", summary.get("process_count", 0))
col2.metric("Disk Files", summary.get("disk_file_count", 0))
col3.metric("Deleted Files", summary.get("deleted_file_count", 0))
col4.metric("Alerts", len(report.get("alerts", [])))

st.subheader("Top Alerts")
st.dataframe(report.get("alerts", []), use_container_width=True)

st.subheader("AI Anomalies")
st.dataframe(report.get("ai_anomalies", []), use_container_width=True)

st.subheader("Hidden Process Alerts")
st.dataframe(report.get("hidden_process_alerts", []), use_container_width=True)

st.subheader("YARA Matches")
st.dataframe(report.get("yara", {}).get("matches", []), use_container_width=True)

if report.get("yara", {}).get("errors"):
    st.warning("YARA scan errors")
    st.write(report.get("yara", {}).get("errors", []))

st.subheader("Correlation")
st.dataframe(report.get("correlated", []), use_container_width=True)
