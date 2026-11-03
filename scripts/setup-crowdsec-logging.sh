#!/bin/bash
# Day 5+ — Forward CrowdSec alerts to host syslog (facility=local0, tag=crowdsec)
#
# Why: the NPMplus access log (scripts/setup-json-logging.sh) only tells
# Sentinel "IP X got a 403 on URI Y". The reason for the block (which CRS
# rule category fired: lfi, sql_injection, xss, appsec-native, ...) and the
# anomaly score exist only inside CrowdSec, as the alert's scenario, e.g.
#   "anomaly score block: sql_injection: 40, anomaly: 40,"
# This also covers attacks Sentinel cannot see at all from HTTP status codes
# (README "Detection blind spot": unauthenticated requests get 302 from the
# identity gate, but CrowdSec AppSec still inspects them).
#
# How: a small systemd service on the HOST polls
#   docker exec crowdsec cscli alerts list -o json
# every 30 s, emits each NEW alert (tracked by alert id) as one JSON line via
#   logger -p local0.notice -t crowdsec
# The existing DCR in sentinel.tf already collects facility local0, so the
# alerts land in the Syslog table with ProcessName == "crowdsec" without any
# change to the AMA -> DCR -> Log Analytics pipeline. sentinel.tf adds the
# KQL function CrowdSecAlerts that parses them.
#
# On the first start the forwarder back-fills the last 24 h of alerts. The
# alert's own timestamp is kept in the JSON ("created_at"), so queries use
# that instead of TimeGenerated (= time of forwarding).
#
# Run after scripts/setup-npmplus.sh (the crowdsec container must exist).
#
# Usage:
#   scp scripts/setup-crowdsec-logging.sh <vm>:/tmp/
#   ssh <vm> "sudo bash /tmp/setup-crowdsec-logging.sh"

set -euo pipefail

FORWARDER=/usr/local/bin/crowdsec-alert-forwarder.py

echo "==> Writing CrowdSec alert forwarder..."
cat > "$FORWARDER" << 'EOF'
#!/usr/bin/env python3
"""Polls CrowdSec alerts and re-emits each new one as JSON to syslog
facility local0 (tag=crowdsec). Parsed in Sentinel by the CrowdSecAlerts
function (sentinel.tf)."""
import json
import os
import re
import shlex
import subprocess
import sys
import time

CSCLI = shlex.split(os.environ.get("CSCLI", "docker exec crowdsec cscli"))
STATE_DIR = os.environ.get("STATE_DIR", "/var/lib/crowdsec-alert-forwarder")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
INTERVAL = int(os.environ.get("INTERVAL", "30"))
BACKFILL_MIN = 24 * 60      # first start / long downtime: look back at most 24 h
OVERLAP_MIN = 5             # re-read a few minutes; duplicates are dropped by id
MAX_MSG = 3800              # stay below `logger --size 4096`
CATEGORY_RE = re.compile(r"([a-z_]+):\s*(\d+)")


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {"last_id": 0, "last_run": 0}


def save_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def fetch_alerts(since_min):
    out = subprocess.run(
        CSCLI + ["alerts", "list", "--since", f"{since_min}m", "-l", "0", "-o", "json"],
        capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out or "null") or []   # cscli prints "null" when empty


def meta_values(alert, key):
    """Collects a meta key from the alert and its events (present depending on
    the CrowdSec version and scenario; absent fields are simply skipped)."""
    vals = []
    sources = [alert.get("meta") or []] + [e.get("meta") or [] for e in alert.get("events") or []]
    for meta in sources:
        for m in meta:
            if m.get("key") != key:
                continue
            v = m.get("value")
            try:                       # alert-level context is a JSON list string
                parsed = json.loads(v)
                items = parsed if isinstance(parsed, list) else [v]
            except (TypeError, ValueError):
                items = [v]
            for i in items:
                if i and str(i) not in vals:
                    vals.append(str(i)[:200])
    return vals[:5]


def to_doc(alert):
    scenario = alert.get("scenario") or ""
    scores = {k: int(v) for k, v in CATEGORY_RE.findall(scenario)}
    anomaly = scores.pop("anomaly", None)
    src = alert.get("source") or {}
    decisions = alert.get("decisions") or []
    doc = {
        "alert_id": alert.get("id"),
        "created_at": alert.get("created_at"),
        "scenario": scenario,
        # "anomaly score block: lfi: 5, anomaly: 5," -> ["lfi"], 5
        # other scenarios (crowdsecurity/appsec-native, http-probing, ...) -> [name]
        "attack_types": list(scores) or [scenario.split("/")[-1]],
        "anomaly_score": anomaly,
        "source_ip": src.get("ip") or src.get("value"),
        "source_range": src.get("range"),
        "country": src.get("cn"),
        "as_name": src.get("as_name"),
        "events_count": alert.get("events_count"),
        "decision": decisions[0].get("type") if decisions else None,
        "decision_duration": decisions[0].get("duration") if decisions else None,
        "target_uris": meta_values(alert, "target_uri"),
        "user_agents": meta_values(alert, "user_agent"),
    }
    msg = json.dumps(doc, separators=(",", ":"))
    while len(msg) > MAX_MSG and (doc["target_uris"] or doc["user_agents"]):
        (doc["target_uris"] or doc["user_agents"]).pop()
        msg = json.dumps(doc, separators=(",", ":"))
    return msg


def run_once(state):
    now = time.time()
    since = BACKFILL_MIN if not state["last_run"] else \
        min(BACKFILL_MIN, int((now - state["last_run"]) / 60) + OVERLAP_MIN)
    alerts = sorted(fetch_alerts(since), key=lambda a: a.get("id") or 0)
    sent = 0
    for alert in alerts:
        if (alert.get("id") or 0) <= state["last_id"]:
            continue
        subprocess.run(["logger", "--size", "4096", "-p", "local0.notice",
                        "-t", "crowdsec", to_doc(alert)], check=True)
        state["last_id"] = alert["id"]
        sent += 1
    state["last_run"] = now
    save_state(state)
    return sent


def main():
    state = load_state()
    while True:
        try:
            n = run_once(state)
            if n:
                print(f"forwarded {n} alert(s), last_id={state['last_id']}", flush=True)
        except Exception as exc:  # crowdsec restarting, docker not up yet, ...
            print(f"poll failed: {exc}", file=sys.stderr, flush=True)
        if os.environ.get("ONESHOT"):
            return
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
EOF
chmod +x "$FORWARDER"

echo "==> Writing systemd unit..."
cat > /etc/systemd/system/crowdsec-alert-forwarder.service << EOF
[Unit]
Description=Forward CrowdSec alerts to syslog local0 as JSON (for Sentinel)
After=docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${FORWARDER}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now crowdsec-alert-forwarder

echo ""
echo "Done. CrowdSec alerts -> syslog local0 (tag=crowdsec), polled every 30 s."
echo ""
echo "Verify locally (wait ~30 s):"
echo "  journalctl -u crowdsec-alert-forwarder -n 20"
echo "  journalctl -t crowdsec --since '1 day ago' | tail"
echo ""
echo "Verify in Sentinel (wait 3-10 min for ingestion, after terraform apply):"
echo "  CrowdSecAlerts | take 10"
