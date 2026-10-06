#!/usr/bin/env python3
"""
Seeds MISP with a small starter IOC set so ioc_correlation.py has something
to correlate against immediately after a fresh install, instead of every
demo run being a "no matches" trip through the pipeline.

The IOCs below are well-known, publicly documented test/benign-but-flagged
indicators (e.g. the EICAR test file hash and RFC 5737/5771 documentation
IP ranges) — NOT real malware intelligence. Replace with a real feed
subscription for anything beyond local demoing.

Usage:
    python3 scripts/seed_misp.py --config soar_automation/config.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymisp import ExpandedPyMISP, MISPAttribute, MISPEvent  # noqa: E402

from soar_automation.utils.config import Config  # noqa: E402

SEED_IOCS = [
    {
        "type": "ip-dst",
        "value": "203.0.113.50",
        "comment": "RFC 5737 TEST-NET-3 documentation range — demo IOC",
    },
    {"type": "domain", "value": "malicious-example.test", "comment": "Reserved .test TLD — demo IOC"},
    {
        "type": "sha256",
        "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
        "comment": "EICAR test file SHA-256 — safe, widely used AV test signature",
    },
    {
        "type": "url",
        "value": "http://malicious-example.test/payload.exe",
        "comment": "Demo phishing payload URL",
    },
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="soar_automation/config.yaml")
    args = parser.parse_args()

    config = Config.load(args.config)
    misp_cfg = config.section("misp")

    misp = ExpandedPyMISP(misp_cfg["url"], misp_cfg["api_key"], misp_cfg.get("verify_tls", False))

    event = MISPEvent()
    event.info = "soar-automation demo seed feed"
    event.distribution = 0
    event.threat_level_id = 3
    event.analysis = 2
    created = misp.add_event(event)
    event_id = created["Event"]["id"]
    misp.tag(created["Event"]["uuid"], "source:soar-automation-seed")

    for ioc in SEED_IOCS:
        attribute = MISPAttribute()
        attribute.type = ioc["type"]
        attribute.value = ioc["value"]
        attribute.comment = ioc["comment"]
        attribute.to_ids = True
        misp.add_attribute(event_id, attribute)
        print(f"  seeded {ioc['type']}: {ioc['value']}")

    print(f"Done. Seeded {len(SEED_IOCS)} IOC(s) into MISP event {event_id}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
