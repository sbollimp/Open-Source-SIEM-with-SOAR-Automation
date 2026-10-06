"""Shared fixtures: a synthetic Wazuh alert and a handful of fake
analyzer verdicts, used across the playbook unit tests so each test file
doesn't re-invent the same alert shape."""

from __future__ import annotations

import logging

import pytest

from soar_automation.integrations.cortex_client import AnalyzerVerdict
from soar_automation.integrations.wazuh_client import WazuhAlert


@pytest.fixture
def logger() -> logging.Logger:
    log = logging.getLogger("test.soar_automation")
    log.setLevel(logging.DEBUG)
    if not log.handlers:
        log.addHandler(logging.NullHandler())
    return log


@pytest.fixture
def brute_force_alert() -> WazuhAlert:
    return WazuhAlert(
        id="alert-1001",
        rule_id=100012,
        rule_level=12,
        description="Sustained SSHD brute force",
        timestamp="2026-10-01T12:00:00Z",
        agent_name="web01",
        observables={"ip": ["203.0.113.50"], "hash": [], "url": [], "domain": []},
        raw={"data": {"srcip": "203.0.113.50"}},
    )


@pytest.fixture
def scanner_alert() -> WazuhAlert:
    """Matches the internal_vuln_scanner_ssh benign pattern."""
    return WazuhAlert(
        id="alert-1002",
        rule_id=100010,
        rule_level=10,
        description="SSHD brute force (internal scanner)",
        timestamp="2026-10-01T12:05:00Z",
        agent_name="web02",
        observables={"ip": ["10.10.50.7"], "hash": [], "url": [], "domain": []},
        raw={"data": {"srcip": "10.10.50.7"}},
    )


@pytest.fixture
def malicious_verdict() -> AnalyzerVerdict:
    return AnalyzerVerdict(
        analyzer="AbuseIPDB_1_0",
        observable="203.0.113.50",
        observable_type="ip",
        verdict="malicious",
        taxonomy_summary="abuse:confidence=malicious; reports=42",
        raw={},
    )


@pytest.fixture
def safe_verdict() -> AnalyzerVerdict:
    return AnalyzerVerdict(
        analyzer="AbuseIPDB_1_0",
        observable="10.10.50.7",
        observable_type="ip",
        verdict="safe",
        taxonomy_summary="abuse:confidence=safe",
        raw={},
    )
