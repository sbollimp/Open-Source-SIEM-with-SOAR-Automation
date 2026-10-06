from soar_automation.playbooks.auto_triage import score_alert
from soar_automation.playbooks.ioc_correlation import CorrelationResult
from soar_automation.playbooks.alert_enrichment import EnrichedAlert

BENIGN_PATTERNS = [
    {
        "id": "internal_vuln_scanner_ssh",
        "match": {"rule_id": [100010, 100011], "srcip_in_cidr": ["10.10.50.0/24"]},
        "weight": -0.6,
    },
]


def test_high_severity_malicious_alert_escalates(brute_force_alert, malicious_verdict):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    correlation = CorrelationResult(enriched=enriched)

    decision = score_alert(correlation, benign_patterns=[])

    assert decision.decision == "escalated"
    assert decision.score >= 0.70


def test_known_benign_scanner_pattern_auto_closes(scanner_alert, safe_verdict):
    enriched = EnrichedAlert(alert=scanner_alert, verdicts=[safe_verdict])
    correlation = CorrelationResult(enriched=enriched)

    decision = score_alert(correlation, benign_patterns=BENIGN_PATTERNS)

    assert decision.decision == "closed_auto"
    assert decision.score < 0.25
    assert any("internal_vuln_scanner_ssh" in r for r in decision.reasons)


def test_existing_misp_match_pushes_score_up(brute_force_alert):
    from soar_automation.integrations.misp_client import MispMatch

    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[])
    correlation = CorrelationResult(
        enriched=enriched,
        existing_matches=[
            MispMatch(value="203.0.113.50", observable_type="ip", event_id="1", event_info="x", tags=[])
        ],
    )

    decision = score_alert(correlation, benign_patterns=[])

    assert decision.score > min(brute_force_alert.rule_level / 15.0, 1.0)


def test_score_without_benign_pattern_match_is_unaffected(brute_force_alert, malicious_verdict):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    correlation = CorrelationResult(enriched=enriched)

    with_patterns = score_alert(
        correlation, benign_patterns=BENIGN_PATTERNS
    )  # pattern targets a different rule_id
    without_patterns = score_alert(correlation, benign_patterns=[])

    assert with_patterns.score == without_patterns.score
