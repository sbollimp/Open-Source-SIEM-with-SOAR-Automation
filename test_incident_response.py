from unittest.mock import MagicMock

from soar_automation.integrations.thehive_client import CaseResult
from soar_automation.playbooks.alert_enrichment import EnrichedAlert
from soar_automation.playbooks.auto_triage import TriageDecision
from soar_automation.playbooks.incident_response import handle_decision
from soar_automation.playbooks.ioc_correlation import CorrelationResult


def _thehive_mock(case_id="case-1"):
    thehive = MagicMock()
    thehive.create_case_from_alert.return_value = CaseResult(case_id=case_id, title="t", tags=[])
    return thehive


def test_escalated_decision_creates_case_and_leaves_it_open(brute_force_alert, malicious_verdict, logger):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    correlation = CorrelationResult(enriched=enriched)
    decision = TriageDecision(score=0.85, decision="escalated", reasons=["high score"])
    thehive = _thehive_mock()

    case_id = handle_decision(correlation, decision, thehive, logger)

    assert case_id == "case-1"
    thehive.create_case_from_alert.assert_called_once()
    thehive.attach_observables.assert_called_once_with("case-1", brute_force_alert.observables)
    thehive.close_case.assert_not_called()


def test_closed_auto_decision_creates_and_closes_case(scanner_alert, safe_verdict, logger):
    enriched = EnrichedAlert(alert=scanner_alert, verdicts=[safe_verdict])
    correlation = CorrelationResult(enriched=enriched)
    decision = TriageDecision(score=0.1, decision="closed_auto", reasons=["known benign scanner"])
    thehive = _thehive_mock(case_id="case-2")

    case_id = handle_decision(correlation, decision, thehive, logger)

    assert case_id == "case-2"
    thehive.close_case.assert_called_once()
    args, kwargs = thehive.close_case.call_args
    assert args[0] == "case-2"
    assert kwargs["resolution_status"] == "FalsePositive"


def test_enrichment_notes_added_per_verdict(brute_force_alert, malicious_verdict, logger):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict, malicious_verdict])
    correlation = CorrelationResult(enriched=enriched)
    decision = TriageDecision(score=0.9, decision="escalated", reasons=[])
    thehive = _thehive_mock()

    handle_decision(correlation, decision, thehive, logger)

    assert thehive.add_enrichment_note.call_count == 2
