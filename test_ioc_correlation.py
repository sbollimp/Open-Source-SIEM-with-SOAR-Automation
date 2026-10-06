from unittest.mock import MagicMock

from soar_automation.integrations.misp_client import MispMatch
from soar_automation.playbooks.alert_enrichment import EnrichedAlert
from soar_automation.playbooks.ioc_correlation import correlate_and_enrich_intel


def test_correlate_finds_existing_match(brute_force_alert, malicious_verdict, logger):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    misp = MagicMock()
    misp.lookup.return_value = MispMatch(
        value="203.0.113.50", observable_type="ip", event_id="42", event_info="known C2", tags=["tlp:amber"]
    )

    result = correlate_and_enrich_intel(enriched, misp, logger, push_confidence_threshold=0.75)

    assert len(result.existing_matches) == 1
    # already known -> should NOT attempt to push again
    misp.push_ioc.assert_not_called()


def test_correlate_pushes_new_malicious_ioc(brute_force_alert, malicious_verdict, logger):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    misp = MagicMock()
    misp.lookup.return_value = None
    misp.push_ioc.return_value = "uuid-123"

    result = correlate_and_enrich_intel(enriched, misp, logger, push_confidence_threshold=0.5)

    assert result.newly_pushed == ["203.0.113.50"]
    misp.push_ioc.assert_called_once()


def test_correlate_does_not_push_below_confidence_threshold(brute_force_alert, malicious_verdict, logger):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    misp = MagicMock()
    misp.lookup.return_value = None

    # malicious_verdict's taxonomy has 1 "malicious" mention -> confidence ~0.7
    result = correlate_and_enrich_intel(enriched, misp, logger, push_confidence_threshold=0.99)

    assert result.newly_pushed == []
    misp.push_ioc.assert_not_called()


def test_correlate_skips_safe_verdicts(scanner_alert, safe_verdict, logger):
    enriched = EnrichedAlert(alert=scanner_alert, verdicts=[safe_verdict])
    misp = MagicMock()
    misp.lookup.return_value = None

    result = correlate_and_enrich_intel(enriched, misp, logger, push_confidence_threshold=0.1)

    assert result.newly_pushed == []
    misp.push_ioc.assert_not_called()


def test_correlate_handles_misp_push_failure_gracefully(brute_force_alert, malicious_verdict, logger):
    enriched = EnrichedAlert(alert=brute_force_alert, verdicts=[malicious_verdict])
    misp = MagicMock()
    misp.lookup.return_value = None
    misp.push_ioc.side_effect = RuntimeError("MISP unreachable")

    result = correlate_and_enrich_intel(enriched, misp, logger, push_confidence_threshold=0.5)

    assert result.newly_pushed == []  # failed push shouldn't be recorded as success
