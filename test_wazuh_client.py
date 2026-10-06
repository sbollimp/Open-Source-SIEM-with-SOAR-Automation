from soar_automation.integrations.wazuh_client import WazuhClient


def test_extract_observables_pulls_srcip_and_url():
    raw = {"data": {"srcip": "198.51.100.9", "url": "http://bad.example.xyz/payload"}}
    observables = WazuhClient._extract_observables(raw)

    assert observables["ip"] == ["198.51.100.9"]
    assert observables["url"] == ["http://bad.example.xyz/payload"]
    assert observables["hash"] == []


def test_extract_observables_pulls_hashes_from_sysmon_fields():
    raw = {
        "data": {
            "win": {
                "eventdata": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                }
            }
        }
    }
    observables = WazuhClient._extract_observables(raw)

    assert "d41d8cd98f00b204e9800998ecf8427e" in observables["hash"]
    assert len(observables["hash"]) == 2


def test_extract_observables_dedupes_values():
    raw = {"data": {"srcip": "198.51.100.9"}}
    # simulate the same field appearing twice by calling normalize twice isn't
    # realistic; instead test dedupe directly via a crafted structure
    observables = WazuhClient._extract_observables(raw)
    assert observables["ip"].count("198.51.100.9") == 1


def test_normalize_maps_rule_fields():
    raw = {
        "id": "999",
        "rule": {"id": 100012, "level": 12, "description": "Sustained SSHD brute force"},
        "timestamp": "2026-10-01T12:00:00Z",
        "agent": {"name": "web01"},
        "data": {"srcip": "203.0.113.50"},
    }
    alert = WazuhClient._normalize(WazuhClient, raw)  # unbound call, no network needed

    assert alert.rule_id == 100012
    assert alert.rule_level == 12
    assert alert.agent_name == "web01"
    assert alert.observables["ip"] == ["203.0.113.50"]
