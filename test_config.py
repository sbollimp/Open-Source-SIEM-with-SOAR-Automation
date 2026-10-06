import os

from soar_automation.utils.config import Config


def test_env_var_interpolation(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_SOAR_SECRET", "s3cr3t")
    config_file = tmp_path / "config.yaml"
    config_file.write_text("""
        thehive:
          api_key: "${TEST_SOAR_SECRET}"
          url: "http://localhost:9000"
        """)

    config = Config.load(config_file)

    assert config.get("thehive.api_key") == "s3cr3t"
    assert config.get("thehive.url") == "http://localhost:9000"


def test_missing_env_var_resolves_to_empty_string(tmp_path):
    os.environ.pop("TOTALLY_UNSET_SOAR_VAR", None)
    config_file = tmp_path / "config.yaml"
    config_file.write_text('wazuh:\n  password: "${TOTALLY_UNSET_SOAR_VAR}"\n')

    config = Config.load(config_file)

    assert config.get("wazuh.password") == ""


def test_missing_config_file_raises(tmp_path):
    missing = tmp_path / "does_not_exist.yaml"
    try:
        Config.load(missing)
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_section_and_default_lookup(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("triage:\n  auto_close_score_below: 0.25\n")
    config = Config.load(config_file)

    assert config.section("triage")["auto_close_score_below"] == 0.25
    assert config.get("triage.nonexistent", "fallback") == "fallback"
