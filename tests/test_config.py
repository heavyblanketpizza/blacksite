from pathlib import Path

import pytest

from blacksite.config import ConfigError, as_dict, feature_summary, load_settings


def test_features_default_to_off(tmp_path: Path) -> None:
    settings = load_settings(environ={}, cwd=tmp_path)
    assert feature_summary(settings) == {"rag": "off", "cases": "off", "playbook": "off"}
    assert settings.learning.require_approval is True
    assert settings.rag.docs_dir == tmp_path / "knowledge"
    assert settings.auth.totp_enabled is False


def test_totp_can_be_restored_by_config_env_or_override(tmp_path: Path) -> None:
    config = tmp_path / "blacksite.toml"
    config.write_text("[auth]\ntotp_enabled = true\n", encoding="utf-8")
    assert load_settings(config, environ={}).auth.totp_enabled is True
    assert load_settings(config, environ={"BLACKSITE__AUTH__TOTP_ENABLED": "false"}).auth.totp_enabled is False
    assert load_settings(config, ["auth.totp_enabled=true"],
                         {"BLACKSITE__AUTH__TOTP_ENABLED": "false"}).auth.totp_enabled is True


def test_file_env_and_overrides_apply_in_order(tmp_path: Path) -> None:
    config = tmp_path / "conf" / "blacksite.toml"
    config.parent.mkdir()
    config.write_text(
        '[rag]\nenabled = true\nmode = "inject"\ndocs_dir = "library"\n'
        "[learning.playbook]\nenabled = true\n",
        encoding="utf-8",
    )
    environ = {"BLACKSITE__RAG__MODE": "tool", "BLACKSITE__LEARNING__CASES__ENABLED": "on"}
    settings = load_settings(config, ["learning.playbook.enabled=false", "rag.top_k=3"], environ, tmp_path)

    assert settings.rag.enabled is True
    assert settings.rag.mode == "tool"  # environment beats the file
    assert settings.rag.top_k == 3
    assert settings.rag.docs_dir == config.parent / "library"  # relative to the config file
    assert settings.learning.cases.enabled is True
    assert settings.learning.playbook.enabled is False  # --set beats both
    assert feature_summary(settings)["rag"] == "on (tool, bm25)"


def test_default_config_file_is_found_in_cwd(tmp_path: Path) -> None:
    (tmp_path / "blacksite.toml").write_text("[learning.cases]\nenabled = true\nmode = 'inject'\n", encoding="utf-8")
    assert feature_summary(load_settings(environ={}, cwd=tmp_path))["cases"] == "on (inject)"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ("rag.enabeld=true", "Unknown setting rag.enabeld"),
        ("rag.mode=always", "must be one of tool, inject"),
        ("rag.enabled=maybe", "must be true or false"),
        ("rag.top_k=0", "must be positive"),
        ("rag", "must look like section.key=value"),
        ("rag.enabled.extra=1", "is a value, not a section"),
    ],
)
def test_invalid_settings_are_rejected_with_the_setting_name(tmp_path: Path, override: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        load_settings(overrides=["rag.enabled=true", override], environ={}, cwd=tmp_path)


def test_missing_config_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_settings(tmp_path / "missing.toml", environ={}, cwd=tmp_path)


def test_example_config_documents_the_defaults(tmp_path: Path) -> None:
    example = Path(__file__).parents[1] / "blacksite.example.toml"
    documented = load_settings(example, environ={}, cwd=tmp_path)
    defaults = load_settings(environ={}, cwd=example.parent)
    assert as_dict(documented) == as_dict(defaults)
