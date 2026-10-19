"""Browser UI assets and routes are intentionally absent; API and CLI remain."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_browser_ui_templates_and_static_assets_are_present():
    assert not (ROOT / 'mobileag' / 'studio').exists()
    assert not (ROOT / 'mobileag' / 'workbench').exists()
    web = ROOT / 'mobileag' / 'web'
    assert (web / 'templates').exists()
    assert (web / 'static').exists()
    assert 'studio/assets' not in (ROOT / 'pyproject.toml').read_text()


def test_cli_does_not_offer_ui_toggle():
    cli = (ROOT / 'mobileag' / 'cli.py').read_text()
    assert 'Enable the local browser workspace' not in cli
    assert '@click.option("--ui"' not in cli
