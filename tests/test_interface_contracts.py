"""Legacy browser bundles stay removed; the new studio is separately opt-in."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/'mobileag/web'


def test_web_ui_template_and_static_bundle_are_absent():
    assert not (ROOT/'templates').exists()
    assert not (ROOT/'static').exists()


def test_optional_web_workbench_is_absent():
    assert not (ROOT.parent / 'workbench').exists()
    package_config = (ROOT.parents[1] / 'pyproject.toml').read_text()
    assert 'workbench/assets' not in package_config
