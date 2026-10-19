"""The API stays default; the evidence-first browser Studio is explicit opt-in."""
import importlib
from fastapi.testclient import TestClient


def test_api_only_default_and_opt_in_studio(monkeypatch):
    web = importlib.import_module('mobileag.web.app')
    monkeypatch.setattr(web.app.state, 'studio_enabled', False, raising=False)
    client = TestClient(web.app)
    root = client.get('/')
    assert root.status_code == 200
    assert root.json()['browser_ui'] == 'disabled'
    assert client.get('/ui').status_code == 404

    from mobileag.studio import enable_studio
    enable_studio(web.app)
    page = client.get('/ui')
    assert page.status_code == 200
    assert 'See the surface' in page.text
    assert client.get('/ui/app.js').status_code == 200
    assert client.get('/ui/style.css').status_code == 200
    # API authorization remains independent of the public UI bundle.
    assert client.get('/api/studio/catalog').status_code == 401


def test_cli_documents_opt_in_without_changing_default():
    from click.testing import CliRunner
    from mobileag.cli import main
    result = CliRunner().invoke(main, ['web', '--help'])
    assert result.exit_code == 0
    assert '--ui' in result.output
    assert 'optional evidence-first browser Studio' in result.output
