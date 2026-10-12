"""Shipped interface contracts; actual behavior is covered by the browser harness."""
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]/'mobileag/web'

@pytest.mark.parametrize('asset',['interface.js','interface.css','experience.js','experience.css'])
def test_shared_interface_asset_is_shipped_and_referenced(asset):
    assert (ROOT/'static'/asset).is_file()
    assert '/static/'+asset in (ROOT/'templates/index.html').read_text()

@pytest.mark.parametrize('claim',['SECURE GATEWAY','OWASP FLAW DETECTED','Bearer mock_token_for_audit','No OWASP API Top 10 vulnerabilities detected'])
def test_api_ui_does_not_invent_success_or_credentials(claim):
    assert claim not in (ROOT/'static/api.js').read_text()

def test_offline_modal_does_not_offer_automatic_bypass_controls():
    html=(ROOT/'templates/index.html').read_text()
    assert 'modal-opt-bypass-root' not in html and 'modal-opt-bypass-ssl' not in html
    console=(ROOT/'static/console.js').read_text()
    assert 'Uploading alone never runs tests' in html or 'Uploading alone never runs tests' in console

def test_assessment_has_grouped_review_and_preserved_provider_gates():
    js=(ROOT/'static/assessment.js').read_text()
    assert "make('fieldset'" in js and 'assessment-plan-summary' in js
    assert 'llm_metadata_egress_confirmed:fields.egress.checked' in js
    assert 'providersLoaded' in js and 'uploading' in js

def test_native_notes_prompt_replaced_by_cancellable_labelled_dialog():
    assert 'window.prompt(' not in (ROOT/'static/findings.js').read_text()
    js=(ROOT/'static/interface.js').read_text()
    assert 'triage-validation-notes' in js and 'notes.required=true' in js
    assert "dialog.addEventListener('close'" in js


def test_llm_configuration_has_one_selector_and_assessment_local_consent():
    html=(ROOT/'templates/index.html').read_text()
    js=(ROOT/'static/assessment.js').read_text()
    assert 'id="configuration-llm-controls"' in html
    assert 'id="settings-open-ai"' not in html
    assert "providerGroup.append(fields[key].parentElement)" in js
    assert "['Optional AI review',['egress','fallback-egress']]" in js
    assert 'assessment-ai-summary' in js and 'assessment-configure-ai' in js
    assert "addEventListener('click',openConfiguration)" in js


def test_advanced_workspace_navigation_is_non_executing_and_text_safe():
    js=(ROOT/'static/experience.js').read_text()
    assert 'workspace-command-dialog' in js and 'workspace-command-search' in js
    assert 'workspace-density' in js and 'workspace-focus-toggle' in js
    assert "document.getElementById('nav-'+id)?.click()" in js
    assert 'innerHTML' not in js and 'localStorage' not in js
    assert "fetch(" not in js and 'Rotate session token' not in js
    assert 'provider-approval-checklist' in js and 'Actual token usage' in js
    assert "window.addEventListener('llm-configuration-changed'" in js
