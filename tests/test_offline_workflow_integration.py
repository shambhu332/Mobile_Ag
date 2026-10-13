"""Real offline analyzers wired into a synthetic orchestrator stage."""
import json
from pathlib import Path
from unittest.mock import AsyncMock
import pytest
from config.settings import Settings
from mobileag.analysis.auth_session_auditor import AuthSessionAuditor
from mobileag.analysis.firebase_auditor import FirebaseAuditor
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.core.orchestrator import Orchestrator
from mobileag.core.state import create_initial_state
from mobileag.reporting.report_engine import ReportEngine


def test_bounded_sources_skip_symlinks_and_large_files(tmp_path):
    outside = tmp_path.parent / 'outside-secret.java'
    outside.write_text('synthetic outside marker')
    (tmp_path / 'Link.java').symlink_to(outside)
    (tmp_path / 'Large.java').write_text('x' * 20)
    (tmp_path / 'Small.java').write_text('ok')
    reader = SourceInventory(max_file_bytes=10)
    rows = list(reader.read(tmp_path, {'.java'}))
    assert [(p.name, data) for p, data in rows] == [('Small.java', b'ok')]
    assert reader.coverage['source_files_skipped'] == 2
    assert reader.coverage['source_file_skip_reasons'] == {
        'symlink_entry': 1, 'file_size_limit': 1,
    }
    assert sum(reader.coverage['source_file_skip_reasons'].values()) == reader.coverage['source_files_skipped']
    assert reader.coverage['static_status'] == 'partial'


def test_entry_and_total_byte_budgets(tmp_path):
    for i in range(5):
        (tmp_path / f'{i}.java').write_text('12345')
    reader = SourceInventory(max_entries=2)
    assert len(list(reader.read(tmp_path, {'.java'}))) == 2
    assert reader.coverage['limits_reached']
    assert reader.coverage['limit_reasons'] == {'entry_budget': 1}
    reader = SourceInventory(max_total_bytes=6)
    assert len(list(reader.read(tmp_path, {'.java'}))) == 1
    assert reader.coverage['static_status'] == 'partial'
    assert reader.coverage['limit_reasons'] == {'total_byte_budget': 1}


@pytest.mark.asyncio
async def test_auth_comments_ignored_and_no_source_values_stored(tmp_path):
    source = tmp_path / 'Auth.java'
    source.write_text('// String password = "syntheticOpaqueCredential";')
    assert (await AuthSessionAuditor().analyze(tmp_path))['findings'] == []
    source.write_text('String password = "syntheticOpaqueCredential";')
    result = await AuthSessionAuditor().analyze(tmp_path)
    assert result['coverage']['candidate_count'] == 1
    assert 'syntheticOpaqueCredential' not in json.dumps([f.model_dump(mode='json') for f in result['findings']])
    assert result['coverage']['runtime_status'] == 'not_tested'


@pytest.mark.asyncio
async def test_firebase_configuration_counts_not_values(tmp_path):
    source = tmp_path / 'source'; source.mkdir()
    resources = tmp_path / 'resources'; resources.mkdir()
    (resources / 'google-services.json').write_text(json.dumps({
        'project_info': {'project_id': 'synthetic-project', 'firebase_url': 'https://synthetic-project.firebaseio.com', 'storage_bucket': 'synthetic-project.appspot.com'},
        'client': [{'api_key': [{'current_key': 'syntheticOpaqueCredential'}]}],
    }))
    auditor = FirebaseAuditor()
    result = await auditor.analyze(source, resources)
    assert result['coverage']['inventory_counts']['api_keys'] == 1
    assert result['coverage']['runtime_status'] == 'not_tested'
    assert len(result['findings']) == 2
    assert 'syntheticOpaqueCredential' not in json.dumps(result, default=str)
    assert 'synthetic-project' not in json.dumps(result, default=str)
    assert all(f.cvss_score == 0 and f.status.value == 'UNVERIFIED' for f in result['findings'])


@pytest.mark.asyncio
async def test_malformed_firebase_config_marks_partial(tmp_path):
    (tmp_path / 'google-services.json').write_text('{not-json')
    result = await FirebaseAuditor().analyze(tmp_path)
    assert result['coverage']['static_status'] == 'partial'
    assert result['findings'] == []


@pytest.mark.asyncio
async def test_real_offline_reviews_integrated_with_failure_coverage(monkeypatch, tmp_path):
    worker = Orchestrator(Settings(_env_file=None, offline=True))
    # Only the two analyzers under test read fixtures; no SDK/network/device work.
    for obj, method, value in [
        (worker._android_surface, 'analyze', {'findings': [], 'coverage': {'categories': {'webview': {'static_status': 'not_analyzed'}}}}),
        (worker._manifest_auditor, 'audit', []), (worker._secret_scanner, 'scan', []),
        (worker._code_reviewer, 'review', []), (worker._api_mapper, 'map_apis', ([], [])),
        (worker._native_analyzer, 'analyze', []), (worker._dependency_scanner, 'scan', []),
        (worker._nsc_auditor, 'audit_directory_async', []),
        (worker._bin_protection, 'audit_directory_async', []),
        (worker._rn_scanner, 'scan_directory_async', []),
    ]:
        monkeypatch.setattr(obj, method, AsyncMock(return_value=value))
    monkeypatch.setattr(worker._call_graph_engine, 'audit_smali_directory', lambda _: [])
    (tmp_path / 'Auth.java').write_text('String password = "syntheticOpaqueCredential";')
    (tmp_path / 'strings.xml').write_text('<string>https://synthetic.firebaseio.com</string>')
    state = create_initial_state('synthetic', 'unused', str(tmp_path))
    state.update(decompiled_path=str(tmp_path), resource_path=str(tmp_path))
    result = await worker._run_analysis(state)
    assert result['coverage']['engines']['auth_session'] == 'analyzed_heuristically'
    assert result['coverage']['engines']['firebase'] == 'analyzed_heuristically'
    assert len(result['raw_findings']) == 2
    assert 'syntheticOpaqueCredential' not in json.dumps(result)
    monkeypatch.setattr(worker._firebase_auditor, 'analyze', AsyncMock(side_effect=RuntimeError('synthetic failure')))
    result = await worker._run_analysis(state)
    assert result['coverage']['firebase']['static_status'] == 'incomplete'
    assert result['coverage']['engines']['firebase'] == 'incomplete'
    report = ReportEngine()._generate_markdown(ReportEngine()._prepare_data(result))
    assert 'auth_session: static=analyzed_heuristically' in report
    assert 'firebase: static=incomplete' in report
