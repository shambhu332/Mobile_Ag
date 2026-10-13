"""Conservative coverage summaries. Execution success is never a security verdict."""
from __future__ import annotations


# A deliberately conservative crosswalk from existing analyzer coverage to
# review surfaces. A mapped analyzer only means its bounded checks ran; it does
# not mean the surface was exhaustively tested or secure.
_SURFACE_ANALYZERS = {
    'ipc_intent_calls': ('android_surface.categories.intent',),
    'serialization': (),
    'files_uri_grants': (),
    'storage_backup_logging': (),
    'webview_deep_links': ('android_surface.categories.webview', 'android_surface.categories.deep_links'),
    'network_api_authentication': ('auth_session', 'api_mapping'),
    'cryptography_native': ('nsc', 'native'),
}


def _coverage_at_path(coverage: dict, path: str) -> dict | None:
    value = coverage
    for part in path.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value if isinstance(value, dict) else None


def review_surface_ledger(coverage: dict | None) -> dict:
    """Expose a stable review-surface crosswalk without upgrading evidence.

    `analysis_state` records only analyzer execution metadata. `evidence_state`
    stays `not_proven`: this ledger does not establish reachability, a finding,
    runtime behavior, or absence of vulnerabilities.
    """
    coverage = coverage if isinstance(coverage, dict) else {}
    rows = {}
    for surface, paths in _SURFACE_ANALYZERS.items():
        records = [(path, _coverage_at_path(coverage, path)) for path in paths]
        records = [(path, record) for path, record in records if record is not None]
        statuses = [record.get('static_status') for _, record in records]
        if not records or all(status in (None, 'not_started', 'not_tested', 'not_selected') for status in statuses):
            analysis_state = 'not_tested'
        elif all(status in ('completed', 'analyzed') for status in statuses):
            analysis_state = 'analyzed'
        elif all(status == 'not_applicable' for status in statuses):
            analysis_state = 'not_applicable'
        else:
            analysis_state = 'incomplete'
        runtime_statuses = [record.get('runtime_status') for _, record in records]
        if runtime_statuses and all(status in ('completed', 'observed') for status in runtime_statuses):
            runtime_state = 'observed'
        elif any(status is not None and status not in ('not_tested', 'not_started', 'not_selected')
                 for status in runtime_statuses):
            runtime_state = 'incomplete'
        else:
            runtime_state = 'not_tested'
        rows[surface] = {
            'analysis_state': analysis_state,
            'runtime_state': runtime_state,
            'evidence_state': 'not_proven',
            'mapped_coverage_paths': [path for path, _ in records],
            'static_statuses': statuses,
            'gap': 'no analyzer mapped to this surface' if not records else None,
        }
    return {
        'schema_version': 1,
        'surfaces': rows,
        'exhaustive': False,
        'security_verdict': 'not_established',
        'limitations': [
            'Analyzer execution is not proof of runtime reachability or exploitability.',
            'No surface state establishes absence of vulnerabilities.',
            'Manifest authorization, serialization, file/URI grants, and storage/backup/logging have no dedicated mapped analyzer yet.',
        ],
    }


def guided_coverage(document: dict) -> dict:
    """Summarize persisted observations only; never infer login or exploit proof.

    The current guided DAST stage observes UI and requires separate action review.
    Even a populated screen map is not evidence of authenticated workflow coverage.
    """
    stages = document.get('stages', {})
    rows = {}
    gaps = []
    for name in ('sast', 'api', 'dast', 'llm'):
        stage = stages.get(name, {})
        status = stage.get('status', 'not_recorded')
        selected = status != 'not_selected'
        row = {'execution_status': status, 'selected': selected}
        if name == 'sast':
            row['assessment_coverage'] = stage.get('assessment_coverage', 'unknown')
            if selected and (status != 'completed' or row['assessment_coverage'] != 'recorded_no_static_gaps'):
                gaps.append('sast: incomplete or unknown static coverage')
        elif name == 'api':
            row.update(executed_requests=stage.get('executed', 0),
                       untested_requests=stage.get('untested'),
                       authorization_validation='operator_imported_comparison' if document.get('authorization_comparisons') else 'not_tested',
                       imported_comparisons=len(document.get('authorization_comparisons', [])))
            if selected:
                gaps.append('api: no independently verified multi-account authorization coverage')
        elif name == 'dast':
            navigation = document.get('latest_navigation_report', {})
            device = navigation.get('application_map', {}).get('device_metadata', stage.get('device_metadata', {}))
            row.update(device_metadata=device, runtime_artifact_binding='not_verified',
                       observed_screens=len(navigation['screen_graph']['nodes']) if 'screen_graph' in navigation else stage.get('screens', 0),
                       authentication_status='not_verified', account_role='not_recorded',
                       workflow_coverage='not_measured', os_build=device.get('fingerprint', 'not_recorded'),
                       declared_authentication_state=navigation.get('test_state', {}).get('authentication_state', stage.get('authentication_state', 'unknown')),
                       attacker_context='not_established', proof_status='not_proven')
            if selected:
                gaps.append('dast: UI mapping does not establish authentication, workflow coverage or exploitability')
        else:
            row['security_validation'] = 'not_performed_by_metadata_review'
        if selected and status not in {'completed', 'completed_with_observations'}:
            gaps.append(f'{name}: execution {status}')
        rows[name] = row
    selected_count = sum(row['selected'] for row in rows.values())
    if not selected_count:
        # An all-not-selected/empty legacy record is not evidence of a
        # static-only assessment. Keep its state distinct from a bounded SAST
        # run so the UI/report cannot imply that any analysis took place.
        gaps.append('assessment: no stages selected or recorded')
    coverage_state = ('unknown' if not selected_count else
                      'partial' if gaps else 'bounded_static_only')
    return {'schema_version': 1, 'artifact_sha256': document.get('artifact_sha256'),
            'package_name': document.get('package_name'), 'stages': rows,
            'assessment_coverage': coverage_state,
            'gaps': gaps, 'exhaustive': False, 'security_verdict': 'not_established',
            'independently_verified_exploits': 0}
