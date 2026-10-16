"""Conservative coverage summaries. Execution success is never a security verdict."""
from __future__ import annotations


# A deliberately conservative crosswalk from existing analyzer coverage to
# review surfaces. A mapped analyzer only means its bounded checks ran; it does
# not mean the surface was exhaustively tested or secure.
_SURFACE_ANALYZERS = {
    'manifest_component_inventory': ('manifest',),
    'ipc_intent_calls': ('android_surface.categories.intent',),
    'serialization': ('android_surface.categories.serialization', 'taint.serialization'),
    'files_uri_grants': ('manifest.provider_path_inventory',),
    'provider_path_configuration': ('manifest.provider_path_inventory',),
    'storage_backup_logging': ('manifest.backup_rules_inventory', 'android_surface.categories.logging',
                               'android_surface.categories.storage'),
    'webview_deep_links': ('android_surface.categories.webview', 'android_surface.categories.deep_links',
                           'taint.webview'),
    'network_api_authentication': ('auth_session', 'api_mapping'),
    'cryptography_native': ('crypto_metadata', 'nsc', 'native'),
}

_SURFACE_GAPS = {
    'manifest_component_inventory': 'parsed manifest only; merged installed manifest and effective caller authorization are not validated',
    'ipc_intent_calls': 'bounded lexical call inventory; caller-controlled dataflow and runtime authorization are not established',
    'serialization': 'only bounded ObjectInputStream flows from modeled sources are traced; other serializers, filters, guards, URI grants and runtime reachability remain unresolved',
    'files_uri_grants': 'configured roots/grant declarations only; URI-grant issuance and caller access are not tested',
    'provider_path_configuration': 'resource configuration only; provider implementation and sensitive files exposed are unknown',
    'storage_backup_logging': 'backup rules, lexical log sites and sensitive-identifier preference-write leads are inventoried only; data sensitivity, encryption, effective backup behavior and accessibility are not validated',
    'webview_deep_links': 'bounded lexical/manifest and modeled taint-sink review; effective origin, caller reachability, bridge behavior and runtime flow remain unproven',
    'network_api_authentication': 'endpoint/session inventory does not establish authentication or server authorization behavior',
    'cryptography_native': 'literal Java/Kotlin factory calls and TLS/native indicators do not establish key safety, full API use, or runtime call reachability',
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
        missing_paths = [path for path, record in records if record is None]
        records = [(path, record) for path, record in records if record is not None]
        statuses = [record.get('static_status') for _, record in records]
        if not records or all(status in (None, 'not_started', 'not_tested', 'not_selected') for status in statuses):
            analysis_state = 'not_tested'
        elif all(status in ('completed', 'analyzed', 'analyzed_heuristically', 'completed_heuristically') for status in statuses):
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
        candidate_paths = [path for path, record in records
                           if type(record.get('candidate_count')) is int and record['candidate_count'] > 0]
        evidence_state = ('not_applicable' if analysis_state == 'not_applicable' else
                          'candidate' if candidate_paths else 'not_tested')
        gap_reasons = [f'{path}: coverage not recorded' for path in missing_paths]
        if not records:
            gap_reasons.append('no analyzer mapped to this surface')
        else:
            for path, record in records:
                status = record.get('static_status')
                if status not in ('completed', 'analyzed', 'analyzed_heuristically',
                                  'completed_heuristically', 'not_applicable'):
                    gap_reasons.append(f"{path}: static status {status if isinstance(status, str) else 'not_recorded'}")
                skipped = record.get('source_files_skipped')
                if type(skipped) is int and skipped > 0:
                    gap_reasons.append(f'{path}: {skipped} source file(s) skipped')
                reasons = record.get('limit_reasons')
                if isinstance(reasons, dict):
                    for reason, count in sorted(reasons.items()):
                        if isinstance(reason, str) and type(count) is int and count > 0:
                            gap_reasons.append(f'{path}: limit {reason} reached ({count})')
            if runtime_state == 'not_tested':
                gap_reasons.append('runtime behavior not tested')
            elif runtime_state == 'incomplete':
                gap_reasons.append('runtime evidence is incomplete')
        surface_gap = _SURFACE_GAPS.get(surface)
        if surface_gap:
            gap_reasons.append(surface_gap)
        rows[surface] = {
            'analysis_state': analysis_state,
            'runtime_state': runtime_state,
            'evidence_state': evidence_state,
            'proof_status': 'not_proven',
            'independently_verified': False,
            'candidate_evidence_paths': candidate_paths,
            'mapped_coverage_paths': [path for path, _ in records],
            'missing_coverage_paths': missing_paths,
            'static_statuses': statuses,
            'recorded_counts': {
                path: {key: record[key] for key in ('component_count', 'exported_component_count', 'candidate_count',
                                                    'provider_count', 'unresolved_count')
                       if type(record.get(key)) is int}
                for path, record in records
                if any(type(record.get(key)) is int for key in ('component_count', 'exported_component_count',
                                                                 'candidate_count', 'provider_count', 'unresolved_count'))
            },
            'gap': 'no analyzer mapped to this surface' if not records else surface_gap,
            'gap_reasons': gap_reasons,
        }
    return {
        'schema_version': 1,
        'surfaces': rows,
        'exhaustive': False,
            'security_verdict': 'not_established',
        'limitations': [
            'Analyzer execution is not proof of runtime reachability or exploitability.',
            'No surface state establishes absence of vulnerabilities.',
            'Effective runtime manifest authorization, URI-grant issuance/access validation, full serialization dataflow, and comprehensive storage/backup/logging coverage remain unproven.',
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
