"""Conservative coverage summaries. Execution success is never a security verdict."""
from __future__ import annotations


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
