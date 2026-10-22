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


def guided_runtime_surface_ledger(document: dict) -> dict:
    """Inventory runtime surfaces actually observed by guided assessment.

    This intentionally separates a small set of bounded observations from
    vulnerability testing. A surface becomes ``observed`` only when the
    corresponding persisted receipt exists; all other surfaces remain explicit
    gaps. No row can establish safety or exploitability.
    """
    stages = document.get('stages', {}) if isinstance(document, dict) else {}
    dast = stages.get('dast', {}) if isinstance(stages, dict) else {}
    if not isinstance(dast, dict):
        dast = {}
    identity = dast.get('runtime_artifact_identity', {})
    permissions = dast.get('runtime_permission_snapshot', {})
    logs = dast.get('runtime_log_observation', {})
    navigation = document.get('latest_navigation_report', {}) if isinstance(document, dict) else {}
    if not isinstance(navigation, dict):
        navigation = {}
    graph = navigation.get('screen_graph', {})
    nodes = graph.get('nodes', []) if isinstance(graph, dict) else []
    screens = len(nodes) if isinstance(nodes, list) else 0
    if not screens:
        screens = dast.get('screens', 0)
    comparisons = document.get('authorization_dynamic_comparisons', []) if isinstance(document, dict) else []

    definitions = {
        'installed_artifact_binding': ('not_tested', None,
            'Exact single-APK identity check was not recorded.'),
        'runtime_permission_state': ('not_tested', None,
            'Installed Package Manager permission snapshot was not recorded.'),
        'startup_ui_logcat': ('not_tested', None,
            'Bounded target-attributed before/after logcat review was not completed.'),
        'ui_navigation_mapping': ('not_tested', None,
            'No mapped screens were recorded; navigation mapping is not workflow testing.'),
        'ipc_and_intent_authorization': ('not_tested', None,
            'No runtime IPC authorization matrix is implemented in guided DAST.'),
        'serialization_and_parser_runtime': ('not_tested', None,
            'No runtime untrusted-serialization/parser test is implemented in guided DAST.'),
        'files_providers_and_uri_grants': ('not_tested', None,
            'No runtime file/provider/URI-grant access test is implemented in guided DAST.'),
        'webview_bridges_and_navigation': ('not_tested', None,
            'No runtime WebView origin/bridge behavior test is implemented in guided DAST.'),
        'network_tls_and_traffic': ('not_tested', None,
            'Transparent HTTPS capture and runtime TLS validation are not implemented.'),
        'api_authorization_pair': ('not_tested', None,
            'No live two-account GET comparison receipt was recorded.'),
        'crypto_and_native_runtime': ('not_tested', None,
            'Runtime crypto and native instrumentation are not implemented in guided DAST.'),
        'business_logic_and_mutating_flows': ('not_tested', None,
            'Business-logic/write/payment flows are outside the implemented guided DAST.'),
        'ios_runtime': ('not_tested', None,
            'Native iOS live automation is not implemented.'),
    }
    if isinstance(identity, dict) and identity.get('status') == 'matched' and identity.get('apk_count') == 1:
        definitions['installed_artifact_binding'] = ('observed', 'stages.dast.runtime_artifact_identity',
            'Single installed APK matched the analyzed artifact hash; this is identity evidence only.')
    if isinstance(permissions, dict) and permissions.get('status') == 'observed':
        definitions['runtime_permission_state'] = ('observed', 'stages.dast.runtime_permission_snapshot',
            'Bounded requested/granted permission metadata was observed; not a vulnerability verdict.')
    if isinstance(logs, dict) and logs.get('status') == 'observed':
        definitions['startup_ui_logcat'] = ('observed', 'stages.dast.runtime_log_observation',
            'Bounded target-attributed logcat delta was examined; no finding absence is inferred.')
    if type(screens) is int and screens > 0:
        definitions['ui_navigation_mapping'] = ('observed', 'latest_navigation_report.screen_graph',
            'Screen mapping was recorded; it does not establish authenticated workflow coverage.')
    if isinstance(comparisons, list) and comparisons:
        definitions['api_authorization_pair'] = ('observed', 'authorization_dynamic_comparisons',
            'A bounded read-only account-pair observation was recorded; it is not independent authorization proof.')

    surfaces = {
        name: {
            'runtime_state': state,
            'evidence_reference': reference,
            'proof_status': 'not_proven',
            'independently_verified': False,
            'gap': reason,
        }
        for name, (state, reference, reason) in definitions.items()
    }
    return {
        'schema_version': 1,
        'surfaces': surfaces,
        'observed_count': sum(row['runtime_state'] == 'observed' for row in surfaces.values()),
        'not_tested_count': sum(row['runtime_state'] == 'not_tested' for row in surfaces.values()),
        'exhaustive': False,
        'security_verdict': 'not_established',
        'limitations': [
            'Observed means only that the named bounded runtime receipt exists.',
            'Not tested is a coverage gap, not a pass.',
            'This inventory is not exhaustive and does not establish absence of vulnerabilities.',
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
            comparisons=document.get('authorization_comparisons',[])
            live_comparisons=document.get('authorization_dynamic_comparisons',[])
            row.update(executed_requests=stage.get('executed', 0),
                       untested_requests=stage.get('untested'),
                       authorization_validation=('live_scoped_read_only_probe' if live_comparisons else
                           'operator_imported_comparison' if comparisons else 'not_tested'),
                       imported_comparisons=len(comparisons),
                       live_read_only_pair_probes=len(live_comparisons),
                       authorization_probe_attempts=document.get('authorization_probe_attempts',0))
            if selected:
                gaps.append('api: multi-account authorization evidence is bounded and unverified; exhaustive authorization coverage is not established')
        elif name == 'dast':
            navigation = document.get('latest_navigation_report', {})
            device = navigation.get('application_map', {}).get('device_metadata', stage.get('device_metadata', {}))
            identity=stage.get('runtime_artifact_identity',{})
            permission_snapshot=stage.get('runtime_permission_snapshot',{})
            log_observation=stage.get('runtime_log_observation',{})
            binding=('matched_single_apk' if identity.get('status')=='matched' and identity.get('apk_count')==1
                     else identity.get('status','not_verified'))
            row.update(device_metadata=device, runtime_artifact_binding=binding,
                       runtime_permission_snapshot_status=permission_snapshot.get('status','not_tested'),
                       runtime_requested_permission_count=permission_snapshot.get('requested_permission_count'),
                       runtime_granted_permission_count=permission_snapshot.get('granted_permission_count'),
                       runtime_static_permission_comparison=permission_snapshot.get('static_comparison_status','not_available'),
                       runtime_log_status=log_observation.get('status','not_tested'),
                       runtime_log_candidates=log_observation.get('candidate_count'),
                       observed_screens=len(navigation['screen_graph']['nodes']) if 'screen_graph' in navigation else stage.get('screens', 0),
                       authentication_status='not_verified', account_role='not_recorded',
                       workflow_coverage='not_measured', os_build=device.get('fingerprint', 'not_recorded'),
                       declared_authentication_state=navigation.get('test_state', {}).get('authentication_state', stage.get('authentication_state', 'unknown')),
                       attacker_context='not_established', proof_status='not_proven')
            if selected:
                gaps.append('dast: UI mapping does not establish authentication, workflow coverage or exploitability')
                if permission_snapshot.get('status')!='observed':
                    gaps.append('dast: installed runtime permission state was not observed')
                if log_observation.get('status')!='observed':
                    gaps.append('dast: target-attributed startup/UI log review was not completed')
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
    runtime_surfaces = guided_runtime_surface_ledger(document)
    return {'schema_version': 1, 'artifact_sha256': document.get('artifact_sha256'),
            'package_name': document.get('package_name'), 'stages': rows,
            'runtime_surfaces': runtime_surfaces,
            'assessment_coverage': coverage_state,
            'gaps': gaps, 'exhaustive': False, 'security_verdict': 'not_established',
            'independently_verified_exploits': 0}
