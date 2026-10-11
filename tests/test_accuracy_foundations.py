import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from mobileag.analysis.evaluation import evaluate_instances, assert_disjoint, validate_corpus
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.reporting.coverage import guided_coverage
from mobileag.reporting.report_engine import ReportEngine

FIXTURE = Path(__file__).parent / 'fixtures/accuracy_instances.json'


def corpus():
    return json.loads(FIXTURE.read_text())


@pytest.mark.parametrize('lexical', [False, True])
def test_location_aware_candidate_patched_safe_pairs(lexical):
    engine = TaintEngine()
    if lexical:
        engine._java_ast.available = False
    result = evaluate_instances(corpus(), engine.analyze_source_content)
    assert (result['tp'], result['fp'], result['fn'], result['failed_cases']) == (2, 0, 0, 0)
    assert len(result['corpus_sha256']) == 64


def test_wrong_location_same_cwe_does_not_get_credit():
    data = corpus(); data['cases'] = data['cases'][:1]
    report = evaluate_instances(data, lambda *args: [SimpleNamespace(cwe_id='CWE-829', line_number=5)])
    assert (report['tp'], report['fp'], report['fn']) == (0, 1, 1)


def test_duplicate_reports_and_distinct_expected_locations():
    data = corpus(); data['cases'] = data['cases'][:1]
    data['cases'][0]['expected'].append({'cwe': 'CWE-829', 'sink_line': 5})
    report = evaluate_instances(data, lambda *args: [SimpleNamespace(cwe_id='CWE-829', line_number=4)] * 3)
    assert (report['tp'], report['fn'], report['duplicate_reports']) == (1, 1, 2)


def test_exception_is_failure_even_for_negative_fixture():
    data = corpus(); data['cases'] = data['cases'][1:2]
    def broken(*args):
        raise RuntimeError('secret payload must not be returned')
    report = evaluate_instances(data, broken)
    assert report['failed_cases'] == 1
    assert report['precision'] is None
    assert 'secret payload' not in json.dumps(report)


def test_exact_content_leakage_and_invalid_labels_rejected():
    data = corpus(); reference = copy.deepcopy(data)
    for case in reference['cases']:
        case['id'] += '_renamed'
    with pytest.raises(ValueError, match='overlaps'):
        assert_disjoint(data, reference)
    data['cases'][0]['expected'][0]['sink_line'] = True
    with pytest.raises(ValueError):
        validate_corpus(data)


@pytest.mark.parametrize('status', ['login_failed', 'typo', None, {}, 'analyzed_heuristically'])
def test_report_unknown_static_states_fail_closed(status):
    report = ReportEngine()._prepare_data({'scan_id': 'fixture', 'coverage': {'test': {'static_status': status}}})
    assert report['assessment_coverage'] == 'partial'
    assert report['coverage_gaps']


def test_report_errors_cannot_produce_gap_free_assessment():
    report = ReportEngine()._prepare_data({'scan_id': 'fixture', 'coverage': {'test': {'static_status': 'completed'}}, 'errors': ['engine failed']})
    assert report['assessment_coverage'] == 'partial'


def test_completed_guided_execution_does_not_infer_login_or_api_authorization():
    report = guided_coverage({'stages': {'sast': {'status': 'completed'},
        'api': {'status': 'completed_with_observations', 'executed': 2},
        'dast': {'status': 'completed', 'screens': 9}, 'llm': {'status': 'completed'}}})
    assert report['assessment_coverage'] == 'partial'
    assert report['security_verdict'] == 'not_established'
    assert report['stages']['dast']['authentication_status'] == 'not_verified'
    assert report['stages']['api']['authorization_validation'] == 'not_tested'
    assert report['independently_verified_exploits'] == 0


def test_confirmation_gate_checks_schema_and_build_without_mutating_triage():
    from mobileag.reporting.evidence_contract import prepare_finding
    from mobileag.reporting.validation import bind_confirmation
    from tests.proof_fixtures import confirmation_evidence
    scan = {'artifact_sha256': 'a' * 64, 'package_name': 'org.example.synthetic', 'version': '1.0'}
    artifact = {**scan, 'app_version': '1.0'}
    finding = {'status': 'CONFIRMED', 'validation_evidence': bind_confirmation(confirmation_evidence(), scan)}
    accepted = prepare_finding(finding, artifact)
    assert accepted['status'] == 'CONFIRMED'
    assert accepted['evidence_assessment']['basis'] == 'analyst_attested'
    assert accepted['evidence_assessment']['independently_verified'] is False
    rejected = prepare_finding(finding, {**artifact, 'artifact_sha256': 'b' * 64})
    assert rejected['status'] == 'UNVERIFIED'
    assert finding['status'] == 'CONFIRMED'
    assert rejected['reported_status'] == 'CONFIRMED'


def test_raw_confirmation_flag_cannot_bypass_json_markdown_or_sarif_gate():
    from mobileag.reporting.finding import Finding
    from mobileag.reporting.sarif_exporter import SARIFExporter
    from mobileag.reporting.professional_report import ProfessionalReportExporter
    value = Finding(title='Synthetic', description='Synthetic test', status='CONFIRMED',
                    validation_evidence={'active': True, 'basis': 'analyst_attested'}).model_dump(mode='json')
    engine = ReportEngine()
    report = engine._prepare_data({'scan_id': 'fixture', 'filtered_findings': [value]})
    assert report['stats']['confirmed'] == 0
    assert 'Next investigation step' in engine._generate_markdown(report)
    sarif = SARIFExporter.generate_sarif([value])
    props = sarif['runs'][0]['results'][0]['properties']
    assert props['status'] == 'UNVERIFIED' and props['proof_basis'] == 'not_proven'
    assert 'Active analyst attestations: 0' in ProfessionalReportExporter().generate_report([value])


@pytest.mark.parametrize('lexical', [False, True])
def test_source_sink_trace_retains_uncertainty(lexical):
    engine = TaintEngine()
    if lexical:
        engine._java_ast.available = False
    case = corpus()['cases'][0]
    findings = engine.analyze_source_content(case['source'], 'fixture.java')
    assert findings
    for finding in findings:
        trace = finding.metadata['source_sink_trace']
        assert trace['source']['line'] == 3
        assert trace['sink']['line'] == 4
        assert trace['guards'] == 'not_resolved'
        assert trace['runtime_verified'] is False
        assert finding.status == 'UNVERIFIED'


@pytest.mark.parametrize('lexical', [False, True])
@pytest.mark.parametrize('primitive', ['int', 'float', 'long', 'boolean'])
def test_primitive_sql_concat_is_not_injection_but_mixed_string_remains_candidate(lexical, primitive):
    engine = TaintEngine()
    if lexical:
        engine._java_ast.available = False
    getter = {'int': 'getIntExtra', 'float': 'getFloatExtra', 'long': 'getLongExtra', 'boolean': 'getBooleanExtra'}[primitive]
    default = 'false' if primitive == 'boolean' else '0'
    code = f'''class Query {{ void run(Intent input, SQLiteDatabase db) {{
        {primitive} amount = input.{getter}("amount", {default});
        db.rawQuery("select * from payments where amount > " + amount, null);
    }} }}'''
    assert not [f for f in engine.analyze_source_content(code, 'query.java') if f.cwe_id == 'CWE-89']
    mixed = code.replace('db.rawQuery(', 'String extra = input.getStringExtra("query"); db.rawQuery(').replace('+ amount,', '+ amount + extra,')
    assert any(f.cwe_id == 'CWE-89' for f in engine.analyze_source_content(mixed, 'query.java'))


@pytest.mark.parametrize('expression', ['"sql" + obj.amount', '"sql" + convert(amount)', '"sql" + amount.toString()', '"sql" + letter', '"sql" + unknown'])
def test_numeric_guard_does_not_accept_unknown_or_character_values(expression):
    from mobileag.analysis.source_syntax import numeric_sql_concatenation
    assert not numeric_sql_concatenation(expression, 'int amount; char letter;')


def test_retest_does_not_mark_changed_status_as_fixed_root_cause():
    from mobileag.automation.report import regression
    before = {'results': [{'test_id': 'x', 'result': 'failed', 'executed': True, 'assertion': 'denied'}]}
    after = {'results': [{'test_id': 'x', 'result': 'passed', 'executed': True, 'assertion': 'denied'}]}
    result = regression(before, after)[0]
    assert result['verification_status'] == 'Assertion now passes'
    assert result['root_cause_fix_status'] == 'not_verified'
    after['results'][0]['assertion'] = 'different assertion'
    assert regression(before, after)[0]['verification_status'] == 'Unable to verify'
    after['results'][0]['assertion'] = 'denied'
    before['results'][0]['executed'] = False
    assert regression(before, after)[0]['verification_status'] == 'Unable to verify'


def test_changed_authentication_context_is_not_a_comparable_retest():
    from mobileag.automation.report import regression
    before = {'auth_state': 'logged_in', 'results': [{'test_id': 'x', 'result': 'failed', 'executed': True}]}
    after = {'auth_state': 'logged_out', 'results': [{'test_id': 'x', 'result': 'passed', 'executed': True}]}
    assert regression(before, after)[0]['verification_status'] == 'Unable to verify'


def test_runtime_device_observation_not_equated_to_artifact_or_login_proof():
    result = guided_coverage({'stages': {'dast': {'status': 'awaiting_action_review', 'screens': 1,
        'device_metadata': {'fingerprint': 'synthetic-build', 'root_shell_observed': True},
        'authentication_state': 'logged_in'}}})
    row = result['stages']['dast']
    assert row['os_build'] == 'synthetic-build'
    assert row['device_metadata']['root_shell_observed'] is True
    assert row['declared_authentication_state'] == 'logged_in'
    assert row['authentication_status'] == 'not_verified'
    assert row['runtime_artifact_binding'] == 'not_verified'
