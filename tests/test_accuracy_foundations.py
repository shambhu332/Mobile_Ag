import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from mobileag.analysis.evaluation import evaluate_instances, assert_disjoint, validate_corpus
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.reporting.coverage import guided_coverage, review_surface_ledger
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
    # The same-source type-qualified instance is intentionally measurable only
    # on the AST backend; lexical fallback must not claim the identity.
    expected_scores = (2, 2, 2, 0) if lexical else (4, 0, 0, 0)
    assert (result['tp'], result['fp'], result['fn'], result['failed_cases']) == expected_scores
    assert len(result['corpus_sha256']) == 64
    assert result['input_coverage'] == {
        'corpus_cases_submitted': 9, 'analyzer_invocations': 9, 'cases_completed': 9,
        'cases_failed': 0, 'cases_skipped': 0,
        'unsupported_constructs': {'status': 'not_measured', 'count': None},
        'unsupported_construct_labels': {
            'status': 'not_measured', 'cases_with_labels': 0, 'cases_submitted': 9,
            'label_occurrences': 0, 'by_construct': {},
            'scope': 'optional corpus-supplied annotations only; not automatic APK or language-coverage measurement',
        },
        'apk_extracted_source_files': {'status': 'not_in_scope', 'count': None},
    }


def test_corpus_unsupported_construct_labels_are_counted_without_claiming_coverage():
    data=corpus()
    data['cases'][0]['unsupported_constructs']=[{'name':'java.method_reference','line':1}]
    result=evaluate_instances(data,lambda *_: [])
    labels=result['input_coverage']['unsupported_construct_labels']
    assert labels['status']=='partial_corpus_labels'
    assert labels['cases_with_labels']==1 and labels['cases_submitted']==9
    assert labels['label_occurrences']==1
    assert labels['by_construct']=={'java.method_reference':{'case_occurrences':1}}
    assert result['input_coverage']['unsupported_constructs']=={'status':'not_measured','count':None}
    assert result['cases'][0]['unsupported_constructs']==[{'name':'java.method_reference','line':1}]


def test_corpus_unsupported_construct_labels_validate_shape_and_lines():
    data=corpus(); data['cases'][0]['unsupported_constructs']=[{'name':'../unsafe','line':1}]
    with pytest.raises(ValueError,match='names must be bounded identifiers'):
        evaluate_instances(data,lambda *_: [])
    data=corpus(); data['cases'][0]['unsupported_constructs']=[{'name':'java.lambda','line':999}]
    with pytest.raises(ValueError,match='must identify a source line'):
        evaluate_instances(data,lambda *_: [])


def test_evaluator_output_v5_published_schema_and_rejects_wrong_version():
    result=evaluate_instances(corpus(),lambda *_: [])
    schema_path=Path(__file__).resolve().parents[1]/'docs/schemas/sast-evaluation-output-v5.schema.json'
    schema=json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    validator=Draft202012Validator(schema)
    validator.validate(result)
    result['schema_version']=4
    assert list(validator.iter_errors(result))


@pytest.mark.parametrize('lexical', [False, True])
def test_evaluator_scores_two_real_flows_in_one_source_file(lexical):
    source = '''class Route {
 void first(Intent input, WebView view) {
  String a = input.getStringExtra("url");
  view.loadUrl(a);
 }
 void second(Intent input, WebView view) {
  String b = input.getStringExtra("url");
  view.loadUrl(b);
 }
}'''
    expected = [
        {'cwe': 'CWE-829', 'source_line': 3, 'source_method': 'first',
         'sink_line': 4, 'sink_method': 'first'},
        {'cwe': 'CWE-829', 'source_line': 7, 'source_method': 'second',
         'sink_line': 8, 'sink_method': 'second'},
    ]
    data = {'schema_version': 1, 'cases': [{'id': 'two_flows', 'language': 'java',
            'file_path': 'src/Route.java', 'source': source, 'expected': expected}]}
    engine = TaintEngine()
    if lexical:
        engine._java_ast.available = False
    result = evaluate_instances(data, engine.analyze_source_content)
    assert (result['tp'], result['fp'], result['fn'], result['failed_cases']) == (2, 0, 0, 0)
    patched = {**data, 'cases': [{**data['cases'][0],
                                  'source': source.replace('view.loadUrl(b);',
                                                           'view.loadUrl("https://fixed.example/");')} ]}
    negative_control = evaluate_instances(patched, engine.analyze_source_content)
    assert (negative_control['tp'], negative_control['fp'], negative_control['fn']) == (1, 0, 1)


def test_wrong_location_same_cwe_does_not_get_credit():
    data = corpus(); data['cases'] = data['cases'][:1]
    report = evaluate_instances(data, lambda *args: [SimpleNamespace(cwe_id='CWE-829', line_number=5)])
    assert (report['tp'], report['fp'], report['fn']) == (0, 1, 1)


def test_duplicate_reports_and_distinct_expected_locations():
    data = corpus(); data['cases'] = data['cases'][:1]
    data['cases'][0]['expected'].append({'cwe': 'CWE-829', 'sink_line': 5})
    path = 'evaluation/java_webview_candidate.java'
    def finding(line, source_line, method='open'):
        return SimpleNamespace(cwe_id='CWE-829', line_number=line, file_path=path,
            metadata={'source_sink_trace': {'source': {'line': source_line, 'file_path': path, 'method': method},
                                            'sink': {'line': line, 'file_path': path, 'method': method}}})
    report = evaluate_instances(data, lambda *args: [finding(4, 3), finding(4, 3), finding(5, 3)])
    assert (report['tp'], report['fn'], report['duplicate_reports']) == (2, 0, 1)


def test_wrong_source_location_same_cwe_and_sink_does_not_match():
    data = corpus(); data['cases'] = data['cases'][:1]
    path = 'evaluation/java_webview_candidate.java'
    result = SimpleNamespace(cwe_id='CWE-829', line_number=4,
        file_path=path, metadata={'source_sink_trace': {'source': {'line': 2, 'file_path': path, 'method': 'open'},
                                                            'sink': {'line': 4, 'file_path': path, 'method': 'open'}}})
    report = evaluate_instances(data, lambda *args: [result])
    assert (report['tp'], report['fp'], report['fn']) == (0, 1, 1)
    assert report['matching'] == 'case_cwe_normalized_file_source_sink_optional_lexical_and_source_qualified_method_identity'


def test_overlapping_optional_identity_expectations_use_maximum_matching():
    data = corpus(); data['cases'] = data['cases'][:1]
    data['cases'][0]['expected'] = [
        {'cwe': 'CWE-829', 'sink_line': 4},
        {'cwe': 'CWE-829', 'sink_line': 4, 'source_method': 'specific'},
    ]
    path = 'evaluation/java_webview_candidate.java'
    def finding(method):
        return SimpleNamespace(cwe_id='CWE-829', line_number=4, file_path=path,
            metadata={'source_sink_trace': {
                'source': {'line': 3, 'file_path': path, 'method': method},
                'sink': {'line': 4, 'file_path': path, 'method': method}}})
    report = evaluate_instances(data, lambda *args: [finding('specific'), finding('other')])
    assert (report['tp'], report['fp'], report['fn']) == (2, 0, 0)


@pytest.mark.parametrize(('source_path', 'method'), [
    ('evaluation/other.java', 'open'),
    ('evaluation/java_webview_candidate.java', 'other'),
])
def test_wrong_file_or_method_does_not_match(source_path, method):
    data = corpus(); data['cases'] = data['cases'][:1]
    result = SimpleNamespace(cwe_id='CWE-829', line_number=4,
        metadata={'source_sink_trace': {'source': {'line': 3, 'file_path': source_path, 'method': method},
                                        'sink': {'line': 4, 'file_path': source_path, 'method': method}}})
    report = evaluate_instances(data, lambda *args: [result])
    assert (report['tp'], report['fp'], report['fn']) == (0, 1, 1)


@pytest.mark.parametrize('unsafe_path', ['../escape.java', '/absolute/File.java', r'C:\private\File.java', r'\\host\share\File.java'])
def test_corpus_rejects_unsafe_normalized_source_path(unsafe_path):
    data = corpus()
    data['cases'][0]['file_path'] = unsafe_path
    with pytest.raises(ValueError, match='safe normalized relative'):
        validate_corpus(data)


def test_unsafe_detector_path_cannot_fall_back_to_fixture_default_and_match():
    data = corpus(); data['cases'] = data['cases'][:1]
    finding = SimpleNamespace(cwe_id='CWE-829', line_number=4,
        file_path='/tmp/outside/Route.java',
        metadata={'source_sink_trace': {'source': {'line': 3, 'method': 'open'},
                                        'sink': {'line': 4, 'method': 'open'}}})
    report = evaluate_instances(data, lambda *args: [finding])
    assert (report['tp'], report['fp'], report['fn'], report['failed_cases']) == (0, 0, 1, 1)
    assert 'outside' not in json.dumps(report)


def test_exception_is_failure_even_for_negative_fixture():
    data = corpus(); data['cases'] = data['cases'][1:2]
    def broken(*args):
        raise RuntimeError('secret payload must not be returned')
    report = evaluate_instances(data, broken)
    assert report['failed_cases'] == 1
    assert report['precision'] is None
    assert report['input_coverage']['cases_failed'] == 1
    assert report['input_coverage']['unsupported_constructs']['status'] == 'not_measured'
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



def test_ast_method_identity_adds_explicit_import_and_package_qualified_label():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    source = """package com.example;
import android.content.Intent;
import android.webkit.WebView;
class Routes {
 void onNewIntent(Intent input, WebView view) {
  String url = input.getStringExtra(\"url\");
  view.loadUrl(url);
 }
}
"""
    findings = JavaAstTaintAnalyzer().analyze(source, "Routes.java")
    assert findings and len(findings) == 1
    trace = findings[0].metadata["source_sink_trace"]
    expected = "com.example.Routes#onNewIntent(android.content.Intent,android.webkit.WebView)"
    assert trace["source"]["source_qualified_method_identity"] == expected
    assert trace["sink"]["source_qualified_method_identity"] == expected
    assert trace["sink"]["source_qualified_identity_kind"] == "package_import_and_same_source_type_lexical_canonicalization_only"
    from mobileag.analysis.taint_engine import TaintEngine
    merged = TaintEngine().analyze_source_content(source, "src/com/example/Route.java")
    assert len(merged) == 1
    merged_trace = merged[0].metadata["source_sink_trace"]
    assert merged_trace["sink"]["source_qualified_method_identity"] == expected
    assert merged[0].metadata["analysis_kind"] == "bounded_lexical_and_java_ast_duplicate"
    assert "lexical_source_sink_trace" in merged[0].metadata


def test_ast_method_identity_withholds_import_ambiguous_wildcard_type():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    source = """package com.example;
import vendor.one.*;
class Routes {
 void onNewIntent(Intent input, WebView view) {
  String url = input.getStringExtra(\"url\");
  view.loadUrl(url);
 }
}
"""
    findings = JavaAstTaintAnalyzer().analyze(source, "Routes.java")
    assert findings and len(findings) == 1
    trace = findings[0].metadata["source_sink_trace"]
    assert trace["sink"]["method_identity"] is not None
    assert trace["sink"]["source_qualified_method_identity"] is None
    assert trace["sink"]["source_qualified_identity_kind"] == "not_available"


def test_ast_method_identity_qualifies_unique_same_source_type_with_wildcard_import():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    source = '''package com.example;
import android.content.Intent;
import android.webkit.WebView;
import vendor.one.*;
class LocalPayload {}
class Routes {
 void onNewIntent(Intent input, LocalPayload payload, WebView view) {
  String url = input.getStringExtra("url");
  view.loadUrl(url);
 }
}'''
    findings = JavaAstTaintAnalyzer().analyze(source, "Routes.java")
    assert findings and len(findings) == 1
    identity = findings[0].metadata["source_sink_trace"]["sink"]["source_qualified_method_identity"]
    assert identity == "com.example.Routes#onNewIntent(android.content.Intent,com.example.LocalPayload,android.webkit.WebView)"


def test_ast_method_identity_withholds_duplicate_same_source_type_names():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    source = '''package com.example;
import android.content.Intent;
import android.webkit.WebView;
class LocalPayload {}
class AnotherPayload {}
class LocalPayload {}
class Routes {
 void onNewIntent(Intent input, LocalPayload payload, WebView view) {
  String url = input.getStringExtra("url");
  view.loadUrl(url);
 }
}'''
    findings = JavaAstTaintAnalyzer().analyze(source, "Routes.java")
    assert findings and len(findings) == 1
    trace = findings[0].metadata["source_sink_trace"]["sink"]
    assert trace["method_identity"] is not None
    assert trace["source_qualified_method_identity"] is None


def test_ast_method_identity_withholds_conflicting_explicit_imports():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    source = """package com.example;
import android.content.Intent;
import vendor.other.Intent;
import android.webkit.WebView;
class Routes {
 void onNewIntent(Intent input, WebView view) {
  String url = input.getStringExtra("url");
  view.loadUrl(url);
 }
}
"""
    findings = JavaAstTaintAnalyzer().analyze(source, "Routes.java")
    assert findings and len(findings) == 1
    trace = findings[0].metadata["source_sink_trace"]
    assert trace["sink"]["method_identity"] is not None
    assert trace["sink"]["source_qualified_method_identity"] is None
    assert trace["sink"]["source_qualified_identity_kind"] == "not_available"

def test_owner_signature_identity_disambiguates_same_named_overloads():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    source = '''class Routes {
      void route(Intent input, WebView view) {
        String first = input.getStringExtra("url");
        view.loadUrl(first);
      }
      void route(Intent input, WebView view, int mode) {
        String second = input.getStringExtra("url");
        view.loadUrl(second);
      }
    }'''
    analyzer = JavaAstTaintAnalyzer()
    findings = analyzer.analyze(source, "Routes.java")
    assert findings is not None and len(findings) == 2
    traces = [finding.metadata["source_sink_trace"] for finding in findings]
    identities = {trace["sink"]["method_identity"] for trace in traces}
    assert identities == {
        "Routes#route(Intent,WebView)",
        "Routes#route(Intent,WebView,int)",
    }
    assert all(trace["source"]["method_identity"] == trace["sink"]["method_identity"]
               for trace in traces)

    case = {
        "schema_version": 1,
        "cases": [{
            "id": "overloads",
            "language": "java",
            "file_path": "Routes.java",
            "source": source,
            "expected": [
                {"cwe": "CWE-829", "source_line": 3, "sink_line": 4,
                 "source_method": "route", "sink_method": "route",
                 "source_method_identity": "Routes#route(Intent,WebView)",
                 "sink_method_identity": "Routes#route(Intent,WebView)",
                 "source_qualified_method_identity": "Routes#route(Intent,WebView)",
                 "sink_qualified_method_identity": "Routes#route(Intent,WebView)"},
                {"cwe": "CWE-829", "source_line": 7, "sink_line": 8,
                 "source_method": "route", "sink_method": "route",
                 "source_method_identity": "Routes#route(Intent,WebView,int)",
                 "sink_method_identity": "Routes#route(Intent,WebView,int)",
                 "source_qualified_method_identity": "Routes#route(Intent,WebView,int)",
                 "sink_qualified_method_identity": "Routes#route(Intent,WebView,int)"},
            ],
        }],
    }
    result = evaluate_instances(case, lambda text, path: analyzer.analyze(text, path) or [])
    assert (result["tp"], result["fp"], result["fn"], result["failed_cases"]) == (2, 0, 0, 0)


def test_kotlin_lexical_owner_signature_identity_disambiguates_overloads():
    source = '''class Routes {
      fun route(input: Intent, view: WebView) {
        val first = input.getStringExtra("url")
        view.loadUrl(first)
      }
      fun route(input: Intent, view: WebView, mode: Int) {
        val second = input.getStringExtra("url")
        view.loadUrl(second)
      }
    }'''
    engine = TaintEngine()
    findings = [f for f in engine.analyze_source_content(source, "Routes.kt") if f.cwe_id == "CWE-829"]
    identities = {f.metadata["source_sink_trace"]["sink"]["method_identity"] for f in findings}
    assert identities == {"Routes#route(Intent,WebView)", "Routes#route(Intent,WebView,Int)"}
    case = {
        "schema_version": 1,
        "cases": [{
            "id": "kotlin-overloads",
            "language": "kotlin",
            "file_path": "Routes.kt",
            "source": source,
            "expected": [
                {"cwe": "CWE-829", "source_line": 3, "sink_line": 4,
                 "source_method": "route", "sink_method": "route",
                 "source_method_identity": "Routes#route(Intent,WebView)",
                 "sink_method_identity": "Routes#route(Intent,WebView)"},
                {"cwe": "CWE-829", "source_line": 7, "sink_line": 8,
                 "source_method": "route", "sink_method": "route",
                 "source_method_identity": "Routes#route(Intent,WebView,Int)",
                 "sink_method_identity": "Routes#route(Intent,WebView,Int)"},
            ],
        }],
    }
    result = evaluate_instances(case, engine.analyze_source_content)
    assert (result["tp"], result["fp"], result["fn"], result["failed_cases"]) == (2, 0, 0, 0)


@pytest.mark.parametrize('status', ['login_failed', 'typo', None, {}, 'analyzed_heuristically'])
def test_report_unknown_static_states_fail_closed(status):
    report = ReportEngine()._prepare_data({'scan_id': 'fixture', 'coverage': {'test': {'static_status': status}}})
    assert report['assessment_coverage'] == 'partial'
    assert report['coverage_gaps']


def test_report_errors_cannot_produce_gap_free_assessment():
    report = ReportEngine()._prepare_data({'scan_id': 'fixture', 'coverage': {'test': {'static_status': 'completed'}}, 'errors': ['engine failed']})
    assert report['assessment_coverage'] == 'partial'


def test_review_surface_ledger_maps_only_recorded_analyzers_and_fails_closed():
    ledger = review_surface_ledger({
        'manifest': {'static_status': 'completed', 'runtime_status': 'not_tested',
                     'component_count': 2, 'exported_component_count': 1, 'candidate_count': 1,
                     'provider_path_inventory': {'static_status': 'completed', 'runtime_status': 'not_tested',
                                                     'provider_count': 1, 'unresolved_count': 0,
                                                     'candidate_count': 1}},
        'android_surface': {'categories': {
            'intent': {'static_status': 'completed', 'runtime_status': 'not_tested'},
            'webview': {'static_status': 'incomplete', 'runtime_status': 'not_tested'},
            'deep_links': {'static_status': 'completed', 'runtime_status': 'not_tested'},
        }},
        'auth_session': {'static_status': 'completed', 'runtime_status': 'not_tested'},
        'api_mapping': {'static_status': 'failed', 'runtime_status': 'not_tested'},
        'nsc': {'static_status': 'completed', 'runtime_status': 'not_tested'},
        'native': {'static_status': 'not_started', 'runtime_status': 'not_tested'},
    })
    surfaces = ledger['surfaces']
    assert surfaces['manifest_component_inventory']['analysis_state'] == 'analyzed'
    assert surfaces['manifest_component_inventory']['recorded_counts']['manifest']['exported_component_count'] == 1
    assert surfaces['provider_path_configuration']['analysis_state'] == 'analyzed'
    assert surfaces['provider_path_configuration']['recorded_counts']['manifest.provider_path_inventory']['provider_count'] == 1
    assert surfaces['ipc_intent_calls']['analysis_state'] == 'analyzed'
    assert surfaces['webview_deep_links']['analysis_state'] == 'incomplete'
    assert surfaces['network_api_authentication']['analysis_state'] == 'incomplete'
    assert surfaces['serialization']['analysis_state'] == 'not_tested'
    assert surfaces['files_uri_grants']['analysis_state'] == 'analyzed'
    assert surfaces['files_uri_grants']['gap'] == 'configured roots/grant declarations only; URI-grant issuance and caller access are not tested'
    assert surfaces['files_uri_grants']['evidence_state'] == 'candidate'
    assert surfaces['provider_path_configuration']['evidence_state'] == 'candidate'
    assert surfaces['manifest_component_inventory']['evidence_state'] == 'candidate'
    assert all(row['proof_status'] == 'not_proven' and row['independently_verified'] is False
               for row in surfaces.values())
    assert all(row['evidence_state'] in {'not_tested', 'candidate', 'observed', 'attested',
                                         'independently_verified', 'not_applicable'}
               for row in surfaces.values())
    assert ledger['exhaustive'] is False
    assert ledger['security_verdict'] == 'not_established'


def test_review_surface_ledger_exposes_specific_analyzer_gap_and_limit_reasons():
    row = review_surface_ledger({'android_surface': {'categories': {
        'webview': {'static_status': 'partial', 'runtime_status': 'not_tested',
                    'candidate_count': 2, 'source_files_skipped': 3,
                    'limit_reasons': {'source_file_budget': 1}},
    }}})['surfaces']['webview_deep_links']

    assert row['analysis_state'] == 'incomplete'
    assert row['candidate_evidence_paths'] == ['android_surface.categories.webview']
    assert 'android_surface.categories.webview: static status partial' in row['gap_reasons']
    assert 'android_surface.categories.webview: 3 source file(s) skipped' in row['gap_reasons']
    assert 'android_surface.categories.webview: limit source_file_budget reached (1)' in row['gap_reasons']
    assert 'runtime behavior not tested' in row['gap_reasons']
    assert row['proof_status'] == 'not_proven'


def test_review_surface_ledger_lists_missing_mapped_analyzers_explicitly():
    row = review_surface_ledger({'android_surface': {'categories': {
        'webview': {'static_status': 'analyzed_heuristically', 'candidate_count': 1},
    }}})['surfaces']['webview_deep_links']

    assert row['analysis_state'] == 'analyzed'
    assert row['mapped_coverage_paths'] == ['android_surface.categories.webview']
    assert row['missing_coverage_paths'] == [
        'android_surface.categories.deep_links', 'taint.webview',
    ]
    assert 'android_surface.categories.deep_links: coverage not recorded' in row['gap_reasons']
    assert 'taint.webview: coverage not recorded' in row['gap_reasons']
    assert row['proof_status'] == 'not_proven'


def test_review_ledger_maps_serialization_and_logging_as_bounded_static_only():
    ledger = review_surface_ledger({
        'manifest': {'static_status': 'completed', 'candidate_count': 1,
                     'backup_rules_inventory': {'static_status': 'completed',
                                                'candidate_count': 0}},
        'android_surface': {'categories': {
            'serialization': {'static_status': 'completed'},
            'logging': {'static_status': 'completed'},
        }},
    })['surfaces']
    assert ledger['serialization']['analysis_state'] == 'analyzed'
    assert 'dataflow' in ledger['serialization']['gap'] or 'flows' in ledger['serialization']['gap']
    assert ledger['storage_backup_logging']['analysis_state'] == 'analyzed'
    assert ledger['storage_backup_logging']['evidence_state'] == 'not_tested'
    assert ledger['storage_backup_logging']['candidate_evidence_paths'] == []


def test_review_ledger_tracks_taint_deserialization_candidate_separately():
    surfaces = review_surface_ledger({
        'taint': {'static_status': 'analyzed_heuristically', 'candidate_count': 9,
                  'serialization': {'static_status': 'analyzed_heuristically',
                                    'candidate_count': 1, 'runtime_status': 'not_tested'}},
    })['surfaces']
    row = surfaces['serialization']
    assert row['analysis_state'] == 'analyzed'
    assert row['evidence_state'] == 'candidate'
    assert row['candidate_evidence_paths'] == ['taint.serialization']
    assert row['recorded_counts']['taint.serialization']['candidate_count'] == 1
    unrelated_only = review_surface_ledger({
        'taint': {'static_status': 'analyzed_heuristically', 'candidate_count': 9,
                  'serialization': {'static_status': 'analyzed_heuristically',
                                    'candidate_count': 0, 'runtime_status': 'not_tested'}},
    })['surfaces']['serialization']
    assert unrelated_only['evidence_state'] == 'not_tested'


def test_review_ledger_tracks_taint_webview_candidate_separately():
    row = review_surface_ledger({
        'taint': {'static_status': 'analyzed_heuristically', 'candidate_count': 12,
                  'webview': {'static_status': 'analyzed_heuristically',
                              'candidate_count': 1, 'runtime_status': 'not_tested'}},
    })['surfaces']['webview_deep_links']
    assert row['analysis_state'] == 'analyzed'
    assert row['evidence_state'] == 'candidate'
    assert row['candidate_evidence_paths'] == ['taint.webview']
    assert row['recorded_counts']['taint.webview']['candidate_count'] == 1


def test_backup_candidates_are_not_inferred_from_unrelated_manifest_candidates():
    ledger = review_surface_ledger({
        'manifest': {'static_status': 'completed', 'candidate_count': 3,
                     'backup_rules_inventory': {'static_status': 'completed',
                                                'candidate_count': 0}},
    })['surfaces']['storage_backup_logging']
    assert ledger['analysis_state'] == 'analyzed'
    assert ledger['evidence_state'] == 'not_tested'
    assert ledger['candidate_evidence_paths'] == []
    assert 'backup rules' in ledger['gap']
    assert ledger['proof_status'] == 'not_proven'


def test_review_ledger_recognizes_heuristic_engine_completion_without_claiming_proof():
    row = review_surface_ledger({'android_surface': {'categories': {
        'intent': {'static_status': 'analyzed_heuristically', 'candidate_count': 1,
                   'runtime_status': 'not_tested'}}}})['surfaces']['ipc_intent_calls']
    assert row['analysis_state'] == 'analyzed'
    assert row['evidence_state'] == 'candidate'
    assert row['proof_status'] == 'not_proven'


def test_review_surface_ledger_is_in_json_and_markdown_reports():
    report = ReportEngine()._prepare_data({'scan_id': 'fixture', 'coverage': {}})
    assert report['review_surface_ledger']['surfaces']['serialization']['analysis_state'] == 'not_tested'
    markdown = ReportEngine()._generate_markdown(report)
    assert 'Review-surface ledger' in markdown
    assert 'storage_backup_logging' in markdown
    assert 'no analyzer mapped to this surface' in markdown


def test_markdown_report_exposes_bounded_static_trace_as_unverified_candidate():
    report = ReportEngine()._prepare_data({
        'scan_id': 'fixture', 'coverage': {},
        'filtered_findings': [{
            'title': 'Synthetic trace', 'description': 'Review this modeled flow.',
            'severity': 'INFO', 'status': 'UNVERIFIED',
            'metadata': {
                'source_sink_trace': {
                    'source': {'kind': 'ANDROID_CALLBACK_INTENT_PARAMETER', 'line': 12},
                    'sink': {'operation': 'WebView.loadUrl', 'line': 21},
                    'guards': 'not_resolved', 'runtime_verified': False,
                },
                'control_flow': 'path_insensitive',
            },
        }],
    })
    markdown = ReportEngine()._generate_markdown(report)
    assert 'Static source-to-sink trace (review candidate)' in markdown
    assert 'ANDROID_CALLBACK_INTENT_PARAMETER' in markdown
    assert 'WebView.loadUrl' in markdown
    assert 'Guards:** not_resolved' in markdown
    assert 'Runtime verified:** False' in markdown
    assert 'not proof of external reachability' in markdown


def test_completed_guided_execution_does_not_infer_login_or_api_authorization():
    report = guided_coverage({'stages': {'sast': {'status': 'completed'},
        'api': {'status': 'completed_with_observations', 'executed': 2},
        'dast': {'status': 'completed', 'screens': 9}, 'llm': {'status': 'completed'}}})
    assert report['assessment_coverage'] == 'partial'
    assert report['security_verdict'] == 'not_established'
    assert report['stages']['dast']['authentication_status'] == 'not_verified'
    assert report['stages']['api']['authorization_validation'] == 'not_tested'
    assert report['independently_verified_exploits'] == 0


def test_guided_coverage_does_not_call_empty_assessment_static_only():
    result = guided_coverage({'stages': {name: {'status': 'not_selected'}
        for name in ('sast', 'api', 'dast', 'llm')}})
    assert result['assessment_coverage'] == 'unknown'
    assert 'assessment: no stages selected or recorded' in result['gaps']
    assert result['security_verdict'] == 'not_established'


def test_bounded_static_only_requires_completed_static_analysis():
    result = guided_coverage({'stages': {
        'sast': {'status': 'completed', 'assessment_coverage': 'recorded_no_static_gaps'},
        'api': {'status': 'not_selected'}, 'dast': {'status': 'not_selected'},
        'llm': {'status': 'not_selected'}}})
    assert result['assessment_coverage'] == 'bounded_static_only'
    assert result['gaps'] == []


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


def test_confirmation_without_scan_artifact_binding_is_unverified():
    from mobileag.reporting.evidence_contract import prepare_finding
    from mobileag.reporting.validation import bind_confirmation
    from tests.proof_fixtures import confirmation_evidence
    scan = {'artifact_sha256': 'a' * 64, 'package_name': 'org.example.synthetic', 'version': '1.0'}
    finding = {'status': 'CONFIRMED', 'validation_evidence': bind_confirmation(confirmation_evidence(), scan)}
    result = prepare_finding(finding)
    assert result['status'] == 'UNVERIFIED'
    assert result['evidence_assessment']['basis'] == 'not_proven'
    assert 'artifact_binding_not_checked' in result['evidence_assessment']['validation_errors']


def test_attested_evidence_and_trace_render_across_report_formats():
    from mobileag.reporting.validation import bind_confirmation
    from mobileag.reporting.sarif_exporter import SARIFExporter
    from tests.proof_fixtures import confirmation_evidence
    artifact = {'artifact_sha256': 'a' * 64, 'package_name': 'org.example.synthetic', 'app_version': '1.0'}
    evidence = bind_confirmation(confirmation_evidence(), {'artifact_sha256': artifact['artifact_sha256'],
        'package_name': artifact['package_name'], 'version': artifact['app_version']})
    finding = {'id': 'synthetic', 'title': 'Synthetic', 'description': 'Synthetic description',
        'severity': 'INFO', 'status': 'CONFIRMED', 'cwe_id': 'CWE-000', 'file_path': 'src/Synthetic.java',
        'line_number': 4, 'affected_component': 'Synthetic', 'validation_evidence': evidence,
        'metadata': {'source_sink_trace': {'source': {'kind': 'intent_extra', 'line': 3},
            'sink': {'operation': 'synthetic sink', 'line': 4}, 'guards': 'not_resolved', 'runtime_verified': False}}}
    engine = ReportEngine()
    prepared = engine._prepare_data({'scan_id': 'synthetic', 'artifact_sha256': artifact['artifact_sha256'],
        'package_name': artifact['package_name'], 'version': artifact['app_version'],
        'filtered_findings': [finding]})
    markdown = engine._generate_markdown(prepared)
    assert 'analyst_attested' in markdown and 'not independently verified' in markdown
    assert 'Synthetic exported test entry' in markdown and 'source-to-sink' in markdown
    sarif = SARIFExporter.generate_sarif([finding], artifact=artifact,
        coverage={'manifest': {'static_status': 'completed'}})
    props = sarif['runs'][0]['results'][0]['properties']
    assert props['proof_basis'] == 'analyst_attested'
    assert props['source_sink_trace']['sink']['operation'] == 'synthetic sink'
    assert 'review_surface_ledger' in sarif['runs'][0]['properties']
    from mobileag.reporting.professional_report import ProfessionalReportExporter
    professional = ProfessionalReportExporter().generate_report([finding], scan_metadata={
        'artifact_provenance': {'sha256': artifact['artifact_sha256']},
        'package_name': artifact['package_name'], 'app_version': artifact['app_version'],
        'coverage': {'manifest': {'static_status': 'completed'}},
        'framework_info': {'framework': 'Native', 'analysis_notes': ['Synthetic fixture']}})
    assert 'Review-Surface Ledger' in professional
    assert 'Framework and Format Support Inventory' in professional


def test_report_capability_inventory_distinguishes_detection_from_analysis():
    engine = ReportEngine()
    data = engine._prepare_data({'scan_id': 'inventory', 'filtered_findings': [],
        'framework_info': {'framework': 'Flutter', 'detection_evidence': ['lib/*/libflutter.so']},
        'coverage': {'native': {'static_status': 'completed'},
                     'android_surface': {'categories': {'webview': {'static_status': 'completed'}}}}})
    assert data['report_schema_version'] == 1
    capabilities = data['capability_inventory']['formats']
    assert data['capability_inventory']['detected_framework_hint'] == 'Flutter'
    assert capabilities['flutter']['support_level'] == 'detection_only'
    assert capabilities['flutter']['execution_state'] == 'not_tested'
    assert capabilities['native_jni']['execution_state'] == 'analyzed_bounded'
    assert capabilities['split_apk_aab']['support_level'] == 'manifest_indicator_only'
    assert capabilities['split_apk_aab']['execution_state'] == 'not_tested'
    markdown = engine._generate_markdown(data)
    assert 'Framework and format support inventory' in markdown
    assert 'not a benchmark' in markdown


def test_capability_inventory_surfaces_path_free_input_and_limit_reasons():
    engine = ReportEngine()
    data = engine._prepare_data({'scan_id': 'inventory-reasons', 'filtered_findings': [],
        'coverage': {'taint': {'static_status': 'partial', 'source_files_skipped': 2,
                               'source_file_skip_reasons': {'file_size_limit': 1, 'symlink_entry': 1},
                               'limit_reasons': {'entry_budget': 1}},
                     'android_surface': {'source_files_skipped': 3,
                         'source_file_skip_reasons': {'directory_read_error': 3},
                         'limit_reasons': {'entry_budget': 1},
                         'categories': {'webview': {'static_status': 'partial'}}}}})
    row = data['capability_inventory']['formats']['java_kotlin']
    assert row['source_files_skipped'] == 2
    assert row['source_file_skip_reasons'] == {'file_size_limit': 1, 'symlink_entry': 1}
    assert row['limit_reasons'] == {'entry_budget': 1}
    webview = data['capability_inventory']['formats']['hybrid_webview']
    assert webview['source_files_skipped'] == 3
    assert webview['source_file_skip_reasons'] == {'directory_read_error': 3}
    markdown = engine._generate_markdown(data)
    assert 'skipped files=2' in markdown
    assert 'file_size_limit=1' in markdown and 'entry_budget=1' in markdown
    from mobileag.reporting.professional_report import ProfessionalReportExporter
    professional = ProfessionalReportExporter().generate_report([], scan_metadata={
        'coverage': {'taint': {'static_status': 'partial', 'source_files_skipped': 2,
                               'source_file_skip_reasons': {'file_size_limit': 1},
                               'limit_reasons': {'entry_budget': 1}}}})
    assert 'skipped files=2' in professional and 'entry_budget=1' in professional


@pytest.mark.parametrize('status', ['partial', 'fallback_lexical'])
def test_capability_inventory_does_not_conflate_partial_analysis_with_skipping(status):
    from mobileag.reporting.capability_inventory import capability_inventory
    result = capability_inventory({'taint': {'static_status': status}})
    assert result['formats']['java_kotlin']['execution_state'] == 'analyzed_partial'
    assert result['formats']['java_kotlin']['static_status'] == status


def test_report_json_obeys_published_v1_schema():
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator
    from mobileag.core.state import create_initial_state
    schema = json.loads(Path('docs/schemas/mobileag-report-v1.schema.json').read_text())
    report = ReportEngine()._prepare_data(create_initial_state('synthetic-schema-test', 'unused'))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


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
