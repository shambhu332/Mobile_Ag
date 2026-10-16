"""Synthetic static-review inventories: no device/cloud operations."""
import json
from unittest.mock import AsyncMock
import pytest
from config.settings import Settings
from mobileag.ingestion.manifest_parser import ManifestParser
from mobileag.ingestion.intent_filters import inventory_links
from mobileag.analysis.android_surface import AndroidSurfaceAnalyzer,mask_non_code
from mobileag.reporting.finding import FindingStatus,Severity
from mobileag.core.state import create_initial_state
from mobileag.core.orchestrator import Orchestrator
from mobileag.analysis.il2cpp_auditor import Il2CppAnalysisResult
from mobileag.reporting.report_engine import ReportEngine


def manifest(tmp_path,content):
    path=tmp_path/'AndroidManifest.xml'
    path.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.example.fixture"><application>'+content+'</application></manifest>')
    return ManifestParser().parse(str(path))


def test_merged_uri_combinations_and_paired_ports(tmp_path):
    parsed=manifest(tmp_path,'<activity android:name=".Router" android:exported="true"><intent-filter android:autoVerify="true"><action android:name="android.intent.action.VIEW"/><data android:scheme="https"/><data android:scheme="fixture"/><data android:host="a.fixture.invalid" android:port="8443"/><data android:host="b.fixture.invalid"/><data android:path="/profile"/></intent-filter></activity>')
    links=parsed['deep_links']
    assert {link['uri'] for link in links}=={'https://a.fixture.invalid:8443/profile','https://b.fixture.invalid/profile','fixture://a.fixture.invalid:8443/profile','fixture://b.fixture.invalid/profile'}
    assert all(link['auto_verify']=='true' and link['runtime_verified'] is False and link['implicitly_authorized'] is False for link in links)
    assert parsed['deep_link_coverage']['domain_verification']=='not_tested'


@pytest.mark.parametrize('path_attribute',['pathPattern','pathAdvancedPattern','pathSuffix'])
def test_patterns_preserved_not_fabricated_test_uri(tmp_path,path_attribute):
    parsed=manifest(tmp_path,f'<activity android:name=".Router"><intent-filter><data android:scheme="fixture" android:host="*.fixture.invalid" android:{path_attribute}="/test.*"/></intent-filter></activity>')
    assert parsed['deep_links'][0]['uri'] is None
    assert parsed['deep_links'][0]['path_kind']==path_attribute


def test_relative_groups_alias_and_mime_only_preserved(tmp_path):
    parsed=manifest(tmp_path,'<activity-alias android:name=".Alias" android:targetActivity=".Real" android:exported="true"><intent-filter><data android:scheme="https" android:host="fixture.invalid"/><uri-relative-filter-group android:allow="false"><data android:query="synthetic=1" android:fragmentPrefix="fixture"/></uri-relative-filter-group></intent-filter><intent-filter><data android:mimeType="text/plain"/></intent-filter></activity-alias>')
    row=parsed['deep_links'][0]
    assert row['uri'] is None and row['relative_uri_groups'][0]['allow']=='false'
    assert parsed['activities'][0]['alias_target']=='.Real'
    assert parsed['deep_link_coverage']['mime_only_filters']==1


def test_no_host_ignores_paths_and_uri_limits(tmp_path):
    parsed=manifest(tmp_path,'<activity android:name=".Router"><intent-filter><data android:scheme="fixture" android:path="/ignored" android:port="4444"/></intent-filter></activity>')
    assert parsed['deep_links'][0]['uri']=='fixture://'
    data=[{'scheme':f'scheme{i}','host':f'h{i}.invalid','path':f'/p{i}'} for i in range(20)]
    links,coverage=inventory_links([{'name':'.Router','intent_filters':[{'data':data}]}],per_filter_limit=5,total_limit=4)
    assert len(links)==4 and coverage['truncated'] and coverage['status']=='partial'


def test_source_new_checks_do_not_claim_exploit():
    source='''class Fixture {
      void configure() { settings.setAllowUniversalAccessFromFileURLs(true); settings.setAllowFileAccessFromFileURLs(true); settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW); }
      public void onReceivedSslError(WebView v, SslErrorHandler handler, SslError error) { handler.proceed(); }
      void route(String input) { if(input.startsWith("https://fixture.invalid")) web.loadUrl(input); }
      void forward(String input) { Intent nested=Intent.parseUri(input,0); startActivity(nested); nested.removeLaunchSecurityProtection(); }
    }'''
    findings,sites=AndroidSurfaceAnalyzer().analyze_source(source,'Fixture.java')
    ids={f.metadata['check_id'] for f in findings}
    assert ids=={'file_origin_universal_access','file_origin_file_access','mixed_content','ssl_error_proceed','weak_uri_guard','parsed_intent_launch','launch_protection_opt_out'}
    cwes={f.metadata['check_id']:f.cwe_id for f in findings}
    assert cwes['file_origin_universal_access']=='CWE-669'
    assert cwes['file_origin_file_access']=='CWE-669'
    assert all(f.status==FindingStatus.UNVERIFIED and f.severity==Severity.INFO and f.cvss_score==0 and f.metadata['proof_state']=='not_proven' for f in findings)
    assert sites['webview'] and sites['intent']


def test_comments_literals_and_safe_ssl_callback_not_flagged():
    source='''// setAllowUniversalAccessFromFileURLs(true);
      class Safe { String sample="setAllowFileAccessFromFileURLs(true)";
      void onReceivedSslError(Object h) { h.cancel(); }
      void cfg(){ settings.setAllowUniversalAccessFromFileURLs(false); web.setJavaScriptEnabled(true); }
      /* Intent.parseUri(input,0); startActivity(input); */ }'''
    findings,sites=AndroidSurfaceAnalyzer().analyze_source(source,'Safe.java')
    assert findings==[] and sites['webview'][0]['operation']=='setJavaScriptEnabled'
    assert len(mask_non_code(source))==len(source) and mask_non_code(source).count('\n')==source.count('\n')


def test_sensitive_preference_write_is_only_an_info_review_lead():
    source='''class Fixture {
      void save(String accessToken) { prefs.edit().putString("k", accessToken).apply(); }
      void unrelated(String label) { builder.putString("k", label); }
      // prefs.edit().putString("k", password).apply();
      String example = "prefs.edit().putString(token, value)";
    }'''
    findings,sites=AndroidSurfaceAnalyzer().analyze_source(source,'Fixture.java')
    storage=[finding for finding in findings if finding.metadata['category']=='storage']
    assert len(storage)==1
    assert storage[0].metadata['check_id']=='sensitive_identifier_in_preference_write_review'
    assert storage[0].cwe_id=='CWE-922'
    assert storage[0].severity==Severity.INFO and storage[0].status==FindingStatus.UNVERIFIED
    assert storage[0].metadata['proof_state']=='not_proven'
    assert len(sites['storage'])==1 and sites['storage'][0]['line']==2


def test_world_accessible_storage_modes_are_reviewed_only_in_mode_argument():
    source='''class Fixture {
      void write() {
        openFileOutput("fixture", MODE_WORLD_READABLE);
        getSharedPreferences("fixture", MODE_PRIVATE | MODE_WORLD_WRITEABLE);
        openFileOutput(MODE_WORLD_READABLE, MODE_PRIVATE);
        // openFileOutput("fixture", MODE_WORLD_READABLE);
        String note = "getSharedPreferences(x, MODE_WORLD_WRITEABLE)";
      }
    }'''
    findings,sites=AndroidSurfaceAnalyzer().analyze_source(source,'Fixture.java')
    modes=[finding for finding in findings if finding.metadata['check_id']=='world_accessible_app_file_mode_review']
    assert len(modes)==2
    assert all(finding.cwe_id=='CWE-732' and finding.severity==Severity.INFO
               and finding.status==FindingStatus.UNVERIFIED
               and finding.metadata['proof_state']=='not_proven' for finding in modes)
    assert [item['line'] for item in sites['storage'] if item['operation'] in {'openFileOutput','getSharedPreferences'}]==[3,4]


def test_javascript_enabled_webview_candidate_requires_same_method_content_or_bridge():
    analyzer=AndroidSurfaceAnalyzer()
    source='''class Fixture {
      void exposed(WebView web) {
        web.getSettings().setJavaScriptEnabled(true);
        web.addJavascriptInterface(new Bridge(), "bridge");
      }
      void javascriptOnly(WebView web) { web.getSettings().setJavaScriptEnabled(true); }
      void safe(WebView web) { web.getSettings().setJavaScriptEnabled(false); web.loadUrl("https://fixture.invalid"); }
    }'''
    findings,_=analyzer.analyze_source(source,'Fixture.java')
    candidates=[finding for finding in findings if finding.metadata['check_id']=='javascript_enabled_with_content_or_bridge_review']
    assert len(candidates)==1
    assert candidates[0].severity==Severity.INFO and candidates[0].status==FindingStatus.UNVERIFIED
    assert candidates[0].metadata['proof_state']=='not_proven'


def test_webview_bridge_registration_joins_only_simple_same_file_constructor_type():
    source='''class Bridge {
      @android.webkit.JavascriptInterface public void open(String value) {}
      @JavascriptInterface public void status() {}
    }
    class Host {
      void bind(WebView web, Object supplied) {
        web.addJavascriptInterface(new Bridge(), "native");
        web.addJavascriptInterface(supplied, "dynamic");
        web.addJavascriptInterface(new other.Bridge(), "qualified");
      }
    }'''
    _,sites=AndroidSurfaceAnalyzer().analyze_source(source,'Fixture.java')
    registrations=[item for item in sites['webview'] if item['operation']=='addJavascriptInterface registration']
    assert len(registrations)==3
    direct=next(item for item in registrations if item['registered_object_type']=='Bridge')
    assert direct['annotated_methods']==['open','status']
    assert direct['association_status']=='same_file_constructor_type_has_annotated_methods'
    dynamic=next(item for item in registrations if item['registered_object_type'] is None)
    assert dynamic['association_status']=='dynamic_or_unresolved_object_expression'
    assert dynamic['annotated_methods']==[]
    assert all(item['evidence'].endswith('invocation unresolved') for item in registrations)


def test_source_skips_and_no_source_not_clean(tmp_path,monkeypatch):
    analyzer=AndroidSurfaceAnalyzer()
    assert analyzer.scan('',{})['coverage']['categories']['webview']['static_status']=='not_analyzed'
    (tmp_path/'Fixture.java').write_text('class Fixture { void cfg(){w.loadUrl(value);} }')
    (tmp_path/'Outside.kt').symlink_to(tmp_path/'Fixture.java')
    report=analyzer.scan(str(tmp_path),{})['coverage']
    assert report['source_files_analyzed']==1 and report['source_files_skipped']==1
    assert report['categories']['webview']['static_status']=='partial'
    assert report['exhaustive'] is False and report['automatic_exploit_proof'] is False
    import mobileag.analysis.android_surface as module
    monkeypatch.setattr(module,'MAX_SOURCE_BYTES',1)
    report=analyzer.scan(str(tmp_path),{})['coverage']
    assert report['limits_reached'] and report['source_files_analyzed']==0


@pytest.mark.asyncio
async def test_orchestrator_runs_surface_review_and_tracks_failure(tmp_path,monkeypatch):
    worker=Orchestrator(Settings(_env_file=None,offline=True,enable_deep_taint=False))
    for target,method in [(worker._manifest_auditor,'audit'),(worker._secret_scanner,'scan'),(worker._code_reviewer,'review'),(worker._native_analyzer,'analyze'),(worker._dependency_scanner,'scan'),(worker._nsc_auditor,'audit_directory_async'),(worker._bin_protection,'audit_directory_async'),(worker._rn_scanner,'scan_directory_async')]:
        monkeypatch.setattr(target,method,AsyncMock(return_value=[]))
    monkeypatch.setattr(worker._api_mapper,'map_apis',AsyncMock(return_value=([],[])))
    monkeypatch.setattr(worker._il2cpp_auditor, 'audit_package', lambda _: Il2CppAnalysisResult(
        is_il2cpp=True, metadata_version=29, metadata_tables_status='parsed',
        metadata_definitions_status='parsed', reconstructed_classes=['Fixture'],
        reconstructed_methods=[{'name': 'reviewOnly'}], scan_status='complete'))
    monkeypatch.setattr(worker._call_graph_engine,'audit_smali_directory',lambda _:[])
    (tmp_path/'Fixture.java').write_text('class Fixture{void cfg(){settings.setAllowUniversalAccessFromFileURLs(true);}}')
    state=create_initial_state('synthetic','unused',str(tmp_path));state.update(decompiled_path=str(tmp_path),resource_path=str(tmp_path),smali_path=str(tmp_path),manifest_data={'components':[]})
    result=await worker._run_analysis(state)
    assert result['coverage']['engines']['taint']=='skipped_disabled'
    assert result['coverage']['android_surface']['categories']['webview']['candidate_count']==1
    assert result['coverage']['manifest']['static_status']=='completed'
    assert result['coverage']['manifest']['exhaustive'] is False
    assert result['coverage']['manifest']['runtime_status']=='not_tested'
    assert result['raw_findings'][0]['status']=='UNVERIFIED'
    assert result['il2cpp_analysis']['reconstructed_classes']==['Fixture']
    assert result['il2cpp_analysis']['reconstructed_methods']==[{'name':'reviewOnly'}]
    assert result['il2cpp_analysis']['proof_status']=='not_proven'
    assert result['il2cpp_analysis']['runtime_status']=='not_tested'
    assert result['il2cpp_analysis']['exhaustive'] is False
    monkeypatch.setattr(worker._android_surface,'analyze',AsyncMock(side_effect=RuntimeError('synthetic failure')))
    result=await worker._run_analysis(create_initial_state('synthetic2','unused',str(tmp_path)))
    assert result['coverage']['engines']['android_surface']=='incomplete'
    assert result['errors']
    monkeypatch.setattr(worker._il2cpp_auditor, 'audit_package', lambda _: (_ for _ in ()).throw(RuntimeError('synthetic failure')))
    result=await worker._run_analysis(create_initial_state('synthetic3','unused',str(tmp_path)))
    assert result['coverage']['il2cpp']['static_status']=='incomplete'
    assert result['il2cpp_analysis']['scan_status']=='incomplete'
    assert result['il2cpp_analysis']['proof_status']=='not_proven'
    assert result['il2cpp_analysis']['scan_errors']==['il2cpp_analysis_engine_failed']


@pytest.mark.asyncio
async def test_orchestrator_persists_bounded_deep_link_flow_correlation(tmp_path, monkeypatch):
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer

    worker = Orchestrator(Settings(_env_file=None, offline=True, enable_deep_taint=True))
    for target, method in [
        (worker._manifest_auditor, 'audit'), (worker._secret_scanner, 'scan'),
        (worker._code_reviewer, 'review'), (worker._native_analyzer, 'analyze'),
        (worker._dependency_scanner, 'scan'), (worker._nsc_auditor, 'audit_directory_async'),
        (worker._bin_protection, 'audit_directory_async'), (worker._rn_scanner, 'scan_directory_async'),
    ]:
        monkeypatch.setattr(target, method, AsyncMock(return_value=[]))
    empty_agent = {"findings": [], "coverage": {"static_status": "not_analyzed",
                                                  "runtime_status": "not_tested",
                                                  "proof_status": "not_proven"}}
    monkeypatch.setattr(worker._auth_session_auditor, 'analyze', AsyncMock(return_value=empty_agent))
    monkeypatch.setattr(worker._firebase_auditor, 'analyze', AsyncMock(return_value=empty_agent))
    monkeypatch.setattr(worker._api_mapper, 'map_apis', AsyncMock(return_value=([], [])))
    monkeypatch.setattr(worker._call_graph_engine, 'audit_smali_directory', lambda _: [])

    source = '''package com.example;
import android.content.Intent;
import android.net.Uri;
import android.webkit.WebView;
class Route { void onCreate(Intent intent, WebView web) {
  Uri uri = intent.getData();
  String target = uri.getQueryParameter("next");
  web.loadUrl(target);
} }'''
    candidate = next(item for item in JavaAstTaintAnalyzer().analyze(source, 'com/example/Route.java')
                     if item.metadata.get('source_kind') == 'URI_QUERY_PARAM')
    monkeypatch.setattr(worker._taint_engine, 'analyze_directory_async',
                        AsyncMock(return_value=[candidate]))
    decoded = tmp_path / 'AndroidManifest.xml'
    decoded.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example">
      <application><activity android:name=".Route" android:exported="true">
        <intent-filter><action android:name="android.intent.action.VIEW"/>
          <category android:name="android.intent.category.DEFAULT"/>
          <category android:name="android.intent.category.BROWSABLE"/>
          <data android:scheme="fixture" android:host="route.invalid" android:path="/open"/>
        </intent-filter>
      </activity></application></manifest>''')
    parsed = ManifestParser().parse(str(decoded))
    state = create_initial_state('synthetic', 'unused', str(tmp_path))
    state.update(decompiled_path=str(tmp_path), resource_path=str(tmp_path), smali_path=str(tmp_path),
                 manifest_data=parsed, package_name='com.example')

    result = await worker._run_analysis(state)

    summary = result['coverage']['deep_link_flow_correlation']
    assert summary['status'] == 'bounded_same_class_join_completed'
    assert summary['correlated_flows'] == 1
    assert summary['proof_status'] == 'not_proven'
    assert result['coverage']['android_surface']['categories']['deep_links'][
        'uri_flow_manifest_route_correlation'] == summary
    correlated = next(item for item in result['raw_findings']
                      if item.get('metadata', {}).get('source_kind') == 'URI_QUERY_PARAM')
    assert correlated['metadata']['manifest_route_correlation']['runtime_verified'] is False


def test_reports_include_category_coverage():
    state=create_initial_state('synthetic','unused')
    engine=ReportEngine();data=engine._prepare_data(state)
    assert data['exhaustive_analysis'] is False and data['coverage']['android_surface']['categories']['intent']['proof_status']=='not_proven'
    assert 'Coverage and proof boundaries' in engine._generate_markdown(data)
    assert 'not_started' in engine._generate_markdown(data)


def test_report_separates_unverified_candidates_from_analyst_attested_confirmations():
    state=create_initial_state('synthetic','unused')
    from mobileag.reporting.validation import bind_confirmation
    from tests.proof_fixtures import confirmation_evidence
    binding={'artifact_sha256':'a'*64,'package_name':'org.example.synthetic','version':'1.0'}
    state.update(binding)
    proof=bind_confirmation(confirmation_evidence(),binding)
    state['filtered_findings']=[
        {'id':'u','status':'UNVERIFIED','severity':'HIGH','cvss_score':0},
        {'id':'c','status':'CONFIRMED','severity':'INFO','cvss_score':0,'validation_evidence':proof},
    ]
    data=ReportEngine()._prepare_data(state)
    assert data['stats']['total']==2
    assert data['stats']['confirmed']==1
    assert data['stats']['unverified_candidates']==1
    assert data['stats']['high']==0  # severity counters are confirmed-only
    assert data['stats']['info']==1
    assert data['stats']['candidate_severity']['high']==1
    assert 'not independently verified' in data['candidate_count_semantics']
    report = ReportEngine()._generate_markdown(data)
    assert 'Confirmed severity totals' in report
    assert 'Unverified candidate labels (provisional)' in report


def test_report_marks_incomplete_static_coverage_separately_from_job_completion():
    state=create_initial_state('synthetic','unused')
    state['coverage']['secrets']['static_status']='partial'
    data=ReportEngine()._prepare_data(state)
    assert data['assessment_coverage']=='partial'
    assert 'coverage.secrets.static_status=partial' in data['coverage_gaps']
    assert state['assessment_coverage']=='not_assessed'
    state['coverage']['secrets']['static_status']='unsupported'
    assert ReportEngine()._prepare_data(state)['assessment_coverage']=='partial'


def test_report_exposes_non_exhaustive_and_budget_limited_coverage():
    state=create_initial_state('synthetic','unused')
    state['coverage']['taint'].update(static_status='analyzed_heuristically', exhaustive=False)
    state['coverage']['taint']['limits_reached']=True
    data=ReportEngine()._prepare_data(state)
    assert data['assessment_coverage']=='partial'
    assert 'coverage.taint.exhaustive=false' in data['coverage_gaps']
    assert 'coverage.taint.limits_reached=true' in data['coverage_gaps']
    summary=data['coverage_summary']
    assert summary['non_exhaustive_analysis_count'] >= 1
    assert summary['limits_reached_paths']==['coverage.taint']
    markdown=ReportEngine()._generate_markdown(data)
    assert 'non-exhaustive analyses:' in markdown
    assert '`coverage.taint.limits_reached=true`' in markdown


@pytest.mark.asyncio
async def test_generate_report_persists_assessment_coverage_in_state(tmp_path):
    state=create_initial_state('synthetic','unused',str(tmp_path))
    state['coverage']['secrets']['static_status']='partial'
    await ReportEngine().generate_reports(state)
    assert state['assessment_coverage']=='partial'
    assert 'coverage.secrets.static_status=partial' in state['coverage_gaps']


def test_webview_debugging_and_safe_browsing_checks_have_positive_and_negative_controls():
    analyzer = AndroidSurfaceAnalyzer()
    positive = '''class ReleaseConfig {
      void configure() {
        WebView.setWebContentsDebuggingEnabled(true);
        settings.setSafeBrowsingEnabled(false);
      }
    }'''
    findings, _ = analyzer.analyze_source(positive, 'Positive.java')
    assert {finding.metadata['check_id'] for finding in findings} == {
        'web_contents_debugging_enabled', 'safe_browsing_disabled'}
    assert all(finding.status == FindingStatus.UNVERIFIED and finding.severity == Severity.INFO
               and finding.metadata['proof_state'] == 'not_proven' for finding in findings)

    negative = '''class ReleaseConfig {
      // WebView.setWebContentsDebuggingEnabled(true);
      String sample = "settings.setSafeBrowsingEnabled(false)";
      void configure() {
        WebView.setWebContentsDebuggingEnabled(false);
        settings.setSafeBrowsingEnabled(true);
      }
    }'''
    findings, _ = analyzer.analyze_source(negative, 'Negative.java')
    assert findings == []


def test_pending_intent_checks_flags_argument_and_accepts_literal_mutability_constants():
    analyzer = AndroidSurfaceAnalyzer()
    source = '''class PendingIntents {
      void build() {
        PendingIntent.getActivity(context, 0, intent, flags);
        PendingIntent.getActivity(context, PendingIntent.FLAG_IMMUTABLE, createIntent(PendingIntent.FLAG_MUTABLE), flags);
        PendingIntent.getBroadcast(context, 1, intent, PendingIntent.FLAG_IMMUTABLE);
        PendingIntent.getService(context, 2, intent, PendingIntent.FLAG_MUTABLE);
      }
    }'''
    findings, _ = analyzer.analyze_source(source, 'PendingIntents.java')
    matches = [finding for finding in findings if finding.metadata.get('check_id') == 'pending_intent_mutability_review']
    assert len(matches) == 2
    mutable = [finding for finding in findings if finding.metadata.get('check_id') == 'pending_intent_mutable_flags_review']
    assert len(mutable) == 1
    assert mutable[0].metadata['category'] == 'intent'
    assert mutable[0].status == FindingStatus.UNVERIFIED and mutable[0].severity == Severity.INFO
    assert mutable[0].metadata['proof_state'] == 'not_proven'
    assert 'FLAG_IMMUTABLE unless fill-in behavior is required' in mutable[0].remediation
    assert matches[0].status == FindingStatus.UNVERIFIED
    assert matches[0].severity == Severity.INFO
    assert matches[0].metadata['proof_state'] == 'not_proven'
    assert 'effective flags expression' in matches[0].remediation


def test_pending_intent_resolves_only_unique_bounded_final_flag_aliases():
    analyzer = AndroidSurfaceAnalyzer()
    source = '''class AliasedFlags {
      private static final int IMMUTABLE_FLAGS = PendingIntent.FLAG_IMMUTABLE;
      private static final int MUTABLE_FLAGS = PendingIntent.FLAG_MUTABLE | PendingIntent.FLAG_UPDATE_CURRENT;
      private static final int UNKNOWN_FLAGS = helper();
      void build() {
        PendingIntent.getActivity(context, 0, immutable, IMMUTABLE_FLAGS);
        PendingIntent.getBroadcast(context, 1, mutable, MUTABLE_FLAGS);
        PendingIntent.getService(context, 2, unknown, UNKNOWN_FLAGS);
      }
    }'''
    findings, _ = analyzer.analyze_source(source, 'AliasedFlags.java')
    by_check = {}
    for finding in findings:
        by_check.setdefault(finding.metadata.get('check_id'), []).append(finding)

    assert len(by_check['pending_intent_mutability_review']) == 1
    assert len(by_check['pending_intent_mutable_flags_review']) == 1
    assert all(f.status == FindingStatus.UNVERIFIED and f.severity == Severity.INFO for f in findings)


def test_pending_intent_resolves_kotlin_const_val_flag_alias():
    analyzer = AndroidSurfaceAnalyzer()
    source = '''object PendingFlags {
      const val IMMUTABLE_FLAGS: Int = PendingIntent.FLAG_IMMUTABLE
      fun create() {
        PendingIntent.getActivity(context, 0, intent, IMMUTABLE_FLAGS)
      }
    }'''
    findings, _ = analyzer.analyze_source(source, 'PendingFlags.kt')
    assert not [f for f in findings if f.metadata.get('check_id') == 'pending_intent_mutability_review']
    assert not [f for f in findings if f.metadata.get('check_id') == 'pending_intent_mutable_flags_review']


def test_pending_intent_duplicate_flag_alias_remains_unresolved():
    analyzer = AndroidSurfaceAnalyzer()
    source = '''class First { static final int FLAGS = PendingIntent.FLAG_IMMUTABLE; }
    class Second { static final int FLAGS = PendingIntent.FLAG_MUTABLE; }
    class Use { void create() { PendingIntent.getActivity(context, 0, intent, FLAGS); } }'''
    findings, _ = analyzer.analyze_source(source, 'AmbiguousFlags.java')
    matches = [f for f in findings if f.metadata.get('check_id') == 'pending_intent_mutability_review']
    assert len(matches) == 1
    assert matches[0].status == FindingStatus.UNVERIFIED


def test_possible_untrusted_deserialization_needs_same_method_entry_lead_and_stays_unproven():
    analyzer = AndroidSurfaceAnalyzer()
    source = '''class ImportReceiver {
      void onReceive(Context context, Intent intent) {
        Object payload = intent.getSerializableExtra("payload");
        ObjectInputStream stream = new ObjectInputStream(input);
        Object value = stream.readObject();
      }
      void localOnly() {
        ObjectInputStream stream = new ObjectInputStream(input);
        Object value = stream.readObject();
      }
    }'''
    findings, _ = analyzer.analyze_source(source, 'ImportReceiver.java')
    matches = [finding for finding in findings if finding.metadata.get('check_id') == 'untrusted_deserialization_source_sink_review']
    assert len(matches) == 1
    assert matches[0].status == FindingStatus.UNVERIFIED and matches[0].severity == Severity.INFO
    assert matches[0].metadata['proof_state'] == 'not_proven'
    assert 'dataflow not proven' in matches[0].description


def test_webview_external_input_bridge_same_method_is_only_a_review_candidate():
    analyzer = AndroidSurfaceAnalyzer()
    source = '''class Router {
      void route(Intent intent, WebView webView) {
        String url = intent.getData().toString();
        webView.addJavascriptInterface(new Bridge(), "bridge");
        webView.loadUrl(url);
      }
    }'''
    findings, _ = analyzer.analyze_source(source, 'Router.java')
    matches = [finding for finding in findings if finding.metadata.get('check_id') == 'external_input_webview_bridge_review']
    assert len(matches) == 1
    assert matches[0].status == FindingStatus.UNVERIFIED and matches[0].severity == Severity.INFO
    assert matches[0].metadata['proof_state'] == 'not_proven'
    assert 'dataflow not proven' in matches[0].description


@pytest.mark.parametrize('annotation', ['@JavascriptInterface public void bridge(String value) { }',
                                         '@JavascriptInterface\n public void bridge(String value) { }'])
def test_webview_coverage_inventories_javascript_interface_methods_only(annotation):
    analyzer = AndroidSurfaceAnalyzer()
    source = f'class Bridge {{ {annotation} public void local(String value) {{ }} }}'
    _, sites = analyzer.analyze_source(source, 'Bridge.java')
    bridges = [site for site in sites['webview'] if site['operation'] == 'JavascriptInterface method']
    assert len(bridges) == 1
    assert bridges[0]['method_name'] == 'bridge'
    assert bridges[0]['evidence'].startswith('annotation_inventory_only')


def test_sensitive_looking_log_identifier_is_review_candidate_not_secret_flow_proof():
    analyzer = AndroidSurfaceAnalyzer()
    positive = '''class Auth {
      void debug(String accessToken) {
        android.util.Log.d("auth", accessToken);
      }
    }'''
    findings, _ = analyzer.analyze_source(positive, 'Auth.java')
    matches = [finding for finding in findings if finding.metadata.get('check_id') == 'sensitive_identifier_in_log_review']
    assert len(matches) == 1
    assert matches[0].status == FindingStatus.UNVERIFIED and matches[0].severity == Severity.INFO
    assert matches[0].metadata['proof_state'] == 'not_proven'
    negative = '''class Auth {
      void debug(String message) {
        // Log.d("auth", accessToken);
        String sample = "Log.d(auth, password)";
        android.util.Log.d("auth", message);
      }
    }'''
    findings, _ = analyzer.analyze_source(negative, 'AuthSafe.java')
    assert not [finding for finding in findings if finding.metadata.get('check_id') == 'sensitive_identifier_in_log_review']


def test_timber_sensitive_argument_is_inventory_lead_and_literal_is_not():
    analyzer=AndroidSurfaceAnalyzer()
    source='''class Auth {
      void debug(String accessToken, String message) {
        Timber.tag("auth").d("token=%s", accessToken);
        Timber.d("message=%s", message);
      }
    }'''
    findings,_=analyzer.analyze_source(source,'Auth.java')
    matches=[finding for finding in findings if finding.metadata.get('check_id')=='sensitive_identifier_in_log_review']
    assert len(matches)==1
    assert matches[0].severity==Severity.INFO and matches[0].status==FindingStatus.UNVERIFIED
    assert matches[0].metadata['proof_state']=='not_proven'
