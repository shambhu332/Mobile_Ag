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
    monkeypatch.setattr(worker._call_graph_engine,'audit_smali_directory',lambda _:[])
    (tmp_path/'Fixture.java').write_text('class Fixture{void cfg(){settings.setAllowUniversalAccessFromFileURLs(true);}}')
    state=create_initial_state('synthetic','unused',str(tmp_path));state.update(decompiled_path=str(tmp_path),resource_path=str(tmp_path),smali_path=str(tmp_path))
    result=await worker._run_analysis(state)
    assert result['coverage']['engines']['taint']=='skipped_disabled'
    assert result['coverage']['android_surface']['categories']['webview']['candidate_count']==1
    assert result['raw_findings'][0]['status']=='UNVERIFIED'
    monkeypatch.setattr(worker._android_surface,'analyze',AsyncMock(side_effect=RuntimeError('synthetic failure')))
    result=await worker._run_analysis(create_initial_state('synthetic2','unused',str(tmp_path)))
    assert result['coverage']['engines']['android_surface']=='incomplete'
    assert result['errors']


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
