"""Evidence-aware report and regression comparison, never an invented risk score."""
import html

def layout_svg(snapshot):
    # Layout evidence is deliberately not raw pixels or UI text. Safe for secrets.
    elements=[e for e in snapshot['elements'] if e['bounds']]
    width=max([e['bounds'][2] for e in elements]+[320]);height=max([e['bounds'][3] for e in elements]+[480])
    parts=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" role="img" aria-label="Redacted structural UI layout"><rect width="100%" height="100%" fill="#fff"/>']
    for i,e in enumerate(elements):
        x,y,x2,y2=e['bounds']
        parts.append(f'<rect x="{x}" y="{y}" width="{x2-x}" height="{y2-y}" fill="none" stroke="#334155"/><text x="{x+2}" y="{y+14}" font-size="12" fill="#111">{i}: {html.escape(e["class"])}</text>')
    return ''.join(parts)+'</svg>'

def regression(before, after):
    """Compare assertions only. Missing observations cannot establish a fix."""
    previous = {r['test_id']: r for r in before['results']}
    current = {r['test_id']: r for r in after['results']}
    changed_context = [key for key in ('package_name', 'environment', 'auth_state')
                       if before.get(key) != after.get(key)]
    rows = []
    for tid, old in previous.items():
        new = current.get(tid, {})
        comparable = (not changed_context and old.get('executed') is True
                      and new.get('executed') is True
                      and old.get('assertion') == new.get('assertion')
                      and old.get('result') in {'failed', 'passed'}
                      and new.get('result') in {'failed', 'passed'})
        status = ('Unable to verify' if not comparable else
                  'Assertion now passes' if old['result'] == 'failed' and new['result'] == 'passed' else
                  'Assertion fails' if new['result'] == 'failed' else 'Assertion unchanged')
        rows.append({'test_id': tid, 'before': old['result'],
                     'after': new.get('result', 'not_executed'),
                     'verification_status': status, 'context_changes': changed_context,
                     'root_cause_fix_status': 'not_verified',
                     'boundary': 'Test assertion comparison, not proof a security root cause was fixed'})
    return rows

def report(doc,parent=None):
    results={r['test_id']:r for r in doc['results']}
    executed={k:r for k,r in results.items() if r.get('executed')}
    coverage=[{'feature':t['feature'],'screen':t.get('screen'),'test_id':t['id'],'variant':t['variant'],
        'ui_tested':t['kind']=='ui' and t['id'] in executed,
        'api_tested':t['kind']=='api' and t['id'] in executed,
        'security_tested':t['variant']=='unauthenticated' and t['id'] in executed,
        'ux_tested':False, 'result':results.get(t['id'],{}).get('result','not_executed'),
        'untested_reason':None if t['id'] in executed else results.get(t['id'],{}).get('reason') or t.get('blocked_reason') or 'Not approved or not reached within budget'}
        for t in doc['tests']]
    return {'executive_summary':{'status':doc['status'],'executed':len(executed),'generated':len(doc['tests']),
                'confirmed_security_issues':0,'production_readiness_score':None,'score_reason':'Coverage is incomplete; no numerical certification is inferred'},
        'test_state':{'environment':doc['environment'],'authentication_state':doc['auth_state'],'authentication_source':doc['auth_state_source'],'account_state':'operator-confirmed dedicated account; credentials are not persisted','database_state':'operator-prepared; agent does not reset data','network_state':'scoped read-only requests; no device network changes'},
        'application_map':{'package_name':doc['package_name'],'environment':doc['environment'],'device_metadata':doc.get('device_metadata',{})},
        'screen_graph':{'nodes':doc['screens'],'edges':doc['edges']},'api_inventory':doc['captures'],
        'coverage':coverage,'security_and_ux_observations':doc['observations'],
        'security_findings':[o for o in doc['observations'] if o.get('api')],
        'accessibility_findings':[o for o in doc['observations'] if not o.get('api')],
        'ui_ux_findings':[], 'performance':doc['measurements'],
        'crashes_reliability':{'crashes':'not_assessed','ANRs':'not_assessed','driver_status':doc['status'],'driver_reason':doc.get('reason')},
        'remediation_priorities':[{'observation_id':o['id'],'priority':'P3 review','recommendation':o['recommended_fix']} for o in doc['observations']],
        'api_ui_correlations':doc['correlations'],'failed_tests':[r for r in doc['results'] if r['result']=='failed'],
        'untested':[c for c in coverage if not c['ui_tested'] and not c['api_tested']],
        'regression':regression(parent,doc) if parent else [],
        'regression_suite':doc['tests'],'limitations':doc['limitations']}
