/* Manual, record-only test plan editor. It never starts device/API activity. */
(() => {
  const host = document.getElementById('view-scans');
  if (!host) return;
  const el = (tag, text, parent) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (parent) parent.append(node);
    return node;
  };
  const panel = el('section', undefined, host);
  panel.className = 'workflow-panel'; panel.id = 'manual-test-plan';
  el('h2', 'Manual test plan', panel);
  el('p', 'Record intended checks and researcher notes for the selected completed scan. Saving this plan does not authorize or run device/API actions. Use account aliases only; never enter credentials, tokens, cookies, endpoints, or device commands.', panel);
  const details = el('details', undefined, panel);
  el('summary', 'Open structured plan editor', details);
  const identity = el('p', 'No scan selected.', details); identity.id = 'test-plan-scope';
  const form = el('form', undefined, details); form.id = 'test-plan-form';
  form.addEventListener('submit', e => e.preventDefault());
  form.addEventListener('input',()=>markDirty());
  form.addEventListener('change',()=>markDirty());

  const definitions = {
    roles: {title:'Research roles', add:'Add role', fields:[['id','Role ID'],['purpose','Purpose']]},
    flows: {title:'Manual flows', add:'Add flow', fields:[['id','Flow ID'],['name','Flow name'],['entrypoint','Entrypoint description'],['sensitive_operation','Sensitive operation'],['prerequisites','Prerequisites']]},
    test_account_aliases: {title:'Test-account aliases', add:'Add account alias', fields:[['alias','Alias'],['role_id','Role ID']]},
    coverage: {title:'Surface coverage', add:'Add surface', fields:[['surface','Surface','surface'],['state','State','state'],['evidence_ref','Evidence note ID'],['gap_reason','Gap or N/A reason']]},
    evidence: {title:'Manual evidence notes', add:'Add evidence note', fields:[['id','Evidence ID'],['flow_id','Flow ID (optional)'],['finding_id','Finding ID (optional)'],['outcome','Outcome','outcome'],['summary','Summary'],['prerequisites','Prerequisites'],['steps','Steps (one per line)','multiline'],['expected','Expected result'],['observed','Observed result'],['negative_control','Negative control']]},
  };
  const choices = {
    surface:['manifest_ipc','serialization','files_uri_grants','storage_logging','webview_deep_links','network_api_auth','crypto_native','runtime'],
    state:['not_tested','candidate','observed','attested','not_applicable'],
    outcome:['not_tested','observed','not_reproduced'],
  };
  const state = Object.fromEntries(Object.keys(definitions).map(name => [name, []]));
  const containers = {};
  let dirty = false;
  let planSaved = false;
  let loadedScanId = null;
  function defaultRecord(name) {
    if (name === 'roles') return {id:'tester',purpose:'Researcher using synthetic test data'};
    if (name === 'flows') return {id:'flow1',name:'Describe one manual flow',entrypoint:'',sensitive_operation:'',prerequisites:''};
    if (name === 'coverage') return {surface:'manifest_ipc',state:'not_tested',evidence_ref:null,gap_reason:'Not assessed'};
    if (name === 'test_account_aliases') return {alias:'',role_id:''};
    return {id:'',flow_id:null,finding_id:null,outcome:'not_tested',summary:'',prerequisites:'',steps:[],expected:'',observed:'',negative_control:''};
  }
  function inputControl(name, field, labelText, kind, value, parent) {
    const label = el('label', labelText, parent);
    let control;
    if (kind === 'surface' || kind === 'state' || kind === 'outcome') {
      control = el('select', undefined, label);
      for (const choice of choices[kind]) { const option=el('option',choice,control); option.value=choice; }
      control.value = value || choices[kind][0];
    } else if (kind === 'multiline') {
      control = el('textarea', undefined, label); control.rows=3;
      control.value = Array.isArray(value) ? value.join('\n') : (value || '');
    } else {
      control = el('input', undefined, label); control.type='text'; control.maxLength=field === 'purpose' ? 300 : 1000;
      control.autocomplete='off'; control.spellcheck=false; control.value=value || '';
    }
    control.dataset.planField=field;
    return control;
  }
  function render(name) {
    const root=containers[name]; root.replaceChildren();
    state[name].forEach((record,index)=>{
      const card=el('fieldset',undefined,root); card.className='plan-entry';
      el('legend',`${definitions[name].title} ${index+1}`,card);
      for (const [field,label,kind] of definitions[name].fields)
        inputControl(name,field,label,kind||'text',record[field],card);
      const remove=el('button','Remove entry',card); remove.type='button'; remove.dataset.planRemove=name;
      remove.addEventListener('click',()=>{state[name].splice(index,1);dirty=true;render(name);});
    });
    const add=el('button',definitions[name].add,root); add.type='button'; add.dataset.planAdd=name;
    add.addEventListener('click',()=>{state[name].push(defaultRecord(name));dirty=true;render(name);});
  }
  for (const [name,definition] of Object.entries(definitions)) {
    const section=el('section',undefined,form); section.className='plan-collection';
    el('h3',definition.title,section);
    containers[name]=el('div',undefined,section); containers[name].className='plan-entries';
    if (name === 'roles' || name === 'flows' || name === 'coverage') state[name].push(defaultRecord(name));
    render(name);
  }

  const baselineLabel=el('label','Optional baseline scan ID for retest linkage (same package)',form);
  const baseline=el('input',undefined,baselineLabel); baseline.type='text'; baseline.autocomplete='off'; baseline.maxLength=128;
  baseline.addEventListener('input',markDirty);
  const expectedRevision=el('input',undefined,form); expectedRevision.type='hidden'; expectedRevision.value='';
  const actions=el('div',undefined,details); actions.className='workflow-actions';
  const save=el('button','Save manual plan',actions); save.type='button';
  const reload=el('button','Reload saved plan / discard draft',actions); reload.type='button';
  const compare=el('button','Compare with baseline',actions); compare.type='button';
  const status=el('p','',details); status.id='test-plan-status'; status.setAttribute('role','status'); status.setAttribute('aria-live','polite');
  function markDirty(){dirty=true;panel.dataset.dirty='true';status.textContent='Unsaved draft changes; save them or explicitly reload to discard.';}
  const comparison=el('pre','',details); comparison.id='test-plan-comparison'; comparison.tabIndex=0;

  function activeScan() { return typeof currentScan !== 'undefined' ? currentScan : null; }
  function planEndpoint(scanId) { return `/api/scans/${encodeURIComponent(scanId)}/test-plan`; }
  async function requestJson(url,options) {
    const response=await fetch(url,options);
    let body={}; try { body=await response.json(); } catch (_) {}
    if (!response.ok) throw Object.assign(new Error(body.detail || body.error || `HTTP ${response.status}`),{status:response.status});
    return body;
  }
  function loadRecord(name,record) {
    return Object.fromEntries(definitions[name].fields.map(([field,,kind])=>[
      field, kind==='multiline' ? (Array.isArray(record[field])?record[field]:[]) : (record[field] ?? (kind ? choices[kind][0] : ''))
    ]));
  }
  async function loadPlan(force=false) {
    const scan=activeScan();
    if(dirty && !force) {
      const sameScan=Boolean(scan && scan.scan_id===loadedScanId);
      identity.textContent=loadedScanId ? `Unsaved draft belongs to scan ${loadedScanId}. Reload it explicitly to discard the draft.` : 'Unsaved draft preserved until explicitly reloaded.';
      status.textContent=sameScan ? 'Unsaved draft preserved; save it or explicitly reload to discard.' : 'Draft preserved. Save is disabled until you explicitly discard/reload for the selected scan.';
      save.disabled=!sameScan; return;
    }
    loadedScanId=scan?.scan_id || null;
    form.hidden=!scan; actions.hidden=!scan; comparison.textContent=''; expectedRevision.value='';
    planSaved=false;
    save.disabled=true;
    if (!scan) { identity.textContent='No scan selected. Open a scan from Scan History first.'; return; }
    identity.textContent=`${scan.package_name || 'Package unknown'} · scan ${scan.scan_id} · SHA-256 ${scan.artifact_sha256 || 'not recorded'} · ${scan.status || 'unknown'}`;
    if (!['completed','complete','success'].includes(scan.status)) { status.textContent='Plans can only be saved for completed scans.'; form.hidden=true; actions.hidden=true; return; }
    try {
      const plan=await requestJson(planEndpoint(scan.scan_id));
      for (const name of Object.keys(definitions)) { state[name]=(plan[name]||[]).map(row=>loadRecord(name,row)); render(name); }
      baseline.value=plan.retest_of_scan_id||''; expectedRevision.value=String(plan.plan_revision); dirty=false;delete panel.dataset.dirty;
      planSaved=true;
      status.textContent=`Loaded saved plan, revision ${plan.plan_revision}.`; save.disabled=false;
    } catch(error) {
      if (error.status===404) {
        for (const name of Object.keys(definitions)) state[name]=(name==='roles'||name==='flows'||name==='coverage')?[defaultRecord(name)]:[];
        for (const name of Object.keys(definitions)) render(name);
        baseline.value=''; expectedRevision.value=''; dirty=false;delete panel.dataset.dirty;
        planSaved=false;
        status.textContent='No plan saved yet. This blank draft remains in the page until saved.'; save.disabled=false;
      } else status.textContent=`Plan unavailable: ${error.message}`;
    }
  }
  const nullableFields = new Set(['flow_id','finding_id','evidence_ref','gap_reason']);
  function gather(name) {
    return [...containers[name].querySelectorAll('.plan-entry')].map(card=>{
      const item={};
      for (const control of card.querySelectorAll('[data-plan-field]')) {
        const field=control.dataset.planField;
        if (field==='steps') item[field]=control.value.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
        else { const value=control.value.trim(); item[field]=(value || nullableFields.has(field)) ? (value || null) : ''; }
      }
      return item;
    });
  }
  save.addEventListener('click',async()=>{
    const scan=activeScan(); if(!scan||scan.scan_id!==loadedScanId)return; save.disabled=true;
    try {
      const payload={}; for(const name of Object.keys(definitions)) payload[name]=gather(name);
      if(baseline.value.trim()) payload.retest_of_scan_id=baseline.value.trim();
      if(expectedRevision.value!=='') payload.expected_revision=Number(expectedRevision.value);
      const saved=await requestJson(planEndpoint(scan.scan_id),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
      expectedRevision.value=String(saved.plan_revision); dirty=false;delete panel.dataset.dirty;
      planSaved=true;
      status.textContent=`Saved local manual plan revision ${saved.plan_revision}; notes remain unverified.`;
    } catch(error) { status.textContent=`Plan not saved: ${error.message}`; }
    finally { save.disabled=false; }
  });
  reload.addEventListener('click',()=>{dirty=false;loadPlan(true);});
  compare.addEventListener('click',async()=>{
    const scan=activeScan();
    if(!scan){status.textContent='Select a scan before comparing.';return;}
    if(dirty){status.textContent='Save or explicitly reload the changed plan before comparing its baseline.';return;}
    if(!planSaved||!baseline.value.trim()){status.textContent='Save a plan with a baseline scan ID before comparing.';return;}
    compare.disabled=true;
    try { comparison.textContent=JSON.stringify(await requestJson(`/api/scans/${encodeURIComponent(scan.scan_id)}/planned-comparison`),null,2); }
    catch(error) { comparison.textContent=`Comparison unavailable: ${error.message}`; }
    finally { compare.disabled=false; }
  });
  window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
  window.addEventListener('workspace-scan-changed',()=>loadPlan());
  window.addEventListener('workspace-session-connected',()=>loadPlan());
  loadPlan();
})();
