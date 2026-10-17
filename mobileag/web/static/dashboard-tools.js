/* Dashboard operation UX. Never mint tokens, execute arbitrary shell/URLs, or start target tests. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);el.textContent=text||'';parent?.append(el);return el;};
  const button=(text,parent,run)=>{const el=make('button',text,parent);el.type='button';el.addEventListener('click',run);return el;};
  const toolbar=document.getElementById('workspace-tools');
  let connected=Boolean(localSessionActive), generation=0, pending=false, capabilities=null, previousFocus=null, tourIndex=-1;
  const opener=button('',toolbar,open);opener.id='dashboard-tools-open';opener.setAttribute('aria-haspopup','dialog');opener.setAttribute('aria-controls','dashboard-tools-dialog');
  const badge=make('span','',opener);badge.id='dashboard-session-label';badge.setAttribute('role','status');
  const dialog=make('dialog','',document.body);dialog.id='dashboard-tools-dialog';dialog.className='ui-dialog dashboard-tools';dialog.setAttribute('aria-labelledby','dashboard-tools-title');
  const header=make('div','',dialog);header.className='dashboard-tools-header';
  const titleBlock=make('div','',header);make('p','LOCAL WORKSPACE',titleBlock).className='dashboard-eyebrow';make('h2','Session & dashboard tools',titleBlock).id='dashboard-tools-title';
  const close=button('Close',header,()=>dialog.close());close.id='dashboard-tools-close';
  make('p','This browser receives a same-origin HttpOnly session automatically. Navigation and reads never start a scan, model review or device action.',dialog);
  const grid=make('div','',dialog);grid.className='dashboard-tools-grid';
  const session=make('section','',grid);session.className='dashboard-tool-card';make('h3','01 · Session connection',session);
  const sessionState=make('p','',session);sessionState.id='dashboard-session-state';sessionState.setAttribute('role','status');sessionState.setAttribute('aria-live','polite');
  make('p','The session cookie is HttpOnly and SameSite=Strict; page scripts cannot read it. API authorization and server-side expiry remain enforced.',session);
  const sessionActions=make('div','',session);sessionActions.className='dashboard-tool-actions';
  const verify=button('Check connection',sessionActions,async()=>{
    const current=generation;verify.disabled=true;
    try{await(await fetch('/api/status')).json();if(current===generation)sessionState.textContent='Connection verified now. This did not start testing.';}
    catch(error){if(current===generation)sessionState.textContent='Local session unavailable. Reload the dashboard.';}
    finally{verify.disabled=!connected;}
  });verify.id='dashboard-verify';
  button('Reload dashboard session',sessionActions,()=>window.location.reload());
  make('p','The browser cookie expires after eight hours. Restart the server to invalidate all browser sessions; closing a tab alone does not revoke it.',session).className='dashboard-note';
  const nav=make('section','',grid);nav.className='dashboard-tool-card';make('h3','02 · Navigate without execution',nav);
  make('p','Open a section or follow a five-step review tour. These controls never select devices, approve scope, or press execution buttons.',nav);
  const sections=[['overview','Overview'],['assessment','Start Assessment'],['surface','Attack Surface'],['findings','Findings & Evidence'],['scans','Scan History'],['settings','Configuration'],['dast','Device Diagnostics'],['taint','Taint Dataflow'],['api','API Review'],['automation','Navigation Review'],['agents','Analyzer Capabilities']];
  const jump=make('div','',nav);jump.className='dashboard-nav-grid';
  const navButtons=sections.map(([id,name])=>{const b=button(name,jump,()=>{dialog.close();navigate(id);});b.dataset.dashboardView=id;return b;});
  const startTour=button('Start navigation-only tour',nav,()=>{dialog.close();tourIndex=0;renderTour();});startTour.id='dashboard-tour-start';
  const tour=make('section','',toolbar);tour.id='dashboard-tour';tour.hidden=true;tour.setAttribute('aria-label','Navigation-only review tour');
  const tourState=make('span','',tour);tourState.id='dashboard-tour-status';tourState.setAttribute('role','status');tourState.setAttribute('aria-live','polite');
  const tourPrev=button('Previous',tour,()=>{if(tourIndex>0){tourIndex--;renderTour();}});tourPrev.id='dashboard-tour-previous';
  const tourNext=button('Next section',tour,()=>{tourIndex++;renderTour();});tourNext.id='dashboard-tour-next';
  const stop=button('Stop tour',tour,()=>{tourIndex=-1;tour.hidden=true;opener.focus();});stop.id='dashboard-tour-stop';
  const tourSteps=[['overview','Review the selected job or empty state.'],['settings','Inspect configuration; changing scope needs explicit approval.'],['assessment','Review scope and stages; do not start without authorization.'],['findings','Review evidence; static candidates are not exploit proof.'],['scans','Inspect history and incomplete jobs.']];
  function navigate(id){document.getElementById('nav-'+id)?.click();document.getElementById('workspace-title')?.focus();}
  function renderTour(){
    if(tourIndex>=tourSteps.length){tourIndex=-1;tour.hidden=true;opener.focus();showToast('Navigation tour finished. No tests were started.','info');return;}
    if(!connected){tourIndex=-1;tour.hidden=true;return;}
    tour.hidden=false;const [id,hint]=tourSteps[tourIndex];navigate(id);
    tourState.textContent=`Step ${tourIndex+1}/${tourSteps.length} · ${hint}`;tourPrev.disabled=tourIndex===0;tourNext.textContent=tourIndex===tourSteps.length-1?'Finish tour':'Next section';tourNext.focus();
  }
  const workbench=make('section','',grid);workbench.className='dashboard-tool-card dashboard-read-card';make('h3','03 · Read-only HTTP / curl',workbench);
  make('p','Choose a dashboard endpoint and explicitly read it. Curl runs on the server against its own listening socket—not arbitrary URLs or shell commands. Redirects and target-device endpoints are blocked.',workbench);
  const availability=make('p','Connect to inspect server-side tool availability.',workbench);availability.id='dashboard-read-availability';
  const form=make('form','',workbench);form.id='dashboard-read-form';
  const fields=make('div','',form);fields.className='dashboard-read-fields';
  const endpointLabel=make('label','Dashboard endpoint',fields),endpoint=make('select','',endpointLabel);endpoint.id='dashboard-read-path';
  const presets=[['/api/status','System status'],['/api/preflight','Local readiness (host-only)'],['/api/scope','Authorized scope'],['/api/scans?limit=10&summaries=true','Scan summaries'],['/api/assessments','Guided assessment history'],['/api/assessments/providers','Provider configuration (not a health check)'],['/api/automation/runs','Navigation run history']];
  for(const [path,label]of presets)make('option',label,endpoint).value=path;
  const transportLabel=make('label','Transport',fields),transport=make('select','',transportLabel);transport.id='dashboard-read-transport';
  make('option','HTTP client',transport).value='httpx';const curlOption=make('option','Curl (server-side)',transport);curlOption.value='curl';
  const actions=make('div','',form);actions.className='dashboard-tool-actions';const run=make('button','Read endpoint',actions);run.type='submit';run.id='dashboard-read-run';
  const copy=button('Copy safe CLI command',actions,async()=>{
    const command=`python -m mobileag.cli dashboard api --path '${endpoint.value}' --transport ${transport.value} --url '${window.location.origin}'`;
    try{await navigator.clipboard.writeText(command);readState.textContent='Copied a token-free CLI command. It privately prompts unless MOBILEAG_API_TOKEN is configured.';}
    catch(error){readState.textContent='Clipboard unavailable; use the token-free command below.';output.textContent=command;}
  });copy.id='dashboard-read-copy';
  const clear=button('Clear result',actions,()=>{output.textContent='No endpoint read yet.';readState.textContent='Result cleared from this page.';});clear.id='dashboard-read-clear';
  const readState=make('p','No request sent. Connect, choose an endpoint and select Read endpoint.',workbench);readState.id='dashboard-read-status';readState.setAttribute('role','status');readState.setAttribute('aria-live','polite');
  const output=make('pre','No endpoint read yet.',workbench);output.id='dashboard-read-result';output.tabIndex=0;output.setAttribute('aria-label','Read-only dashboard result, keyboard-scrollable');
  make('p','No response, credential or command is saved automatically. Sensitive fields and reflected session tokens are redacted by the server; results are not a security verdict.',workbench).className='dashboard-note';
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(!connected||pending||!capabilities?.local_socket_available)return;
    const current=generation;pending=true;update();readState.textContent='Reading the selected dashboard endpoint…';output.textContent='Waiting for a bounded response…';
    try{const result=await(await fetch('/api/dashboard/read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:endpoint.value,transport:transport.value})})).json();
      if(current!==generation)return;
      output.textContent=JSON.stringify(result.data,null,2);readState.textContent=`HTTP ${result.status_code} · ${result.transport} · this dashboard only · no target testing.`;
    }catch(error){if(current===generation){output.textContent='No result retained.';readState.textContent='Read failed. Check connection, local server and transport availability. No automatic retry.';}}
    finally{if(current===generation){pending=false;update();}}
  });
  async function loadCapabilities(){
    const current=generation;
    try{const data=await(await fetch('/api/dashboard/capabilities')).json();if(current===generation){capabilities=data;update();}}
    catch(error){if(current===generation){capabilities=null;readState.textContent='Dashboard tools unavailable. Reconnect and reopen this panel.';update();}}
  }
  function update(){
    badge.textContent=(connected?'Local session':'Disconnected')+' · Dashboard tools';opener.dataset.connected=String(connected);
    sessionState.textContent=connected?'Local browser session active; credential is HttpOnly and not exposed to page scripts.':'Local session unavailable. Reload the dashboard.';
    verify.disabled=!connected;startTour.disabled=!connected;navButtons.forEach(b=>b.disabled=!connected);
    availability.textContent=!connected?'Disconnected; no server-side tool authority.':!capabilities?'Tool availability not loaded; reopen this panel to check.':!capabilities.local_socket_available?'Unavailable for this server binding; the workbench requires a loopback-capable local socket.':'Local HTTP client available · '+(capabilities.curl_installed?'curl installed (not a health check)':'curl not installed; use HTTP client')+' · redirects blocked.';
    run.disabled=!connected||pending||!capabilities?.local_socket_available;endpoint.disabled=pending;transport.disabled=pending;clear.disabled=pending;copy.disabled=pending;
    curlOption.disabled=!capabilities?.curl_installed;if(curlOption.disabled&&transport.value==='curl')transport.value='httpx';
    run.textContent=pending?'Reading…':'Read endpoint';form.setAttribute('aria-busy',String(pending));
  }
  function open(){if(document.querySelector('dialog[open]'))return;previousFocus=document.activeElement;dialog.showModal();close.focus();if(connected)loadCapabilities();update();}
  dialog.addEventListener('close',()=>{if(!document.querySelector('dialog[open]'))previousFocus?.focus();});
  window.addEventListener('workspace-session-connected',()=>{generation++;connected=Boolean(localSessionActive);pending=false;capabilities=null;output.textContent='No endpoint read yet.';readState.textContent='Current local session connected. No request sent.';update();if(dialog.open)loadCapabilities();});
  window.addEventListener('workspace-session-invalidated',()=>{generation++;connected=false;pending=false;capabilities=null;output.textContent='Result cleared after disconnect.';readState.textContent='Session disconnected; no cached response is retained.';tourIndex=-1;tour.hidden=true;update();if(dialog.open)dialog.close();});
  update();
})();

/* Evidence presentation is DOM/text only, never executable finding instructions. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);el.textContent=text||'';parent?.append(el);return el;};
  function finding(parent,value){
    const card=make('section','',parent);card.className='evidence-review';card.id='finding-evidence-review';
    make('h3','Evidence & next review step',card);
    const state=value.evidence_assessment||{};
    make('p','Basis: '+(state.basis||'not_proven')+' · artifact binding: '+(state.artifact_binding||'not_verified'),card);
    make('p','Independent exploit verification: not established. Valid CONFIRMED records are analyst attestations, not automatic proof.',card);
    if(value.reported_status&&value.reported_status!==value.status)make('p','Reported '+value.reported_status+' was downgraded for presentation because required evidence or artifact binding was not satisfied. The stored decision is unchanged.',card);
    if(state.missing_fields?.length)make('p','Missing evidence: '+state.missing_fields.join(', '),card);
    if(state.validation_errors?.length)make('p','Review gaps: '+state.validation_errors.join(', '),card);
    make('p','Next step: '+(value.investigation_plan?.next_step||'establish_external_reachability_and_attacker_control').replaceAll('_',' ')+'. Advisory only; this does not authorize execution.',card);
    const trace=value.metadata?.source_sink_trace;
    if(trace){const details=make('details','',card);make('summary','Structured static source / sink trace',details);const pre=make('pre',JSON.stringify(trace,null,2),details);pre.tabIndex=0;pre.setAttribute('aria-label','Static trace, keyboard-scrollable');}
    parent.prepend(card);
  }
  function coverage(parent,document){
    const card=make('section','',parent);card.className='evidence-review';card.id='assessment-coverage-review';make('h3','Coverage ledger · what was actually assessed',card);
    const ledger=document.coverage_ledger;
    if(!ledger){make('p','Coverage not recorded for this older assessment. Completed execution is not exhaustive security coverage.',card);return;}
    make('p','Coverage: '+ledger.assessment_coverage+' · security verdict: '+ledger.security_verdict+' · exhaustive: no',card);
    make('p','Authentication, account roles and attacker reachability are not inferred from visible screens or HTTP status codes.',card);
    const rows=make('ul','',card);
    for(const [name,stage]of Object.entries(ledger.stages||{}))make('li',name.toUpperCase()+': '+stage.execution_status+(stage.authentication_status?' · authentication: '+stage.authentication_status:'')+(stage.authorization_validation?' · authorization: '+stage.authorization_validation:''),rows);
    const gaps=make('ul','',card);gaps.setAttribute('aria-label','Remaining coverage gaps');for(const gap of ledger.gaps||[])make('li',gap,gaps);
  }
  window.MobileAgEvidence=Object.freeze({finding,coverage});
})();

/* Import operator evidence only; no API replay or account impersonation. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);el.textContent=text||'';parent?.append(el);return el;};
  let sessionGeneration=0;
  window.addEventListener('workspace-session-invalidated',()=>{sessionGeneration++;const dialog=document.getElementById('authorization-pair-dialog');if(dialog){dialog.querySelector('textarea').value='';dialog.close();}});
  function add(parent,document,onUpdate){
    const captures=(document.stages.api?.inventory||[]).filter(c=>c.protected);
    const launch=make('button','Import synthetic paired-account evidence',parent);launch.type='button';launch.disabled=document.status==='running'||!captures.length;
    launch.title='Requires a completed assessment and an approved protected API capture. No network requests are replayed.';
    launch.addEventListener('click',()=>{
      if(window.document.querySelector('dialog[open]'))return;
      const focus=window.document.activeElement,dialog=make('dialog','',window.document.body);dialog.id='authorization-pair-dialog';dialog.className='ui-dialog dashboard-tools';dialog.setAttribute('aria-labelledby','authorization-pair-title');
      make('h2','Compare synthetic paired-account captures',dialog).id='authorization-pair-title';
      make('p','Import owner baseline, other-account baseline and cross-account response with distinct synthetic markers and opaque evidence IDs. This compares operator-provided data; it does not log in, send requests or independently verify account identity, ownership or exploitation.',dialog);
      const form=make('form','',dialog),captureLabel=make('label','Approved protected API capture',form),capture=make('select','',captureLabel);capture.id='authorization-pair-capture';
      for(const row of captures)make('option','Capture '+row.id,capture).value=row.id;
      const label=make('label','AuthorizationPair JSON (synthetic, redacted captures only)',form),input=make('textarea','',label);input.id='authorization-pair-json';input.rows=10;input.maxLength=65536;input.required=true;input.autocomplete='off';input.spellcheck=false;
      make('p','Required fields: owner_baseline, other_account_baseline, cross_account (status_code, response_json, evidence_id); marker_path; distinct owner_marker / other_marker starting mobileag-test-; and the explicit authorized_synthetic_captures, distinct_controlled_accounts_confirmed, same_owner_resource_requested, identities_checked confirmations. Artifact and capture binding come from this assessment.',form);
      const consentLabel=make('label','',form),consent=make('input','',consentLabel);consent.type='checkbox';consent.required=true;consent.id='authorization-pair-consent';make('span','I am importing authorized researcher-controlled, synthetic data—not real user data or credentials.',consentLabel);
      const actions=make('div','',form);actions.className='dashboard-tool-actions';const submit=make('button','Import and compare (no replay)',actions);submit.type='submit';submit.id='authorization-pair-submit';
      const cancel=make('button','Cancel',actions);cancel.type='button';cancel.addEventListener('click',()=>dialog.close());
      const status=make('p','Nothing imported yet.',dialog);status.setAttribute('role','status');status.setAttribute('aria-live','polite');
      form.addEventListener('submit',async event=>{
        event.preventDefault();if(!consent.checked||submit.disabled)return;
        if(new TextEncoder().encode(input.value).length>65536){status.textContent='Import exceeds the 64 KiB UI budget. No import was sent.';return;}
        let value;try{value=JSON.parse(input.value);if(!value||Array.isArray(value)||typeof value!=='object')throw new Error();}catch(error){status.textContent='Invalid JSON object. No import was sent.';return;}
        value.artifact_sha256=document.artifact_sha256;value.capture_id=capture.value;
        const generation=sessionGeneration;input.value='';submit.disabled=true;status.textContent='Comparing the imported synthetic evidence…';
        try{await(await fetch('/api/assessments/'+document.id+'/authorization-evidence',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)})).json();
          if(generation!==sessionGeneration)return;dialog.close();await onUpdate();showToast('Imported comparison recorded as UNVERIFIED; no requests replayed.','info');
        }catch(error){if(generation===sessionGeneration)status.textContent='Import rejected. Check scope, artifact, baselines, controls, evidence IDs and lifecycle. Raw input was cleared; no automatic retry.';}
        finally{submit.disabled=false;value=null;}
      });
      dialog.addEventListener('close',()=>{input.value='';dialog.remove();focus?.focus();});dialog.showModal();capture.focus();
    });
    for(const comparison of document.authorization_comparisons||[])make('p','Imported authorization comparison: '+comparison.outcome+' · UNVERIFIED · operator import, not independent proof.',parent);
  }
  window.MobileAgAuthorizationEvidence=Object.freeze({add});
})();
