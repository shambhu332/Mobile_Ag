/* Bounded authorized automation. All evidence is rendered as text, not HTML. */
(() => {
  const root=document.getElementById('view-automation');
  const make=(tag,text,parent)=>{const el=document.createElement(tag);if(text)el.textContent=text;if(parent)parent.append(el);return el;};
  const panel=make('section','',root);panel.className='workflow-panel automation-panel';
  make('h2','Authorized automation',panel);
  make('p','Observe → map → generate → approve → execute → report → retest. Unknown controls are not clicked. Generated tests are not executed coverage. No root, consent acceptance, destructive writes or credential filling.',panel);
  make('p','ADB input is device-wide and package checks are not atomic isolation. Use a dedicated researcher-controlled device and synthetic/staging accounts only. Structural layouts hide pixels and text.',panel);
  const status=make('p','Load saved runs or discover an explicitly scoped application.',panel);status.id='automation-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');
  const controls=make('div','',panel);controls.className='workflow-actions';
  const button=(text,parent,fn)=>{const b=make('button',text,parent);b.type='button';b.addEventListener('click',async()=>{b.disabled=true;try{await fn();}catch(e){status.textContent=e.message;}finally{b.disabled=false;}});return b;};
  let current=null, timer=null;
  const fields={};const form=make('form','',panel);
  for(const [key,title,value] of [['serial','Exact authorized device serial',''],['package_name','Exact Android package ID',''],['component','Package/activity component',''],['parent_run_id','Regression baseline run ID (optional)',''],['max_steps','Maximum UI steps','8'],['max_requests','Maximum read-only API requests','4']]){
    const label=make('label',title,form),input=make('input','',label);input.name=key;input.id='automation-'+key;input.value=value;input.required=['serial','package_name','component'].includes(key);fields[key]=input;
    if(key.startsWith('max_')){input.type='number';input.min=key==='max_steps'?'1':'0';input.max=key==='max_steps'?'30':'10';}
  }
  const envLabel=make('label','Test environment',form),env=make('select','',envLabel);env.id='automation-environment';
  for(const v of ['synthetic','dedicated_staging']){const o=make('option',v,env);o.value=v;}
  const captureLabel=make('label','Imported read-only captures (JSON array; no headers, credentials or bodies)',form),captures=make('textarea','',captureLabel);captures.id='automation-captures';captures.value='[]';captures.rows=5;
  make('p','Example: [{"method":"GET","url":"https://your-staging.example/profile","read_only_confirmed":true,"protected":true}]. Import is operator-declared, not independently verified traffic. Exact origin/method scope is required.',form);
  const agreeLabel=make('label','I confirm a dedicated authorized device and synthetic/dedicated test account. No shared production data.',form),agree=make('input','',agreeLabel);agree.type='checkbox';agree.id='automation-dedicated-confirm';agree.required=true;
  button('Launch explicitly selected app',controls,async()=>{await fetch('/api/dast/launch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({serial:fields.serial.value,component:fields.component.value})});status.textContent='Launch request completed; inspect device state. Launch requires separate scope approval.';});
  button('Load saved runs',controls,loadRuns);
  const submit=make('button','Discover current app screen (no taps)',form);submit.type='submit';
  form.addEventListener('submit',async(event)=>{event.preventDefault();submit.disabled=true;try{
    const body={serial:fields.serial.value,package_name:fields.package_name.value,component:fields.component.value,environment:env.value,
      dedicated_account_confirmed:agree.checked,dedicated_device_confirmed:agree.checked,max_steps:Number(fields.max_steps.value),max_requests:Number(fields.max_requests.value),captures:JSON.parse(captures.value)};
    if(fields.parent_run_id.value)body.parent_run_id=fields.parent_run_id.value;
    current=await(await fetch('/api/automation/runs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();render();
  }catch(e){status.textContent=e.message;}finally{submit.disabled=false;}});
  const runs=make('div','',panel);runs.id='automation-runs';
  const detail=make('div','',panel);detail.id='automation-detail';
  async function loadRuns(){
    runs.replaceChildren();const data=await(await fetch('/api/automation/runs')).json();
    if(!data.length)make('p','No automation runs. Unknown/unapproved targets are not tested.',runs);
    for(const r of data)button(r.package_name+' · '+r.status+' · '+r.id,runs,async()=>{current=await(await fetch('/api/automation/runs/'+r.id)).json();render();});
  }
  function render(){
    detail.replaceChildren();status.textContent=current.id+' · '+current.status+' · revision '+current.revision+' · '+(current.reason||'');
    make('h3','Reviewed execution plan',detail);
    make('p','Approve only recognizable controls on your test device. Approval is for exact recorded controls; new screens pause for review. Input/consent/destructive cases remain untested. At most one attempt per UI action.',detail);
    const selectedActions=[],selectedCases=[];
    for(const a of current.actions){
      const label=make('label',`${a.label} · ${a.action} at ${JSON.stringify(a.original_bounds)} · ${a.id}${a.blocked_reason?' — '+a.blocked_reason:''}`,detail),check=make('input','',label);check.type='checkbox';check.disabled=Boolean(a.blocked_reason)||current.status==='running';
      check.dataset.actionId=a.id;selectedActions.push([check,a.id]);
    }
    for(const t of current.tests.filter(t=>t.kind==='api')){
      const label=make('label',`${t.feature} · ${t.variant} · ${t.id}`,detail),check=make('input','',label);check.type='checkbox';check.disabled=current.status==='running';selectedCases.push([check,t.id]);
    }
    const backLabel=make('label','Allow bounded Back navigation on this dedicated device',detail),back=make('input','',backLabel);back.type='checkbox';
    const tokenLabel=make('label','Dedicated test Authorization header (optional; memory only, not captured credentials)',detail),token=make('input','',tokenLabel);token.type='password';token.autocomplete='off';token.id='automation-test-authorization';
    const confirmLabel=make('label','Confirm execution by entering this run ID',detail),confirmation=make('input','',confirmLabel);confirmation.id='automation-confirmation';
    const actions=make('div','',detail);actions.className='workflow-actions';
    button('Execute approved batch',actions,async()=>{
      if(confirmation.value!==current.id)throw new Error('Enter the exact run ID before execution.');
      const body={revision:current.revision,confirmation:confirmation.value,approved_action_ids:selectedActions.filter(([c])=>c.checked).map(([,id])=>id),approved_api_cases:selectedCases.filter(([c])=>c.checked).map(([,id])=>id),allow_back:back.checked};
      if(token.value)body.test_authorization=token.value;token.value='';
      current=await(await fetch('/api/automation/runs/'+current.id+'/execute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();render();
    }).disabled=current.status==='running';
    button('Observe again (no taps)',actions,async()=>{current=await(await fetch('/api/automation/runs/'+current.id+'/observe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:current.revision})})).json();render();}).disabled=current.status==='running';
    button('Stop run',actions,async()=>{current=await(await fetch('/api/automation/runs/'+current.id+'/cancel',{method:'POST'})).json();render();}).disabled=current.status!=='running';
    button('Import/rebind capture URLs',actions,async()=>{current=await(await fetch('/api/automation/runs/'+current.id+'/captures',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:current.revision,captures:JSON.parse(captures.value)})})).json();render();}).disabled=current.status==='running';
    button('Prepare regression run',actions,async()=>{fields.parent_run_id.value=current.id;fields.package_name.value=current.package_name;fields.serial.value=current.serial;fields.component.value=current.component;form.scrollIntoView({behavior:'auto'});status.textContent='Re-establish the same test state manually, provide current capture URLs, then discover. No data reset is automatic.';});
    button('Export redacted report',actions,async()=>{const blob=await(await fetch('/api/automation/runs/'+current.id+'/export')).blob();const url=URL.createObjectURL(blob);const a=make('a','',document.body);a.href=url;a.download=current.id+'-report.json';a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
    button('Refresh evidence and coverage',actions,refreshReport);
    const evidence=make('pre','',detail);evidence.id='automation-report';evidence.tabIndex=0;evidence.setAttribute('aria-label','Redacted automation report, keyboard-scrollable');
    if(timer)clearTimeout(timer);
    if(current.status==='running')timer=setTimeout(async()=>{try{current=await(await fetch('/api/automation/runs/'+current.id)).json();render();}catch(e){status.textContent=e.message;}},1500);
    refreshReport().catch(e=>{status.textContent=e.message;});
  }
  async function refreshReport(){if(!current)return;const data=await(await fetch('/api/automation/runs/'+current.id+'/report')).json();const target=document.getElementById('automation-report');if(target)target.textContent=JSON.stringify(data,null,2);}
  window.addEventListener('automation-open-run',async event=>{switchView('automation');try{current=await(await fetch('/api/automation/runs/'+event.detail.id)).json();render();}catch(e){status.textContent=e.message;}});
  document.getElementById('nav-automation')?.addEventListener('click',async()=>{switchView('automation');try{await loadRuns();}catch(e){status.textContent=e.message;}});
})();
