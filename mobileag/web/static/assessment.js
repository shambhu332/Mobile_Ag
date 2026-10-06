/* Primary upload → scope → stages → start → results workflow; no implicit tests. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);if(text)el.textContent=text;if(parent)parent.append(el);return el;};
  const root=document.getElementById('view-assessment');const panel=make('section','',root);panel.className='workflow-panel assessment-panel';
  make('h2','Start an authorized assessment',panel);
  make('p','1 Upload APK → 2 Approve APK + API scope → 3 Choose stages → 4 Start → 5 Review evidence. Advanced tools remain optional. Uploading alone never starts testing.',panel);
  const status=make('p','Choose an owned APK to begin.',panel);status.id='assessment-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');
  const form=make('form','',panel);const fields={};let current=null,timer=null;
  const field=(key,title,tag='input',type='text')=>{const label=make('label',title,form),el=make(tag,'',label);el.id='assessment-'+key;if(tag==='input')el.type=type;fields[key]=el;return el;};
  const upload=field('file','1. Upload your authorized Android APK','input','file');upload.accept='.apk';
  upload.addEventListener('change',async()=>{if(!upload.files[0])return;status.textContent='Uploading and validating archive (no scan started)…';try{const result=await uploadApkFile(upload.files[0],false);if(result?.error)status.textContent=result.error;}catch(e){status.textContent=e.message;}});
  const artifact=field('artifact','Uploaded artifact');artifact.readOnly=true;
  const pkg=field('package','2. Exact authorized Android package ID');pkg.required=true;
  const origins=field('origins','Authorized API origins (one per line; exact scheme/host/port)','textarea');origins.rows=2;
  const serial=field('serial','Dedicated device serial (only for DAST)');
  const component=field('component','Approved package/activity (only for DAST)');
  const methods=field('methods','Approved API methods (read-only)');methods.value='GET,HEAD';methods.readOnly=true;
  const check=(key,title)=>{const el=field(key,title,'input','checkbox');el.parentElement.className='assessment-check';el.parentElement.prepend(el);return el;};
  check('api','3. API testing: approved observed GET/HEAD requests');
  check('dast','DAST: device preflight, optional install/launch and live screen mapping');
  check('install','Install this exact APK only if its package is absent (device-wide; no replacement or forced runtime grants)');
  check('launch','Launch the explicitly approved activity');
  const captures=field('captures','Observed read-only requests (JSON array; no credentials/headers/bodies)','textarea');captures.value='[]';captures.rows=4;
  const captureHelp=make('p','Example: [{"method":"GET","url":"https://your-staging.example/profile","read_only_confirmed":true,"protected":true,"response_status":200}]. Discovered URLs are not automatically authorized. API tests do not require a device.',form);
  const authorization=field('authorization','Dedicated test Authorization header (optional, memory only)','input','password');authorization.autocomplete='off';
  const llm=field('provider','Optional AI review (aggregate counts/coverage only)','select');
  const noAI=make('option','No AI — deterministic testing only',llm);noAI.value='';
  check('egress','I approve sending only aggregate counts/status to the selected model provider (cloud may charge fees/share with processors)');
  check('account','I confirm dedicated synthetic/staging test accounts for API/device stages');
  check('device','I confirm an authorized dedicated test device for DAST (ADB input is device-wide)');
  check('authorized','I own/have permission for this APK and every listed API/device target');fields.authorized.required=true;
  check('scope','I approve replacing the saved global workbench scope; this can stop other active jobs');fields.scope.required=true;
  const confirmation=field('confirmation','Type START SCOPED TESTS to approve execution');confirmation.required=true;
  make('p','SAST always runs offline in the isolated worker. Live phases start only after static success and an exact package match. DAST maps the live app automatically; taps on discovered controls still need exact action approval. No root, TLS bypass, write APIs or destructive tests.',form);
  const providerHelp=make('details','',form);make('summary','Configure local/cloud providers (server owner)',providerHelp);
  make('p','Keep keys in your server environment or private .env, never in an APK or report. Use .env.example for exact variable names. Configure MOBILEAG_LLM_ALLOWED_PROVIDERS and MOBILEAG_LLM_<PROVIDER>_MODEL; cloud adapters need their server API key. Local Ollama/OpenAI-compatible servers also need MOBILEAG_LLM_LOCAL_ORIGINS and an explicit loopback origin. Restart the server, then Refresh providers. Configuration does not prove provider availability.',providerHelp);
  const show=(name,visible)=>{fields[name].parentElement.style.display=visible?'':'none';};
  function updateStages(){
    const api=fields.api.checked,dast=fields.dast.checked;
    for(const name of ['origins','methods','captures','authorization'])show(name,api);
    for(const name of ['serial','component','install','launch','device'])show(name,dast);
    captureHelp.style.display=api?'':'none';
    show('account',api||dast);show('egress',Boolean(llm.value));
  }
  for(const field of [fields.api,fields.dast,llm])field.addEventListener('change',updateStages);
  updateStages();
  const controls=make('div','',panel);controls.className='workflow-actions';
  const button=(title,parent,run)=>{const b=make('button',title,parent);b.type='button';b.addEventListener('click',async()=>{b.disabled=true;try{await run();}catch(e){status.textContent=e.message;}finally{b.disabled=false;}});return b;};
  button('Check tools and server scope',controls,async()=>{const [ready,scope]=await Promise.all([fetch('/api/readiness').then(r=>r.json()),fetch('/api/scope').then(r=>r.json())]);status.textContent='Offline sandbox: '+(ready.sandbox_probe?'ready':'unavailable; SAST will not run unsafely')+'; allowed devices: '+(scope.ceilings.devices.join(', ')||'none')+'; API origins: '+(scope.ceilings.origins.join(', ')||'none');});
  button('Refresh providers',controls,loadProviders);
  button('Advanced static APK/IPA scan',controls,async()=>{document.getElementById('scan-modal').classList.remove('hidden');});
  button('Load previous assessments',controls,loadRuns);
  const submit=make('button','Start scoped assessment',form);submit.type='submit';submit.id='assessment-start';
  const runs=make('div','',panel);runs.id='assessment-runs';
  const results=make('div','',panel);results.id='assessment-results';
  window.addEventListener('assessment-uploaded',event=>{artifact.value=event.detail.path;status.textContent='APK uploaded. No tests started; review and approve scope.';});
  async function loadProviders(){
    const data=await(await fetch('/api/assessments/providers')).json();llm.replaceChildren();const empty=make('option','No AI — deterministic testing only',llm);empty.value='';
    for(const provider of data.providers){const option=make('option',provider.title+' · '+(provider.enabled?provider.model:'configure server first'),llm);option.value=provider.id;option.disabled=!provider.enabled;}
    updateStages();status.textContent='Provider configuration loaded; no provider contacted. Keys remain server-side. Select a configured provider and explicitly approve metadata egress.';
  }
  async function loadRuns(){runs.replaceChildren();const list=await(await fetch('/api/assessments')).json();if(!list.length)make('p','No guided assessments yet.',runs);for(const row of list)button(row.package_name+' · '+row.status,runs,async()=>{current=await(await fetch('/api/assessments/'+row.id)).json();render();});}
  form.addEventListener('submit',async event=>{event.preventDefault();if(confirmation.value!=='START SCOPED TESTS'){status.textContent='Type START SCOPED TESTS before execution.';return;}submit.disabled=true;
    try{
      const isDast=fields.dast.checked,isAPI=fields.api.checked;
      const actions=isDast?['automation_observe','automation_execute']:[];
      if(isDast&&fields.install.checked)actions.push('install');if(isDast&&fields.launch.checked)actions.push('launch');
      const scope={devices:isDast?[serial.value.trim()]:[],packages:[pkg.value.trim()],origins:isAPI?origins.value.split(/\s+/).filter(Boolean):[],methods:['GET','HEAD'],actions};
      const body={apk_path:artifact.value,package_name:pkg.value.trim(),scope,authorized:fields.authorized.checked,scope_change_confirmed:fields.scope.checked,confirmation:confirmation.value,
        api:isAPI,dast:isDast,serial:isDast?serial.value.trim():null,component:isDast?component.value.trim():null,
        dedicated_account_confirmed:fields.account.checked,dedicated_device_confirmed:fields.device.checked,
        install_if_absent:isDast&&fields.install.checked,launch:isDast&&fields.launch.checked,captures:isAPI?JSON.parse(captures.value):[],llm_provider:llm.value||null,llm_metadata_egress_confirmed:fields.egress.checked};
      if(authorization.value)body.api_authorization=authorization.value;authorization.value='';
      current=await(await fetch('/api/assessments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();render();
    }catch(e){status.textContent=e.message;}finally{submit.disabled=false;}
  });
  function render(){
    results.replaceChildren();status.textContent=current.id+' · '+current.status+' · '+(current.reason||'');
    make('h3','Stage results (actual execution, not promised coverage)',results);
    for(const [name,stage] of Object.entries(current.stages))make('p',name.toUpperCase()+': '+stage.status+(stage.executed!==undefined?' · '+stage.executed+' cases observed':'')+(stage.screens!==undefined?' · '+stage.screens+' live screens mapped':''),results);
    const actions=make('div','',results);actions.className='workflow-actions';
    if(current.scan_id)button('Review SAST findings',actions,async()=>{await loadSpecificScan(current.scan_id);switchView('findings');});
    if(current.automation_run_id)button('Review/approve exact navigation actions',actions,async()=>{window.dispatchEvent(new CustomEvent('automation-open-run',{detail:{id:current.automation_run_id}}));});
    button('Stop future stages',actions,async()=>{await fetch('/api/assessments/'+current.id+'/cancel',{method:'POST'});status.textContent='Stop requested. Issued actions cannot be undone.';}).disabled=current.status!=='running';
    button('Export assessment evidence',actions,async()=>{const data=await(await fetch('/api/assessments/'+current.id)).json();const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const link=make('a','',document.body);link.href=url;link.download=current.id+'-assessment.json';link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
    const pre=make('pre',JSON.stringify(current,null,2),results);pre.tabIndex=0;pre.setAttribute('aria-label','Assessment evidence, keyboard-scrollable');
    if(timer)clearTimeout(timer);if(current.status==='running')timer=setTimeout(async()=>{try{current=await(await fetch('/api/assessments/'+current.id)).json();render();}catch(e){status.textContent=e.message;}},1500);
  }
  document.getElementById('nav-assessment').addEventListener('click',async()=>{switchView('assessment');try{await loadProviders();await loadRuns();}catch(e){status.textContent=e.message;}});
})();
