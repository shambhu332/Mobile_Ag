/* Primary upload → scope → stages → start → results workflow; no implicit tests. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);if(text)el.textContent=text;if(parent)parent.append(el);return el;};
  const root=document.getElementById('view-assessment');const panel=make('section','',root);panel.className='workflow-panel assessment-panel';
  make('h2','Start an authorized assessment',panel);
  make('p','1 Upload APK → 2 Approve APK + API scope → 3 Choose stages → 4 Start → 5 Review evidence. Advanced tools remain optional. Uploading alone never starts testing.',panel);
  const status=make('p','Choose an owned APK to begin.',panel);status.id='assessment-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');
  const form=make('form','',panel);const fields={};let current=null,timer=null;
  let providers=new Map(),providersLoaded=false,providerLoad=0,submitting=false,uploading=false;
  const field=(key,title,tag='input',type='text')=>{const label=make('label',title,form),el=make(tag,'',label);el.id='assessment-'+key;if(tag==='input')el.type=type;fields[key]=el;return el;};
  const upload=field('file','1. Upload your authorized Android APK','input','file');upload.accept='.apk';
  upload.addEventListener('change',async()=>{if(!upload.files[0])return;artifact.value='';uploading=true;upload.disabled=true;updateProvider();status.textContent='Uploading and validating archive (no scan started)…';try{const result=await uploadApkFile(upload.files[0],false);if(result?.error)status.textContent=result.error;}catch(e){status.textContent=e.message;}finally{uploading=false;upload.disabled=false;updateProvider();updatePlan();}});
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
  const llm=field('provider','Primary AI provider (aggregate counts/coverage only)','select');
  const noAI=make('option','No AI — deterministic testing only',llm);noAI.value='';
  const model=field('model','Primary server-configured model (read-only)');model.readOnly=true;
  const secondary=field('secondary','Secondary AI provider (HTTP 429 fallback only)','select');make('option','No secondary — stop on rate limit',secondary).value='';
  const secondaryModel=field('secondary-model','Secondary server-configured model (read-only)');secondaryModel.readOnly=true;
  const providerInfo=make('div','',form);providerInfo.id='assessment-provider-info';providerInfo.setAttribute('role','status');providerInfo.setAttribute('aria-live','polite');llm.setAttribute('aria-describedby',providerInfo.id);secondary.setAttribute('aria-describedby',providerInfo.id);
  check('egress','I approve sending aggregate counts/status to the primary provider (cloud may charge fees/share with processors)');
  check('fallback-egress','I also approve sending the same metadata to the secondary provider, once only if the primary returns HTTP 429 (secondary may charge fees)');
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
    show('account',api||dast);show('egress',Boolean(llm.value));show('model',Boolean(llm.value));show('secondary',Boolean(llm.value));show('secondary-model',Boolean(llm.value&&secondary.value));show('fallback-egress',Boolean(llm.value&&secondary.value));
    updateProvider();if(typeof plan!=='undefined')updatePlan();
  }
  for(const field of [fields.api,fields.dast])field.addEventListener('change',updateStages);
  llm.addEventListener('change',()=>{fields.egress.checked=false;fields['fallback-egress'].checked=false;if(!llm.value)secondary.value='';updateStages();});
  secondary.addEventListener('change',()=>{fields['fallback-egress'].checked=false;updateStages();});
  fields['fallback-egress'].addEventListener('change',updateProvider);
  fields.egress.addEventListener('change',updateProvider);
  const controls=make('div','',panel);controls.className='workflow-actions';
  const button=(title,parent,run)=>{const b=make('button',title,parent);b.type='button';b.addEventListener('click',async()=>{b.disabled=true;try{await run();}catch(e){status.textContent=e.message;}finally{b.disabled=false;}});return b;};
  button('Check tools and server scope',controls,async()=>{const [ready,scope]=await Promise.all([fetch('/api/readiness').then(r=>r.json()),fetch('/api/scope').then(r=>r.json())]);status.textContent='Offline sandbox: '+(ready.sandbox_probe?'ready':'unavailable; SAST will not run unsafely')+'; allowed devices: '+(scope.ceilings.devices.join(', ')||'none')+'; API origins: '+(scope.ceilings.origins.join(', ')||'none');});
  const providerControls=document.getElementById('configuration-llm-controls');
  const providerActions=make('div','',providerControls);providerActions.className='workflow-actions';
  button('Refresh providers',providerActions,loadProviders);
  button('Return to Start Assessment',providerActions,async()=>{document.getElementById('nav-assessment').click();(llm.value?fields.egress:configureAI).focus();});
  button('Advanced static APK/IPA scan',controls,async()=>{document.getElementById('scan-modal').classList.remove('hidden');});
  button('Load previous assessments',controls,loadRuns);
  const submit=make('button','Start scoped assessment',form);submit.type='submit';submit.id='assessment-start';
  const steps=make('ol','',panel);steps.className='assessment-steps';steps.setAttribute('aria-label','Assessment preparation steps');form.before(steps);
  for(const title of ['1 Artifact','2 Test stages','3 Optional AI','4 Approve & start'])make('li',title,steps);
  const sections=[['Artifact and package',['file','artifact','package']],['Scoped test stages',['api','origins','methods','captures','authorization','account','dast','serial','component','install','launch','device']],['Optional AI review',['egress','fallback-egress']],['Authorization and execution',['authorized','scope','confirmation']]];
  const groups=sections.map(([title,keys],index)=>{const group=make('fieldset','',form);group.className='form-section';make('legend',`${index+1}. ${title}`,group);for(const key of keys)group.append(fields[key].parentElement);return group;});
  groups[1].append(captureHelp);
  const providerGroup=make('fieldset','',providerControls);providerGroup.className='form-section';make('legend','Primary / secondary selection',providerGroup);
  for(const key of ['provider','model','secondary','secondary-model'])providerGroup.append(fields[key].parentElement);
  providerGroup.append(providerInfo,providerHelp);providerControls.append(providerActions);
  const aiSummary=make('p','',groups[2]);aiSummary.id='assessment-ai-summary';aiSummary.setAttribute('role','status');aiSummary.setAttribute('aria-live','polite');groups[2].prepend(aiSummary);
  const openConfiguration=()=>{document.getElementById('scan-modal').classList.add('hidden');document.getElementById('nav-settings').click();llm.focus();};
  const configureAI=button('Configure LLM providers',groups[2],openConfiguration);configureAI.id='assessment-configure-ai';
  groups[2].insertBefore(aiSummary,fields.egress.parentElement);groups[2].insertBefore(configureAI,fields.egress.parentElement);
  const plan=make('p','',groups[3]);plan.id='assessment-plan-summary';plan.className='assessment-plan';submit.before(plan);groups[3].append(plan,submit);
  form.addEventListener('input',updatePlan);form.addEventListener('change',updatePlan);
  function updatePlan(){const names=['SAST (offline)',...(fields.api.checked?['API (explicit GET/HEAD captures)']:[]),...(fields.dast.checked?['DAST (map first; later action approval)']:[]),...(llm.value?['AI primary: '+(providers.get(llm.value)?.title||llm.value)+(secondary.value?' → HTTP 429 only → secondary: '+(providers.get(secondary.value)?.title||secondary.value):' (no fallback)')]:[])];plan.textContent='Selected stages: '+names.join(' → ')+'\nPackage: '+(pkg.value.trim()||'not specified')+' · Artifact: '+(artifact.value?'uploaded; original preserved':'not uploaded')+'\nNothing starts until you approve the scope and press Start.';steps.children[0].dataset.complete=String(Boolean(artifact.value&&pkg.value.trim()));steps.children[1].dataset.complete='true';steps.children[2].dataset.complete=String(!llm.value||aiReady());steps.children[3].dataset.complete=String(fields.authorized.checked&&fields.scope.checked&&confirmation.value==='START SCOPED TESTS');}
  updateStages();updatePlan();
  const runs=make('div','',panel);runs.id='assessment-runs';
  const results=make('div','',panel);results.id='assessment-results';
  window.addEventListener('assessment-uploaded',event=>{artifact.value=event.detail.path;status.textContent=event.detail.platform==='ios'?'IPA uploaded. Use Advanced static APK/IPA scan; guided live assessment accepts Android APKs only.':'APK uploaded. No tests started; review and approve scope.';updatePlan();});
  function aiReady(){return Boolean(providersLoaded&&providers.get(llm.value)?.enabled&&fields.egress.checked&&(!secondary.value||(secondary.value!==llm.value&&providers.get(secondary.value)?.enabled&&fields['fallback-egress'].checked)));}
  function updateProvider(){
    providerInfo.replaceChildren();model.value=providers.get(llm.value)?.model||'';secondaryModel.value=providers.get(secondary.value)?.model||'';
    if(!llm.value)make('p','AI is optional. Select a primary provider to inspect setup. No provider has been contacted.',providerInfo);
    else if(!providersLoaded)make('p','Provider configuration unavailable or loading. Refresh providers before starting AI review.',providerInfo);
    else{
      for(const [role,id] of [['Primary',llm.value],['Secondary',secondary.value]]){
        if(!id)continue;const provider=providers.get(id);
        if(!provider){make('p',role+' provider missing from catalog; refresh or select another.',providerInfo);continue;}
        make('p',role+': '+provider.title+' — '+(provider.enabled?'Configured (not a connectivity test).':'Setup required — execution blocked: '+provider.reason),providerInfo);
        const setup=provider.setup;
        if(setup){
          const details=make('details','',providerInfo);make('summary','Server setup for '+provider.title,details);
          make('p','Keep keys private on the server. Merge BOTH selected IDs into the comma-separated approval list (for Gemini and Grok: gemini,grok), configure exact models, restart and refresh. Never paste keys into the dashboard.',details);
          const lines=[setup.approval_variable+'='+[llm.value,secondary.value].filter(Boolean).join(','),setup.model_variable+'=REPLACE_WITH_EXACT_MODEL_ID'];
          if(setup.key_variable)lines.push(setup.key_variable+'=REPLACE_PRIVATELY_ON_SERVER');
          if(setup.origin_variable)lines.push(setup.origin_variable+'='+setup.default_origin,setup.allowed_origins_variable+'='+setup.default_origin);
          const code=make('pre',lines.join('\n'),details);code.tabIndex=0;code.setAttribute('aria-label','Server configuration variable names, no credentials');
        }
      }
      if(secondary.value===llm.value)make('p','Choose different primary and secondary providers. Execution is blocked.',providerInfo);
      else if(secondary.value)make('p','On primary HTTP 429 only, try the approved secondary once. No fallback for authentication errors, timeouts, server errors or blocked/invalid content; no retry loop. Each assessment starts with the primary.',providerInfo);
    }
    aiSummary.textContent=llm.value?'Selected AI: primary '+(providers.get(llm.value)?.title||llm.value)+' / '+(model.value||'model not configured')+(secondary.value?' → HTTP 429 only → secondary '+(providers.get(secondary.value)?.title||secondary.value)+' / '+(secondaryModel.value||'model not configured'):'; no secondary')+'. '+(providersLoaded?'Review the configuration and approve metadata egress below.':'Provider catalog unavailable; refresh in Configuration before approving AI.'):'No AI selected — deterministic stages only. Choose optional providers in Configuration.';
    submit.disabled=submitting||uploading||Boolean(llm.value&&!aiReady());
  }
  async function loadProviders(){
    const sequence=++providerLoad;providersLoaded=false;updateProvider();
    try{
      const data=await(await fetch('/api/assessments/providers')).json();if(sequence!==providerLoad)return;
      if(!Array.isArray(data.providers))throw new Error('Invalid provider catalog; retry Refresh providers.');
      const primaryId=llm.value,secondaryId=secondary.value,previous=providers.get(primaryId),previousSecondary=providers.get(secondaryId);
      providers=new Map(data.providers.map(provider=>[provider.id,provider]));
      if([primaryId,secondaryId].some(id=>id&&!providers.has(id)))throw new Error('Selected provider no longer appears in the catalog. Review primary and secondary selections.');
      for(const [selector,id,emptyTitle] of [[llm,primaryId,'No AI — deterministic testing only'],[secondary,secondaryId,'No secondary — stop on rate limit']]){
        selector.replaceChildren();make('option',emptyTitle,selector).value='';
        for(const provider of data.providers)make('option',provider.title+' · '+(provider.enabled?provider.model:'Setup required'),selector).value=provider.id;
        selector.value=id;
      }
      providersLoaded=true;
      if(primaryId&&(!providers.get(primaryId)?.enabled||previous?.model!==providers.get(primaryId).model)){fields.egress.checked=false;fields['fallback-egress'].checked=false;}
      if(secondaryId&&(!providers.get(secondaryId)?.enabled||previousSecondary?.model!==providers.get(secondaryId).model))fields['fallback-egress'].checked=false;
      updateStages();
    }catch(error){if(sequence===providerLoad){providersLoaded=false;updateProvider();make('p','Could not load provider configuration: '+error.message,providerInfo);}throw error;}
  }
  async function loadRuns(){runs.replaceChildren();const list=await(await fetch('/api/assessments')).json();if(!list.length)make('p','No guided assessments yet.',runs);for(const row of list)button(row.package_name+' · '+row.status,runs,async()=>{current=await(await fetch('/api/assessments/'+row.id)).json();render();});}
  form.addEventListener('submit',async event=>{event.preventDefault();if(uploading){status.textContent='Wait for archive upload and validation to finish.';return;}if(!artifact.value){status.textContent='Upload an authorized Android APK first.';upload.focus();return;}if((secondary.value&&!llm.value)||(llm.value&&!aiReady())){status.textContent='AI review needs distinct configured providers and explicit primary/secondary egress approval. Choose No AI to run deterministic stages only.';updateProvider();return;}if(confirmation.value!=='START SCOPED TESTS'){status.textContent='Type START SCOPED TESTS before execution.';return;}submitting=true;updateProvider();
    try{
      const isDast=fields.dast.checked,isAPI=fields.api.checked;
      const actions=isDast?['automation_observe','automation_execute']:[];
      if(isDast&&fields.install.checked)actions.push('install');if(isDast&&fields.launch.checked)actions.push('launch');
      const scope={devices:isDast?[serial.value.trim()]:[],packages:[pkg.value.trim()],origins:isAPI?origins.value.split(/\s+/).filter(Boolean):[],methods:['GET','HEAD'],actions};
      const body={apk_path:artifact.value,package_name:pkg.value.trim(),scope,authorized:fields.authorized.checked,scope_change_confirmed:fields.scope.checked,confirmation:confirmation.value,
        api:isAPI,dast:isDast,serial:isDast?serial.value.trim():null,component:isDast?component.value.trim():null,
        dedicated_account_confirmed:fields.account.checked,dedicated_device_confirmed:fields.device.checked,
        install_if_absent:isDast&&fields.install.checked,launch:isDast&&fields.launch.checked,captures:isAPI?JSON.parse(captures.value):[],llm_provider:llm.value||null,llm_metadata_egress_confirmed:fields.egress.checked,llm_secondary_provider:secondary.value||null,llm_fallback_egress_confirmed:Boolean(secondary.value&&fields['fallback-egress'].checked)};
      if(authorization.value)body.api_authorization=authorization.value;authorization.value='';
      current=await(await fetch('/api/assessments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json();render();
    }catch(e){status.textContent=e.message;}finally{submitting=false;updateProvider();}
  });
  function render(){
    results.replaceChildren();status.textContent=current.id+' · '+current.status+' · '+(current.reason||'');
    make('h3','Stage results (actual execution, not promised coverage)',results);
    for(const [name,stage] of Object.entries(current.stages))make('p',name.toUpperCase()+': '+stage.status+(stage.executed!==undefined?' · '+stage.executed+' cases observed':'')+(stage.screens!==undefined?' · '+stage.screens+' live screens mapped':''),results);
    const review=current.stages.llm?.review,attempts=review?.attempts||current.stages.llm?.attempts||[];
    if(review)make('p','AI advice from '+review.provider+' / '+review.model+(review.fallback_used?' — secondary used after primary HTTP 429':' — primary used; secondary not contacted'),results);
    if(attempts.length)make('p','Provider attempts: '+attempts.map(attempt=>attempt.provider+': '+attempt.outcome+(attempt.http_status?' (HTTP '+attempt.http_status+')':'')).join(' → '),results);
    if(current.stages.llm?.reason)make('p','AI stage: '+current.stages.llm.reason,results);
    const actions=make('div','',results);actions.className='workflow-actions';
    if(current.scan_id)button('Review SAST findings',actions,async()=>{await loadSpecificScan(current.scan_id);switchView('findings');});
    if(current.automation_run_id)button('Review/approve exact navigation actions',actions,async()=>{window.dispatchEvent(new CustomEvent('automation-open-run',{detail:{id:current.automation_run_id}}));});
    button('Stop future stages',actions,async()=>{await fetch('/api/assessments/'+current.id+'/cancel',{method:'POST'});status.textContent='Stop requested. Issued actions cannot be undone.';}).disabled=current.status!=='running';
    button('Export assessment evidence',actions,async()=>{const data=await(await fetch('/api/assessments/'+current.id)).json();const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));const link=make('a','',document.body);link.href=url;link.download=current.id+'-assessment.json';link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
    const evidence=make('details','',results);make('summary','Technical assessment evidence (JSON)',evidence);
    const pre=make('pre',JSON.stringify(current,null,2),evidence);pre.tabIndex=0;pre.setAttribute('aria-label','Assessment evidence, keyboard-scrollable');
    if(timer)clearTimeout(timer);if(current.status==='running')timer=setTimeout(async()=>{try{current=await(await fetch('/api/assessments/'+current.id)).json();render();}catch(e){status.textContent=e.message;}},1500);
  }
  document.getElementById('nav-assessment').addEventListener('click',async()=>{switchView('assessment');try{await loadProviders();await loadRuns();}catch(e){status.textContent=e.message;}});
  document.getElementById('nav-settings').addEventListener('click',async()=>{try{await loadProviders();}catch(e){status.textContent=e.message;}});
  document.getElementById('modal-open-ai')?.addEventListener('click',openConfiguration);
})();
