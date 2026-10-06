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
  const llm=field('provider','Optional AI review (aggregate counts/coverage only)','select');
  const noAI=make('option','No AI — deterministic testing only',llm);noAI.value='';
  const model=field('model','Server-configured exact model (read-only)');model.readOnly=true;
  const providerInfo=make('div','',form);providerInfo.id='assessment-provider-info';providerInfo.setAttribute('role','status');providerInfo.setAttribute('aria-live','polite');llm.setAttribute('aria-describedby',providerInfo.id);
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
    show('account',api||dast);show('egress',Boolean(llm.value));show('model',Boolean(llm.value));
    updateProvider();if(typeof plan!=='undefined')updatePlan();
  }
  for(const field of [fields.api,fields.dast])field.addEventListener('change',updateStages);
  llm.addEventListener('change',()=>{fields.egress.checked=false;updateStages();});
  fields.egress.addEventListener('change',updateProvider);
  const controls=make('div','',panel);controls.className='workflow-actions';
  const button=(title,parent,run)=>{const b=make('button',title,parent);b.type='button';b.addEventListener('click',async()=>{b.disabled=true;try{await run();}catch(e){status.textContent=e.message;}finally{b.disabled=false;}});return b;};
  button('Check tools and server scope',controls,async()=>{const [ready,scope]=await Promise.all([fetch('/api/readiness').then(r=>r.json()),fetch('/api/scope').then(r=>r.json())]);status.textContent='Offline sandbox: '+(ready.sandbox_probe?'ready':'unavailable; SAST will not run unsafely')+'; allowed devices: '+(scope.ceilings.devices.join(', ')||'none')+'; API origins: '+(scope.ceilings.origins.join(', ')||'none');});
  button('Refresh providers',controls,loadProviders);
  button('Advanced static APK/IPA scan',controls,async()=>{document.getElementById('scan-modal').classList.remove('hidden');});
  button('Load previous assessments',controls,loadRuns);
  const submit=make('button','Start scoped assessment',form);submit.type='submit';submit.id='assessment-start';
  const steps=make('ol','',panel);steps.className='assessment-steps';steps.setAttribute('aria-label','Assessment preparation steps');form.before(steps);
  for(const title of ['1 Artifact','2 Test stages','3 Optional AI','4 Approve & start'])make('li',title,steps);
  const sections=[['Artifact and package',['file','artifact','package']],['Scoped test stages',['api','origins','methods','captures','authorization','account','dast','serial','component','install','launch','device']],['Optional AI review',['provider','model','egress']],['Authorization and execution',['authorized','scope','confirmation']]];
  const groups=sections.map(([title,keys],index)=>{const group=make('fieldset','',form);group.className='form-section';make('legend',`${index+1}. ${title}`,group);for(const key of keys)group.append(fields[key].parentElement);return group;});
  groups[1].append(captureHelp);groups[2].insertBefore(providerInfo,fields.egress.parentElement);groups[2].append(providerHelp);
  const plan=make('p','',groups[3]);plan.id='assessment-plan-summary';plan.className='assessment-plan';submit.before(plan);groups[3].append(plan,submit);
  form.addEventListener('input',updatePlan);form.addEventListener('change',updatePlan);
  function updatePlan(){const names=['SAST (offline)',...(fields.api.checked?['API (explicit GET/HEAD captures)']:[]),...(fields.dast.checked?['DAST (map first; later action approval)']:[]),...(llm.value?['AI ('+(providers.get(llm.value)?.title||llm.value)+')']:[])];plan.textContent='Selected stages: '+names.join(' → ')+'\nPackage: '+(pkg.value.trim()||'not specified')+' · Artifact: '+(artifact.value?'uploaded; original preserved':'not uploaded')+'\nNothing starts until you approve the scope and press Start.';steps.children[0].dataset.complete=String(Boolean(artifact.value&&pkg.value.trim()));steps.children[1].dataset.complete='true';steps.children[2].dataset.complete=String(!llm.value||Boolean(providersLoaded&&providers.get(llm.value)?.enabled&&fields.egress.checked));steps.children[3].dataset.complete=String(fields.authorized.checked&&fields.scope.checked&&confirmation.value==='START SCOPED TESTS');}
  updateStages();updatePlan();
  const runs=make('div','',panel);runs.id='assessment-runs';
  const results=make('div','',panel);results.id='assessment-results';
  window.addEventListener('assessment-uploaded',event=>{artifact.value=event.detail.path;status.textContent=event.detail.platform==='ios'?'IPA uploaded. Use Advanced static APK/IPA scan; guided live assessment accepts Android APKs only.':'APK uploaded. No tests started; review and approve scope.';updatePlan();});
  function updateProvider(){
    providerInfo.replaceChildren();const provider=providers.get(llm.value),selected=Boolean(llm.value);
    model.value=provider?.model||'';
    if(!selected)make('p','AI is optional. Select any provider to see its setup requirements. No provider has been contacted.',providerInfo);
    else if(!providersLoaded||!provider)make('p','Provider configuration unavailable or loading. Refresh providers before starting AI review.',providerInfo);
    else{
      make('p',provider.enabled?'Configured for selection (not a connectivity test). Approve aggregate-metadata egress below to include AI review.':'Setup required — AI execution is blocked: '+provider.reason,providerInfo);
      const setup=provider.setup;
      if(setup){
        const details=make('details','',providerInfo);make('summary','Server setup for '+provider.title,details);
        make('p','Set these privately in the server environment or .env. Replace placeholders with your actual model/key, merge the provider into the existing allowlist, restart the server, then Refresh providers. Do not paste keys into this dashboard.',details);
        const lines=[setup.approval_variable+'='+provider.id,setup.model_variable+'=REPLACE_WITH_EXACT_MODEL_ID'];
        if(setup.key_variable)lines.push(setup.key_variable+'=REPLACE_PRIVATELY_ON_SERVER');
        if(setup.origin_variable)lines.push(setup.origin_variable+'='+setup.default_origin,setup.allowed_origins_variable+'='+setup.default_origin);
        const code=make('pre',lines.join('\n'),details);code.tabIndex=0;code.setAttribute('aria-label','Server configuration variable names, no credentials');
      }
    }
    submit.disabled=submitting||uploading||(selected&&(!providersLoaded||!provider?.enabled||!fields.egress.checked));
  }
  async function loadProviders(){
    const sequence=++providerLoad;providersLoaded=false;updateProvider();
    try{
      const data=await(await fetch('/api/assessments/providers')).json();if(sequence!==providerLoad)return;
      if(!Array.isArray(data.providers))throw new Error('Invalid provider catalog; retry Refresh providers.');
      const selected=llm.value,previous=providers.get(selected);providers=new Map(data.providers.map(provider=>[provider.id,provider]));
      if(selected&&!providers.has(selected))throw new Error('Selected provider no longer appears in the server catalog. Choose No AI or an available provider.');
      llm.replaceChildren();const empty=make('option','No AI — deterministic testing only',llm);empty.value='';
      for(const provider of data.providers){const option=make('option',provider.title+' · '+(provider.enabled?provider.model:'Setup required'),llm);option.value=provider.id;}
      // Keep the operator's intent on refresh; never silently drop AI to No AI.
      llm.value=selected;providersLoaded=true;
      const refreshed=providers.get(selected);if(selected&&(!refreshed?.enabled||previous?.model!==refreshed.model))fields.egress.checked=false;
      updateStages();
    }catch(error){if(sequence===providerLoad){providersLoaded=false;updateProvider();make('p','Could not load provider configuration: '+error.message,providerInfo);}throw error;}
  }
  async function loadRuns(){runs.replaceChildren();const list=await(await fetch('/api/assessments')).json();if(!list.length)make('p','No guided assessments yet.',runs);for(const row of list)button(row.package_name+' · '+row.status,runs,async()=>{current=await(await fetch('/api/assessments/'+row.id)).json();render();});}
  form.addEventListener('submit',async event=>{event.preventDefault();if(uploading){status.textContent='Wait for archive upload and validation to finish.';return;}if(!artifact.value){status.textContent='Upload an authorized Android APK first.';upload.focus();return;}if(llm.value&&(!providersLoaded||!providers.get(llm.value)?.enabled||!fields.egress.checked)){status.textContent='AI review needs server configuration and explicit metadata-egress approval. Choose No AI to run deterministic stages only.';updateProvider();return;}if(confirmation.value!=='START SCOPED TESTS'){status.textContent='Type START SCOPED TESTS before execution.';return;}submitting=true;updateProvider();
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
    }catch(e){status.textContent=e.message;}finally{submitting=false;updateProvider();}
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
    const evidence=make('details','',results);make('summary','Technical assessment evidence (JSON)',evidence);
    const pre=make('pre',JSON.stringify(current,null,2),evidence);pre.tabIndex=0;pre.setAttribute('aria-label','Assessment evidence, keyboard-scrollable');
    if(timer)clearTimeout(timer);if(current.status==='running')timer=setTimeout(async()=>{try{current=await(await fetch('/api/assessments/'+current.id)).json();render();}catch(e){status.textContent=e.message;}},1500);
  }
  document.getElementById('nav-assessment').addEventListener('click',async()=>{switchView('assessment');try{await loadProviders();await loadRuns();}catch(e){status.textContent=e.message;}});
  for(const id of ['settings-open-ai','modal-open-ai'])document.getElementById(id)?.addEventListener('click',()=>{document.getElementById('scan-modal').classList.add('hidden');document.getElementById('nav-assessment').click();llm.focus();});
})();
