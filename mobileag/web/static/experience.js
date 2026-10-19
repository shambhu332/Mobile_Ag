/* Navigation and configuration UX only. Never execute scans, tools, or model calls. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);el.textContent=text||'';parent?.append(el);return el;};
  const button=(text,parent,run)=>{const el=make('button',text,parent);el.type='button';el.addEventListener('click',run);return el;};
  const views={
    assessment:['Start Assessment','Upload an owned APK, narrow scope, choose stages and explicitly approve execution.','upload apk scope start',['settings','scans']],
    surface:['Attack Surface','Inspect observed static coverage. Components, symbols and routes are candidates, not exploit proof.','graph manifest components coverage',['findings','taint']],
    findings:['Findings & Evidence','Filter candidates, compare source/sink evidence and record actual reproduced prerequisites and impact.','triage evidence candidates reproduction',['surface','api']],
    scans:['Scan History','Open a recorded job; inspect incomplete stages before retrying. Original artifacts remain preserved.','jobs history incomplete retry',['assessment','settings']],
    settings:['Configuration','Inspect provider setup, authorized scope and local readiness. Saving preferences never authorizes model or device egress.','settings llm provider gemini grok gpt hermes local scope readiness',['assessment','agents']],
    dast:['Device Diagnostics','Select an explicitly authorized dedicated device. Shell/root diagnostics are not ordinary-app exploit proof.','adb emulator device diagnostic',['settings','automation']],
    taint:['Taint Dataflow','Review static source-to-sink candidates. Straight-line heuristics are not full interprocedural analysis.','source sink trace dataflow',['findings','surface']],
    api:['API Review','Review observed, redacted captures. Replay needs exact server-approved origins/methods; discovered URLs are not scope.','endpoint capture response replay',['settings','findings']],
    automation:['Navigation Review','Observe approved app screens, then review exact controls before approving input actions.','dast screen navigate action approval',['dast','settings']],
    agents:['Analyzer Capabilities','Check what modules exist; consult the selected job to see which actually ran.','analyzer module engine capability',['settings','scans']]
  };
  function navigate(id){document.getElementById('nav-'+id)?.click();document.getElementById('workspace-title').focus();}
  const context=document.querySelector('.workspace-context');
  const toolbar=make('section','');toolbar.id='workspace-tools';toolbar.setAttribute('aria-label','Workspace navigation and layout');context.after(toolbar);
  const searchButton=button('Find a section · Ctrl/⌘ K',toolbar,openCommands);searchButton.id='workspace-command-open';searchButton.setAttribute('aria-haspopup','dialog');searchButton.setAttribute('aria-controls','workspace-command-dialog');
  const densityLabel=make('label','Layout density',toolbar),density=make('select','',densityLabel);density.id='workspace-density';
  for(const [value,title] of [['comfortable','Comfortable'],['compact','Compact']])make('option',title,density).value=value;
  density.addEventListener('change',()=>{document.body.dataset.density=density.value;});
  const focusButton=button('Focus layout (desktop)',toolbar,()=>{const on=document.body.classList.toggle('workspace-focus');focusButton.setAttribute('aria-pressed',String(on));});focusButton.id='workspace-focus-toggle';focusButton.setAttribute('aria-pressed','false');
  const guide=make('details','',toolbar);guide.id='workspace-guide';const guideSummary=make('summary','Next steps',guide),guideBody=make('div','',guide);
  function updateGuide(){
    guideSummary.textContent='Next steps · '+(views[activeView]?.[0]||'Workspace');guideBody.replaceChildren();
    const spec=views[activeView]||views.assessment;make('p',spec[1],guideBody);
    const job=make('p',currentScan?.scan_id?'Selected job: '+currentScan.scan_id+' · '+(currentScan.status||'status not recorded')+' · '+(Array.isArray(currentScan.findings)?currentScan.findings.length:0)+' recorded candidates. Confirmation requires reproduction evidence.':'No job selected. Begin with an authorized artifact; no results are implied.',guideBody);job.id='workspace-guide-job';
    const links=make('div','',guideBody);links.className='experience-actions';
    const next=!currentScan?.scan_id&&activeView!=='assessment'?['assessment','settings']:spec[3];
    for(const id of [...new Set(next)])button('Open '+views[id][0],links,()=>navigate(id));
    make('p','Shortcuts: Ctrl/⌘ K opens section search; / also opens search outside text fields. Escape closes it. Layout choices last for this page only.',guideBody);
  }
  window.addEventListener('workspace-view-changed',updateGuide);window.addEventListener('workspace-scan-changed',updateGuide);updateGuide();
  const dialog=make('dialog','',document.body);dialog.id='workspace-command-dialog';dialog.className='ui-dialog command-dialog';dialog.setAttribute('aria-labelledby','workspace-command-title');
  make('h2','Navigate the workspace',dialog).id='workspace-command-title';
  make('p','Navigation only: opening a section never starts an assessment, provider review, replay or device input.',dialog);
  const label=make('label','Search sections or workflows',dialog),search=make('input','',label);search.type='search';search.id='workspace-command-search';search.maxLength=100;search.autocomplete='off';
  const commandStatus=make('p','',dialog);commandStatus.id='workspace-command-status';commandStatus.setAttribute('role','status');commandStatus.setAttribute('aria-live','polite');
  const results=make('ul','',dialog);results.id='workspace-command-results';results.setAttribute('aria-label','Matching sections');
  button('Close section search',dialog,()=>dialog.close());let previousFocus=null,chosen=false;
  function renderCommands(){
    results.replaceChildren();const q=search.value.trim().toLowerCase();
    const matches=Object.entries(views).filter(([,v])=>[v[0],v[1],v[2]].join(' ').toLowerCase().includes(q));
    commandStatus.textContent=matches.length?matches.length+' matching sections. Arrow Down moves to results; Enter opens the first match.':'No matching sections. Try scope, findings, APK, provider or history.';
    for(const [id,spec] of matches){const item=make('li','',results),b=button('',item,()=>{chosen=true;dialog.close();navigate(id);});b.dataset.section=id;make('strong',spec[0],b);make('span',spec[1],b);}
  }
  function openCommands(){
    if(dialog.open){search.focus();return;}
    if(document.querySelector('dialog[open]')||!document.getElementById('scan-modal').classList.contains('hidden'))return;
    previousFocus=document.activeElement;chosen=false;search.value='';renderCommands();dialog.showModal();search.focus();
  }
  search.addEventListener('input',renderCommands);
  search.addEventListener('keydown',event=>{if(event.key==='ArrowDown'){event.preventDefault();results.querySelector('button')?.focus();}if(event.key==='Enter'){event.preventDefault();results.querySelector('button')?.click();}});
  results.addEventListener('keydown',event=>{if(!['ArrowDown','ArrowUp','Home','End'].includes(event.key))return;event.preventDefault();const buttons=[...results.querySelectorAll('button')],index=buttons.indexOf(document.activeElement);if(!buttons.length)return;buttons[event.key==='Home'?0:event.key==='End'?buttons.length-1:(index+(event.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length].focus();});
  dialog.addEventListener('keydown',event=>{if(event.key==='Escape'){event.preventDefault();event.stopPropagation();dialog.close();}});
  dialog.addEventListener('close',()=>{if(!chosen)previousFocus?.focus();});
  window.addEventListener('keydown',event=>{const editing=event.target.closest?.('input,textarea,select,[contenteditable="true"]');if(!event.repeat&&!event.altKey&&((event.key.toLowerCase()==='k'&&(event.ctrlKey||event.metaKey))||(event.key==='/'&&!editing&&!event.ctrlKey&&!event.metaKey))){if(document.querySelector('dialog[open]:not(#workspace-command-dialog)'))return;event.preventDefault();openCommands();}});

  // Provider explorer consumes only the authenticated, public catalog snapshot.
  const providerRoot=document.getElementById('configuration-llm-controls'),explorer=make('section','');explorer.id='provider-explorer';explorer.setAttribute('aria-labelledby','provider-explorer-title');providerRoot.before(explorer);
  make('h3','Provider workspace',explorer).id='provider-explorer-title';
  make('p','Compare local and cloud integrations. Configured means server settings exist—not model health, quota, availability or permission to execute.',explorer);
  const catalogStatus=make('p','Catalog not loaded. Open Configuration or Refresh providers.',explorer);catalogStatus.id='provider-explorer-status';catalogStatus.setAttribute('role','status');catalogStatus.setAttribute('aria-live','polite');
  const filters=make('div','',explorer);filters.className='provider-filters';
  const queryLabel=make('label','Find a provider or model',filters),query=make('input','',queryLabel);query.id='provider-search';query.type='search';query.maxLength=100;query.autocomplete='off';
  const filterLabel=make('label','Filter integrations',filters),filter=make('select','',filterLabel);filter.id='provider-filter';
  for(const [value,title] of [['all','All integrations'],['configured','Configured'],['setup','Setup required'],['local','Local only'],['cloud','Cloud only']])make('option',title,filter).value=value;
  const grid=make('div','',explorer);grid.id='provider-grid';grid.className='provider-grid';
  const review=make('section','',explorer);review.id='provider-routing-review';review.setAttribute('aria-labelledby','provider-routing-title');
  const limitsPanel=make('details','',explorer);make('summary','Broker limits and usage boundaries',limitsPanel);const limitsBody=make('div','',limitsPanel);limitsBody.id='provider-limits';
  let snapshot={providers:[],loaded:false,limits:null,primary:'',secondary:'',primaryConsent:false,secondaryConsent:false};
  function chooseProvider(role,id){const selector=document.getElementById('assessment-'+(role==='primary'?'provider':'secondary'));selector.value=id;selector.dispatchEvent(new Event('change',{bubbles:true}));selector.focus();}
  function renderProviders(){
    const {providers,loaded,primary,secondary}=snapshot;const q=query.value.trim().toLowerCase();grid.replaceChildren();
    if(!loaded){catalogStatus.textContent='Catalog unavailable/loading. Refresh in Configuration; stale configuration cannot authorize AI.';make('p','Provider cards are unavailable until the current catalog loads.',grid);return;}
    const matches=providers.filter(p=>[p.id,p.title,p.model].join(' ').toLowerCase().includes(q)&&({all:true,configured:p.enabled,setup:!p.enabled,local:p.local,cloud:!p.local}[filter.value]));
    catalogStatus.textContent=matches.length+' of '+providers.length+' integrations shown · '+providers.filter(p=>p.enabled).length+' configured · no connectivity checks performed.';
    if(!matches.length)make('p','No matching integrations. Clear the search or choose All integrations.',grid);
    for(const p of matches){
      const card=make('article','',grid);card.className='provider-card';card.dataset.provider=p.id;card.dataset.configured=String(p.enabled);
      make('h4',p.title,card);const badges=make('div','',card);badges.className='provider-badges';make('span',p.local?'Local / loopback':'Cloud egress',badges);make('span',p.enabled?'Configured':'Setup required',badges);
      if(primary===p.id)make('span','Primary selection',badges);if(secondary===p.id)make('span','Secondary selection',badges);
      make('p','Model: '+(p.model||'not configured'),card);make('p',p.enabled?'Configuration present; live model health is unknown.':p.reason||'Server setup required.',card);
      const actions=make('div','',card);actions.className='experience-actions';
      button('Set primary: '+p.title,actions,()=>chooseProvider('primary',p.id));
      const secondaryButton=button('Set secondary: '+p.title,actions,()=>chooseProvider('secondary',p.id));secondaryButton.disabled=!primary||primary===p.id;
      if(!primary||primary===p.id)secondaryButton.title='Choose a different primary first; primary and secondary must be distinct.';
    }
  }
  function renderReview(){
    review.replaceChildren();make('h3','Routing and approval checklist',review).id='provider-routing-title';
    const pair=make('div','',review);pair.className='provider-comparison';
    for(const [role,id] of [['Primary',snapshot.primary],['Secondary',snapshot.secondary]]){const p=snapshot.providers.find(p=>p.id===id),card=make('div','',pair);make('h4',role,card);make('p',p?p.title:role==='Primary'?'No AI selected':'No fallback selected',card);make('p',p?'Model: '+(p.model||'not configured')+' · '+(p.local?'loopback destination':'cloud processor'):'No destination for this role.',card);}
    const primary=snapshot.providers.find(p=>p.id===snapshot.primary),secondary=snapshot.providers.find(p=>p.id===snapshot.secondary),hasPrimary=Boolean(snapshot.primary),hasSecondary=Boolean(snapshot.secondary);
    const checks=make('ul','',review);checks.id='provider-approval-checklist';
    const rows=[['Current server catalog',snapshot.loaded?'Loaded; no provider contacted':'Unavailable — selected AI blocked',snapshot.loaded],['Primary configuration',!hasPrimary?'AI not selected':primary?.enabled?'Configured; not a health check':'Setup required — execution blocked',!hasPrimary||Boolean(snapshot.loaded&&primary?.enabled)],['Secondary configuration',!hasSecondary?'Not selected; stop on primary rate limit':snapshot.secondary===snapshot.primary?'Invalid duplicate provider — blocked':secondary?.enabled?'Configured; HTTP 429 only':'Setup required — execution blocked',!hasSecondary||Boolean(snapshot.loaded&&secondary?.enabled&&snapshot.secondary!==snapshot.primary)],['Primary egress approval',!hasPrimary?'Not needed for deterministic stages':snapshot.primaryConsent?'Approved for the current assessment selection':'Pending in Start Assessment',!hasPrimary||snapshot.primaryConsent],['Secondary egress approval',!hasSecondary?'Not needed without secondary':snapshot.secondaryConsent?'Separately approved for the current selection':'Pending in Start Assessment',!hasSecondary||snapshot.secondaryConsent]];
    for(const [title,text,ok] of rows){const item=make('li','',checks);item.dataset.ready=String(ok);make('strong',title,item);make('span',text,item);}
    make('p','Only Start Assessment can approve scope and begin work. Changing a provider clears the relevant consent. No permanent switch, retries, tertiary providers or automatic device actions.',review);
    limitsBody.replaceChildren();const l=snapshot.loaded?snapshot.limits:null;
    make('p',l?'Requests per AI review: at most '+(hasPrimary?(hasSecondary?l.max_attempts:1):0)+'. Requested output ceiling: '+l.output_token_limit+' tokens per attempt. Outer request timeout: '+l.request_timeout_seconds+'s; HTTP transport timeout: '+l.transport_timeout_seconds+'s.':'Load the current server catalog to see broker limits.',limitsBody);
    make('p','Actual token usage, billing, account quota and tokens/minute are not measured here. These are configured ceilings, not consumed-token estimates. Each provider may bill separately. Raw APK/source/findings/URLs never leave this broker; aggregate counts/status only.',limitsBody);
  }
  query.addEventListener('input',renderProviders);filter.addEventListener('change',renderProviders);
  window.addEventListener('llm-configuration-changed',event=>{snapshot=event.detail;renderProviders();renderReview();});
  window.dispatchEvent(new Event('llm-configuration-request'));
})();
