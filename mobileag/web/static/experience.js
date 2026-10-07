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

})();
