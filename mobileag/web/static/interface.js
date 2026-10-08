/* Shared UI recovery/accessibility helpers; no target operations or credentials. */
(() => {
  const make=(tag,text,parent)=>{const el=document.createElement(tag);el.textContent=text||'';parent?.append(el);return el;};
  function state(parent,title,message,kind='empty',retry){
    parent.replaceChildren();const box=make('div','',parent);box.className='ui-state';box.dataset.state=kind;
    box.setAttribute('role',kind==='error'?'alert':'status');make('h3',title,box);make('p',message,box);
    if(retry){const button=make('button','Retry',box);button.type='button';button.addEventListener('click',retry);}
    return box;
  }
  function askNotes(){
    if(document.getElementById('triage-notes-dialog'))return Promise.resolve(null);
    return new Promise(resolve=>{
      const previous=document.activeElement,dialog=make('dialog','',document.body);dialog.id='triage-notes-dialog';dialog.className='ui-dialog';dialog.setAttribute('aria-labelledby','triage-notes-title');
      const title=make('h2','Record confirmed reproduction',dialog);title.id='triage-notes-title';
      make('p','Describe attacker prerequisites, reproduced impact and evidence. Static candidates, shell privileges and suggested procedures alone do not establish an ordinary-app exploit. Do not include credentials or real user data.',dialog);
      const form=make('form','',dialog),label=make('label','Validation notes (required)',form),notes=make('textarea','',label);notes.id='triage-validation-notes';notes.required=true;notes.maxLength=10000;notes.rows=6;
      const actions=make('div','',form),cancel=make('button','Cancel',actions),submit=make('button','Save confirmed decision',actions);cancel.type='button';submit.type='submit';let value=null;
      cancel.addEventListener('click',()=>dialog.close());form.addEventListener('submit',event=>{event.preventDefault();if(!notes.value.trim()){notes.setCustomValidity('Describe the actual reproduced impact and evidence.');notes.reportValidity();return;}value=notes.value.trim();dialog.close();});notes.addEventListener('input',()=>notes.setCustomValidity(''));
      dialog.addEventListener('close',()=>{dialog.remove();previous?.focus();resolve(value);},{once:true});dialog.showModal();notes.focus();
    });
  }
  function renderReadiness(result){
    const parent=document.getElementById('readiness-result');parent.replaceChildren();
    make('h3','Local readiness (no target contacted)',parent);const list=make('dl','',parent);list.className='readiness-list';
    for(const [name,value] of [['Offline sandbox',result.sandbox_probe?'Probe passed':'Unavailable — static jobs fail closed'],['JADX',result.android_tools?.jadx?'Installed; parser coverage unverified':'Not installed'],['APKTool',result.android_tools?.apktool?'Installed; parser coverage unverified':'Not installed'],['Worker network',result.web_static_network||'Not observed'],['Device acceptance',result.production_device_validation||'Not performed'],['Deployment',result.multiuser_deployment==='unsupported'?'Single local operator only':'Review deployment limits']]){const item=make('div','',list);make('dt',name,item);make('dd',value,item);}
    const details=make('details','',parent);make('summary','Technical readiness details',details);make('pre',JSON.stringify(result,null,2),details).tabIndex=0;
  }
  window.MobileAgUI={state,askNotes,renderReadiness};
  const menuButton=document.getElementById('workspace-menu-toggle'),navigation=document.getElementById('workspace-navigation'),mobile=matchMedia('(max-width:767px)');
  function setMenu(open){navigation.classList.toggle('navigation-collapsed',!open);menuButton.setAttribute('aria-expanded',String(open));}
  setMenu(!mobile.matches);mobile.addEventListener('change',()=>setMenu(!mobile.matches));
  menuButton.addEventListener('click',()=>setMenu(menuButton.getAttribute('aria-expanded')!=='true'));
  navigation.addEventListener('click',event=>{if(mobile.matches&&event.target.closest('.nav-item')){setMenu(false);document.getElementById('main-workspace').focus();}});
  window.addEventListener('keydown',event=>{if(event.key==='Escape'&&mobile.matches&&menuButton.getAttribute('aria-expanded')==='true'){setMenu(false);menuButton.focus();}});
  const views={overview:['Security Overview','Your application security workspace. Upload, scope and review evidence.'],assessment:['Start Assessment','Upload → exact scope → stages → explicit approval → actual evidence.'],surface:['Attack Surface','Static candidates and observed coverage, not a security certification.'],findings:['Findings & Evidence','Review candidates, suggested procedures and reproduced validation notes.'],scans:['Scan History','Inspect jobs, recover incomplete work and retain original artifacts.'],agents:['Analyzer Capabilities','Available modules are not proof that a particular scan executed them.'],settings:['Configuration','Review server policy, provider setup, session and authorized scope.'],dast:['Device Diagnostics','Explicit dedicated-device actions; ADB permissions are device-wide.'],taint:['Taint Dataflow','Straight-line static heuristics; source-to-sink candidates require validation.'],api:['API Review','Discovered routes are unverified. Replay needs exact server-approved scope.'],automation:['Navigation Review','Observe first; approve exact controls before any input is issued.']};
  function updateView(){const names=views[activeView]||['Workspace',''];document.getElementById('workspace-title').textContent=names[0];document.getElementById('workspace-subtitle').textContent=names[1];document.querySelectorAll('.nav-item').forEach(el=>{if(el.id==='nav-'+activeView)el.setAttribute('aria-current','page');else el.removeAttribute('aria-current');});if(document.getElementById('nav-'+activeView)?.closest('#advanced-tools'))document.getElementById('advanced-tools').open=true;}
  function updateScan(){document.getElementById('export-menu-button').disabled=!currentScan?.scan_id;const summary=document.getElementById('text-surface-summary');if(summary)summary.textContent=currentScan?JSON.stringify({scan_id:currentScan.scan_id,status:currentScan.status,coverage:currentScan.coverage||{},components:currentScan.components||[],deep_links:currentScan.deep_links||[],endpoints:currentScan.api_endpoints||[]},null,2):'No scan selected. Start an authorized assessment.';}
  window.addEventListener('workspace-view-changed',updateView);window.addEventListener('workspace-scan-changed',updateScan);updateView();updateScan();
  document.getElementById('scans-table-body').closest('table').createCaption().textContent='Recorded scan jobs — completion does not imply vulnerability verification.';
  for(const [value,title]of [['LOW','Low'],['INFO','Info']]){const button=make('button',title,document.getElementById('sev-all').parentElement);button.id='sev-'+value.toLowerCase();button.className='sev-btn';button.type='button';button.addEventListener('click',()=>setSeverityFilter(value));}
  for(const id of ['findings-search-input','api-search-input'])document.getElementById(id).type='search';
  const drawer=document.getElementById('copilot-drawer');drawer.hidden=true;drawer.setAttribute('role','region');drawer.setAttribute('aria-label','Local evidence summary');
  document.getElementById('copilot-messages').setAttribute('role','log');
  window.addEventListener('keydown',event=>{if(event.key==='Escape'){const menu=document.getElementById('export-dropdown');if(!menu.classList.contains('hidden')){menu.classList.add('hidden');document.getElementById('export-menu-button').setAttribute('aria-expanded','false');document.getElementById('export-menu-button').focus();}if(copilotOpen)toggleCopilotDrawer();}});
})();
