/* Local-only workflow extensions. Browser session credentials stay HttpOnly. */
(() => {
  const make = (tag, text, parent) => { const node=document.createElement(tag); if(text) node.textContent=text; if(parent) parent.append(node); return node; };
  const button = (text,parent,run) => { const b=make('button',text,parent); b.type='button'; b.addEventListener('click',async()=>{ b.disabled=true; try {await run();} catch(e){notice(e.message,true);} finally {b.disabled=false;} });return b; };
  const status=make('p','',document.body); status.id='workflow-status'; status.setAttribute('role','status'); status.setAttribute('aria-live','polite');
  function notice(text,error=false){status.textContent=text;status.classList.toggle('error',error);}
  const settings=document.getElementById('view-settings');
  const panel=make('section','',settings); panel.className='workflow-panel';
  make('h2','Session and authorized scope',panel);
  make('p','Scope is enforced by the server. UI allowlists can only narrow environment permissions. Root, shell, install and Frida approvals are device-wide, not package-isolated. Web static jobs always run offline.',panel);
  const actions=make('div','',panel); actions.className='workflow-actions';
  make('p','The dashboard session is managed automatically by the local browser and is not displayed as a bearer token.',actions);
  const form=make('form','',panel);const fields={};
  for(const name of ['devices','packages','origins','methods','actions']){
    const label=make('label',name+' (comma-separated exact values)',form);const input=make('input','',label);input.id='scope-'+name;input.name=name;fields[name]=input;
  }
  const readiness=make('section','',panel);readiness.id='readiness-result';readiness.setAttribute('aria-live','polite');
  button('Check local readiness',actions,async()=>{const result=await(await fetch('/api/readiness')).json();window.MobileAgUI.renderReadiness(result);notice('Readiness checked without contacting a device, model or target.');});
  const help=make('p','Actions: connect, root, install, launch, deeplink, execute_adb, logcat, screenshot, storage, providers, deeplinks, memory, crawl, frida_status (read-only device-wide process observation), fuzz, automation_observe, automation_execute. Frida hooks and bypasses are disabled. Device log clearing is disabled to preserve evidence. Automation input is device-wide; only dedicated devices. Empty scope disables execution.',form);help.id='scope-help';
  Object.values(fields).forEach(input=>input.setAttribute('aria-describedby','scope-help'));
  const save=make('button','Save authorized scope',form);save.type='submit';
  form.addEventListener('submit',async(event)=>{event.preventDefault();save.disabled=true;try{
    const value=Object.fromEntries(Object.entries(fields).map(([k,v])=>[k,v.value.split(',').map(s=>s.trim()).filter(Boolean)]));
    await fetch('/api/scope',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(value)});notice('Scope saved and enforced server-side.');
  }catch(e){notice(e.message,true);}finally{save.disabled=false;}});
  button('Load saved scope and server limits',actions,async()=>{const result=await (await fetch('/api/scope')).json();for(const [key,input]of Object.entries(fields))input.value=(result.policy?.[key]||[]).join(', ');notice('Server ceilings: devices '+(result.ceilings.devices.join(', ')||'none')+'; origins '+(result.ceilings.origins.join(', ')||'none'));});
  const jobs=make('section','',document.getElementById('view-scans'));jobs.className='workflow-panel';make('h2','Job recovery and evidence retention',jobs);
  const label=make('label','Scan ID',jobs);const sid=make('input','',label);sid.id='job-scan-id';
  const controls=make('div','',jobs);controls.className='workflow-actions';
  button('Cancel active scan',controls,async()=>{await fetch('/api/scans/'+encodeURIComponent(sid.value)+'/cancel',{method:'POST'});notice('Cancellation requested; refresh history to confirm final status.');});
  button('Retry incomplete scan',controls,async()=>{const result=await(await fetch('/api/scans/'+encodeURIComponent(sid.value)+'/retry',{method:'POST'})).json();notice('New job: '+result.scan_id);await loadScansView();});
  const preview=make('pre','',jobs);preview.setAttribute('aria-live','polite');preview.tabIndex=0;let pending=null;sid.addEventListener('input',()=>{pending=null;preview.textContent='Scan ID changed. Preview again before deleting evidence.';});
  button('Preview evidence deletion',controls,async()=>{pending=await(await fetch('/api/scans/'+encodeURIComponent(sid.value)+'/retention')).json();preview.textContent=JSON.stringify(pending,null,2);});
  const confirmLabel=make('label','Type the exact previewed scan ID to delete its outputs and decisions',jobs);const confirmation=make('input','',confirmLabel);confirmation.autocomplete='off';
  button('Delete previewed evidence',controls,async()=>{if(!pending||!pending.allowed||confirmation.value!==pending.scan_id)throw new Error('Preview an inactive scan and type its exact ID first.');await fetch('/api/scans/'+encodeURIComponent(pending.scan_id)+'/purge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation:confirmation.value,revision:pending.revision})});if(currentScan?.scan_id===pending.scan_id){currentScan=null;renderDashboard({stats:{},findings:[]});document.getElementById('detail-content').textContent='Evidence deleted.';document.getElementById('text-surface-summary').textContent='No scan selected.';}pending=null;preview.textContent='Evidence deleted. Uploaded original preserved.';await loadScansView();});
  // Existing controls receive semantic labels from their adjacent text or placeholders.
  document.querySelectorAll('input,select,textarea').forEach(el=>{if(!el.labels?.length&&!el.getAttribute('aria-label'))el.setAttribute('aria-label',el.placeholder||el.id||el.name||'Input');});
  document.querySelectorAll('button').forEach(el=>{if(!el.textContent.trim()&&!el.getAttribute('aria-label'))el.setAttribute('aria-label',el.title||el.querySelector('[data-lucide]')?.getAttribute('data-lucide')||'Action');});
  document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>{document.querySelectorAll('.nav-item').forEach(n=>n.removeAttribute('aria-current'));el.setAttribute('aria-current','page');}));
})();
(() => {
  const surface=document.getElementById('view-surface');
  const section=document.createElement('section');section.className='workflow-panel';
  const title=document.createElement('h2');title.textContent='Attack surface — text alternative';section.append(title);
  const refresh=document.createElement('button');refresh.type='button';refresh.textContent='Refresh text attack surface';section.append(refresh);
  const summary=document.createElement('pre');summary.id='text-surface-summary';summary.setAttribute('aria-live','polite');section.append(summary);surface.append(section);
  refresh.addEventListener('click',()=>{summary.textContent=currentScan?JSON.stringify({scan_id:currentScan.scan_id,status:currentScan.status,coverage:currentScan.coverage||{},components:currentScan.components||[],deep_links:currentScan.deep_links||[],endpoints:currentScan.api_endpoints||[]},null,2):'No scan selected. Upload an authorized APK or IPA.';});
  const modal=document.getElementById('scan-modal');modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.setAttribute('aria-label','New offline static analysis');let previous=null;
  new MutationObserver(()=>{if(!modal.classList.contains('hidden')){previous=document.activeElement;modal.querySelector('button,input')?.focus();}else previous?.focus();}).observe(modal,{attributes:true,attributeFilter:['class']});
  modal.addEventListener('keydown',event=>{if(event.key==='Escape'){closeNewScanModal();return;}if(event.key!=='Tab')return;const controls=[...modal.querySelectorAll('button,input,select,textarea')].filter(el=>!el.disabled&&el.offsetParent!==null);if(!controls.length)return;if(event.shiftKey&&document.activeElement===controls[0]){event.preventDefault();controls.at(-1).focus();}else if(!event.shiftKey&&document.activeElement===controls.at(-1)){event.preventDefault();controls[0].focus();}});
})();

(() => {
  const labelControls=()=>document.querySelectorAll('input,textarea,select').forEach(el=>{if(!el.labels?.length&&!el.hasAttribute('aria-label'))el.setAttribute('aria-label',el.placeholder||el.name||el.id||'Input');});
  new MutationObserver(labelControls).observe(document.getElementById('main-workspace'),{childList:true,subtree:true});
})();
