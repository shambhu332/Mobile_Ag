/* Automatic local preflight only. No target selection, credentials, model calls or job starts. */
(() => {
  const make=(tag,text,parent)=>{const element=document.createElement(tag);element.textContent=text;if(parent)parent.append(element);return element;};
  const panel=make('section','');panel.id='assessment-readiness';panel.className='workflow-panel';panel.setAttribute('aria-labelledby','readiness-title');
  document.querySelector('#view-assessment .assessment-panel').before(panel);
  make('h2','Automatic readiness checklist',panel).id='readiness-title';
  make('p','Checked after connecting and again before Start. Only local sandbox, host ADB inventory and configuration are inspected. No device shell, root, install, hook, target request or model call runs here.',panel);
  const status=make('p','Connect your session to check readiness.',panel);status.id='auto-ready-status';status.setAttribute('role','status');status.setAttribute('aria-live','polite');
  const list=make('ul','',panel);list.id='auto-ready-checklist';
  const actions=make('div','',panel);actions.className='workflow-actions';
  const retry=make('button','Recheck readiness',actions);retry.type='button';
  const configure=make('button','Open configuration',actions);configure.type='button';configure.addEventListener('click',()=>document.getElementById('nav-settings').click());
  const serial=document.getElementById('assessment-serial');const choices=make('datalist','',panel);choices.id='assessment-device-choices';serial.setAttribute('list',choices.id);
  make('p','Device suggestions never select a target. You must choose an exact authorized serial and approve the dedicated-device scope. Missing dependencies block execution; nothing is installed automatically.',panel);
  make('p','After you explicitly select a device, Frida process observation is automatic only if its saved frida_status action is approved. This never starts Frida or attaches hooks.',panel);
  let pending=null,generation=0;
  function clear(){list.replaceChildren();choices.replaceChildren();}
  async function check(){
    if(pending)return pending;
    const current=++generation;retry.disabled=true;status.textContent='Checking local readiness…';clear();
    const task=(async()=>{
      try{
        const data=await(await fetch('/api/preflight')).json();
        if(current!==generation)throw new Error('Session changed; reconnect and recheck readiness.');
        const host=data.host,inventory=data.devices;
        make('li','Isolated offline worker: '+(host.sandbox_probe?'ready':'blocked — Linux bubblewrap and ordinary-user systemd required'),list);
        for(const [name,ready] of Object.entries(host.android_tools))make('li',name+': '+(ready?'present in worker configuration':'missing — configure the trusted worker tool'),list);
        make('li','ADB executable: '+(inventory.adb_available?'available (not device readiness)':'unavailable; DAST blocked'),list);
        const eligible=inventory.devices.filter(device=>device.allowed&&device.status==='device');
        make('li','Device inventory: '+inventory.inventory_state+'; '+eligible.length+' online server-approved; selection remains explicit',list);
        for(const device of eligible)make('option',device.model,choices).value=device.serial;
        make('li','Saved device actions at check time: '+(data.scope.policy?.actions?.join(', ')||'none; static-only until explicit approval'),list);
        const configured=data.providers.providers.filter(provider=>provider.enabled).map(provider=>provider.title);
        make('li','AI configuration: '+(configured.join(', ')||'no provider configured')+'; not a connectivity check; no model contacted',list);
        status.textContent='Checked '+new Date(data.checked_at).toLocaleTimeString()+'. This readiness check did not start tests. Actual assessment execution is shown below.';
        await refreshDastDevices(inventory);
        return data;
      }catch(error){if(current===generation){clear();status.textContent='Readiness unavailable — reconnect or Recheck. '+error.message;}throw error;}
      finally{if(current===generation){pending=null;retry.disabled=false;}}
    })();pending=task;return task;
  }
  retry.addEventListener('click',()=>{check().catch(()=>{});});
  window.MobileAgReady=Object.freeze({check});
  window.addEventListener('dast-device-selected',async event=>{
    const serial=event.detail.serial;
    try{
      const data=await(await fetch('/api/scope')).json();
      if(dastActiveDevice!==serial)return;
      if(data.policy?.devices?.includes(serial)&&data.policy?.actions?.includes('frida_status'))await checkFridaServerStatus();
      else document.getElementById('frida-status-badge').textContent='Frida process not checked — frida_status approval required';
    }catch(error){if(dastActiveDevice===serial)document.getElementById('frida-status-badge').textContent='Frida status unknown — reconnect or retry';}
  });
  window.addEventListener('workspace-session-connected',()=>{check().catch(()=>{});window.dispatchEvent(new Event('assessment-refresh-providers'));});
  window.addEventListener('workspace-session-invalidated',()=>{generation++;pending=null;retry.disabled=false;clear();status.textContent='Session disconnected — readiness invalidated. Reconnect to recheck.';});
})();
