/* MobileAg session-actions.js — ordered local classic-script module; shared workspace state is in workspace.js. */

    // Token stays in page memory, never in a URL, cookie, localStorage or report.
    let accessToken = '';
    const nativeFetch = window.fetch.bind(window);
    let resolveConnection;
    let connectedBefore=false;
    const connectionReady = new Promise(resolve => {resolveConnection=resolve;});
    function showConnectionForm() {
      let dialog = document.getElementById('session-connect');
      if (!dialog) {
        dialog = document.createElement('dialog');dialog.id='session-connect';dialog.className='workflow-panel';dialog.setAttribute('aria-labelledby','session-title');
        const heading=document.createElement('h2');heading.id='session-title';heading.textContent='Connect to your local workbench';dialog.append(heading);
        const text=document.createElement('p');text.textContent='Use the session token displayed in your server terminal. It stays in page memory only. Sessions expire after eight hours.';dialog.append(text);
        const help=document.createElement('details');const summary=document.createElement('summary');summary.textContent='What token is this?';help.append(summary);
        const guide=document.createElement('p');guide.textContent='This is the workbench access key, not your GitHub password, mobile-app login, or AI API key. In the terminal running this server, copy the value after “Session access token (paste into dashboard):”. If MOBILEAG_API_TOKEN is configured, use that configured value. Do not share it. A server restart usually changes the key and stops active jobs.';help.append(guide);dialog.append(help);
        const form=document.createElement('form');const label=document.createElement('label');label.textContent='Session token';
        const input=document.createElement('input');input.type='password';input.id='session-token';input.required=true;input.autocomplete='off';label.append(input);form.append(label);
        const error=document.createElement('p');error.setAttribute('role','alert');form.append(error);
        const submit=document.createElement('button');submit.textContent='Connect';submit.type='submit';form.append(submit);
        form.addEventListener('submit',async(event)=>{event.preventDefault();submit.disabled=true;try{
          const result=await nativeFetch('/api/status',{headers:{Authorization:'Bearer '+input.value}});
          if(!result.ok)throw new Error('Token invalid or expired. Check the server terminal.');
          accessToken=input.value;input.value='';dialog.close();
          if(connectedBefore){await loadInitialScan();await loadPrivacyPolicy();if(wsConnection)wsConnection.close();connectTelemetryWebSocket();}
          else{connectedBefore=true;resolveConnection();}
          window.dispatchEvent(new Event('workspace-session-connected'));
        }catch(e){error.textContent=e.message;}finally{submit.disabled=false;}});
        dialog.append(form);document.body.append(dialog);
      }
      if (!dialog.open) dialog.showModal();
      dialog.querySelector('input').focus();
    }
    window.fetch = async function(input, options = {}) {
      const url = new URL(typeof input === 'string' ? input : input.url, window.location.href);
      const headers = new Headers(options.headers || {});
      if (url.origin === window.location.origin && url.pathname.startsWith('/api/')) {
        headers.set('Authorization', 'Bearer ' + accessToken);
      }
      const response = await nativeFetch(input, {...options, headers});
      if (!response.ok) {
        const body = await response.clone().json().catch(() => ({}));
        if(response.status===401){accessToken='';window.dispatchEvent(new Event('workspace-session-invalidated'));showConnectionForm();}
        const error=new Error(body.detail || `Request failed (${response.status})`);error.status=response.status;throw error;
      }
      return response;
    };

    // Callback registry: HTML only contains opaque IDs, never executable payloads.
    const actionCallbacks = new Map();
    let actionSequence = 0;
    let cleanupQueued = false;
    function bindAction(type, callback) {
      const id = 'dynamic' + (++actionSequence);
      actionCallbacks.set(id, callback);
      if (!cleanupQueued) {
        cleanupQueued = true;
        queueMicrotask(() => {
          cleanupQueued = false;
          const used = new Set();
          document.querySelectorAll('[data-onclick],[data-onchange],[data-oninput],[data-onkeydown],[data-ondrop],[data-ondragover]').forEach(el => {
            for (const attr of el.attributes) if (attr.name.startsWith('data-on')) used.add(attr.value);
          });
          for (const key of actionCallbacks.keys()) if (key.startsWith('dynamic') && !used.has(key)) actionCallbacks.delete(key);
        });
      }
      return 'data-on' + type + '="' + id + '"';
    }
    actionCallbacks.set('static-dragleave', function(event) { handleDragLeave(event); });
    actionCallbacks.set('static-reconnect', function() { showConnectionForm(); });
    actionCallbacks.set('static0', function(event) { switchView('surface'); });
    actionCallbacks.set('static1', function(event) { switchView('findings'); });
    actionCallbacks.set('static2', function(event) { switchView('dast'); });
    actionCallbacks.set('static3', function(event) { switchView('taint'); });
    actionCallbacks.set('static4', function(event) { switchView('api'); });
    actionCallbacks.set('static5', function(event) { switchView('scans'); });
    actionCallbacks.set('static6', function(event) { switchView('agents'); });
    actionCallbacks.set('static7', function(event) { switchView('settings'); });
    actionCallbacks.set('static8', function(event) { selectDastDevice(this.value); });
    actionCallbacks.set('static9', function(event) { deployFridaScriptQuick('root_bypass'); });
    actionCallbacks.set('static10', function(event) { deployFridaScriptQuick('unpinning'); });
    actionCallbacks.set('static11', function(event) { openNewScanModal(); });
    actionCallbacks.set('static12', function(event) { toggleExportMenu(); });
    actionCallbacks.set('static13', function(event) { exportReportJSON(); });
    actionCallbacks.set('static14', function(event) { exportReportMarkdown(); });
    actionCallbacks.set('static15', function(event) { exportReportSARIF(); });
    actionCallbacks.set('static16', function(event) { toggleCopilotDrawer(); });
    actionCallbacks.set('static17', function(event) { handleDragOver(event); });
    actionCallbacks.set('static18', function(event) { handleDrop(event, true); });
    actionCallbacks.set('static19', function(event) { triggerQuickUpload(); });
    actionCallbacks.set('static20', function(event) { handleQuickFileInput(event); });
    actionCallbacks.set('static21', function(event) { graphFit(); });
    actionCallbacks.set('static22', function(event) { graphZoomIn(); });
    actionCallbacks.set('static23', function(event) { graphZoomOut(); });
    actionCallbacks.set('static24', function(event) { applyFindingsFilter(); });
    actionCallbacks.set('static25', function(event) { setSeverityFilter('ALL'); });
    actionCallbacks.set('static26', function(event) { setSeverityFilter('CRITICAL'); });
    actionCallbacks.set('static27', function(event) { setSeverityFilter('HIGH'); });
    actionCallbacks.set('static28', function(event) { setSeverityFilter('MEDIUM'); });
    actionCallbacks.set('static29', function(event) { applyFindingsFilter(); });
    actionCallbacks.set('static30', function(event) { openNewScanModal(); });
    actionCallbacks.set('static31', function(event) { handleDragOver(event); });
    actionCallbacks.set('static32', function(event) { handleDrop(event, true); });
    actionCallbacks.set('static33', function(event) { triggerQuickUpload(); });
    actionCallbacks.set('static34', function(event) { triggerAllAgents(); });
    actionCallbacks.set('static35', function(event) { saveSettingsForm(); });
    actionCallbacks.set('static36', function(event) { connectDastDevice(); });
    actionCallbacks.set('static37', function(event) { refreshDastDevices(); });
    actionCallbacks.set('static38', function(event) { restartDastRoot(); });
    actionCallbacks.set('static39', function(event) { launchDastActivity(); });
    actionCallbacks.set('static40', function(event) { dispatchDastDeeplink(); });
    actionCallbacks.set('static41', function(event) { auditDastDeepLinks(); });
    actionCallbacks.set('static42', function(event) { installDastApk(); });
    actionCallbacks.set('static43', function(event) { auditDastProviders(); });
    actionCallbacks.set('static44', function(event) { auditDastMemory(); });
    actionCallbacks.set('static45', function(event) { auditDastStorage(); });
    actionCallbacks.set('static46', function(event) { crawlDastUI(); });
    actionCallbacks.set('static47', function(event) { runDastFuzzSuite(); });
    actionCallbacks.set('static48', function(event) { checkFridaServerStatus(); });
    actionCallbacks.set('static49', function(event) { deployFridaScript('unpinning'); });
    actionCallbacks.set('static50', function(event) { previewFridaScript('unpinning'); });
    actionCallbacks.set('static51', function(event) { deployFridaScript('crypto'); });
    actionCallbacks.set('static52', function(event) { previewFridaScript('crypto'); });
    actionCallbacks.set('static53', function(event) { deployFridaScript('root_bypass'); });
    actionCallbacks.set('static54', function(event) { previewFridaScript('root_bypass'); });
    actionCallbacks.set('static55', function(event) { copyFridaScript(); });
    actionCallbacks.set('static56', function(event) { document.getElementById('frida-script-preview-panel').classList.add('hidden'); });
    actionCallbacks.set('static57', function(event) { filterDastTerminalLogs(); });
    actionCallbacks.set('static58', function(event) { fetchDastLogcat(); });
    actionCallbacks.set('static59', function(event) { clearDastLogcat(); });
    actionCallbacks.set('static60', function(event) { captureDastScreenshot(); });
    actionCallbacks.set('static61', function(event) { loadSelectedTaintSample(); });
    actionCallbacks.set('static62', function(event) { runTaintAnalysis(); });
    actionCallbacks.set('static63', function(event) { filterApiEndpoints(); });
    actionCallbacks.set('static64', function(event) { setApiMethodFilter('ALL'); });
    actionCallbacks.set('static65', function(event) { setApiMethodFilter('GET'); });
    actionCallbacks.set('static66', function(event) { setApiMethodFilter('POST'); });
    actionCallbacks.set('static67', function(event) { setApiMethodFilter('DELETE'); });
    actionCallbacks.set('static68', function(event) { filterApiEndpoints(); });
    actionCallbacks.set('static69', function(event) { fuzzAllApiEndpoints(); });
    actionCallbacks.set('static70', function(event) { toggleCopilotDrawer(); });
    actionCallbacks.set('static71', function(event) { askCopilotActivePoc(); });
    actionCallbacks.set('static72', function(event) { askCopilotActiveAdb(); });
    actionCallbacks.set('static73', function(event) { askCopilotActiveFrida(); });
    actionCallbacks.set('static74', function(event) { askCopilotActiveFix(); });
    actionCallbacks.set('static75', function(event) { askCopilotBountyReport(); });
    actionCallbacks.set('static76', function(event) { if(event.key==='Enter') sendCopilotChat(); });
    actionCallbacks.set('static77', function(event) { sendCopilotChat(); });
    actionCallbacks.set('static78', function(event) { closeNewScanModal(); });
    actionCallbacks.set('static79', function(event) { handleDragOver(event); });
    actionCallbacks.set('static80', function(event) { handleDrop(event, false); });
    actionCallbacks.set('static81', function(event) { triggerModalUpload(); });
    actionCallbacks.set('static82', function(event) { handleModalFileInput(event); });
    actionCallbacks.set('static83', function(event) { closeNewScanModal(); });
    actionCallbacks.set('static84', function(event) { submitNewScan(); });
    actionCallbacks.set('static85', function(event) { switchFindingSubTab('poc'); });
    actionCallbacks.set('static86', function(event) { switchFindingSubTab('adb'); });
    actionCallbacks.set('static87', function(event) { switchFindingSubTab('frida'); });
    actionCallbacks.set('static88', function(event) { switchFindingSubTab('proof'); });
    actionCallbacks.set('static89', function(event) { switchFindingSubTab('ast'); });
    actionCallbacks.set('static90', function(event) { switchFindingSubTab('fix'); });
    actionCallbacks.set('static91', function(event) { document.getElementById('poc-adb-terminal').innerHTML=''; });
    actionCallbacks.set('static92', function(event) { deployFridaFromPoc('unified'); });
    actionCallbacks.set('static93', function(event) { connectDastDevice(); });
    actionCallbacks.set('static94', function(event) { switchApiSubTab('owasp'); });
    actionCallbacks.set('static95', function(event) { switchApiSubTab('request'); });
    actionCallbacks.set('static96', function(event) { switchApiSubTab('response'); });
    actionCallbacks.set('static97', function(event) { switchApiSubTab('remediation'); });
    actionCallbacks.set('static98', function(event) { toggleExportMenu(); });
    for (const type of ['click', 'change', 'input', 'keydown', 'drop', 'dragover', 'dragleave']) {
      document.addEventListener(type, event => {
        const el = event.target.closest?.('[data-on' + type + ']');
        const callback = el && actionCallbacks.get(el.getAttribute('data-on' + type));
        if (callback) {
          try { Promise.resolve(callback.call(el, event)).catch(error => showToast(String(error.message), 'error')); }
          catch (error) { showToast(String(error.message), 'error'); }
        }
      });
    }
