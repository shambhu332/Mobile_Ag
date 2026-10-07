/* MobileAg dast.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    // DAST & Emulator Live Orchestration Logic
    // =========================================================================
    let dastActiveDevice = null;
    let dastDevices = [];
    let dastFindings = [];
    let dastRawLogs = [];

    async function loadDastView() {
      if (currentScan && currentScan.package_name) {
        const pkgInput = document.getElementById('dast-input-package');
        if (pkgInput && (!pkgInput.value || pkgInput.value === 'com.target.mobile.app')) {
          pkgInput.value = currentScan.package_name;
        }
      }
      await refreshDastDevices();
      renderDastFindings();
    }

    async function refreshDastDevices(inventory = null) {
      try {
        const data = inventory || await (await fetch('/api/dast/devices')).json();
        if (data.inventory_state === 'unknown') throw new Error('Inventory unavailable');
        dastDevices = data.devices || [];
        if (!dastDevices.some(d => d.serial === dastActiveDevice && d.allowed && d.status === 'device')) dastActiveDevice = null;

        // Update badge and indicator
        const badge = document.getElementById('nav-dast-device-badge');
        if (badge) badge.textContent = `${dastDevices.length} Devs`;

        const fleetCount = document.getElementById('dast-fleet-count');
        if (fleetCount) fleetCount.textContent = `${dastDevices.filter(d => d.status === 'device').length} Online / ${dastDevices.length} Listed`;

        const adbIndicator = document.getElementById('dast-adb-indicator');
        if (adbIndicator) {
          if (data.adb_available) {
            adbIndicator.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950/60 border border-emerald-800 text-emerald-400 flex items-center gap-1.5';
            adbIndicator.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> ADB executable available';
          } else {
            adbIndicator.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-950/60 border border-amber-800 text-amber-400 flex items-center gap-1.5';
            adbIndicator.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> ADB unavailable';
          }
        }

        // Update header BYOD device status bar (Djini.ai style)
        const headerDevSelect = document.getElementById('header-device-select');
        if (headerDevSelect) {
          if (dastDevices.length === 0) {
            headerDevSelect.innerHTML = '<option value="">No Active Device</option>';
          } else {
            headerDevSelect.innerHTML = '<option value="">Select an authorized device</option>' + dastDevices.filter(d => d.allowed && d.status === 'device').map(d =>
              `<option value="${escapeHtml(String(d.serial))}" ${d.serial === dastActiveDevice ? 'selected' : ''}>${escapeHtml(d.model)} (${escapeHtml(String(d.serial))})</option>`
            ).join('');
          }
        }
        const headerRootBadge = document.getElementById('header-root-badge');
        if (headerRootBadge) {
          const activeDev = dastDevices.find(d => d.serial === dastActiveDevice);
          if (activeDev && activeDev.root_checked && activeDev.is_rooted) {
            headerRootBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800';
            headerRootBadge.innerHTML = '● Root diagnostic';
          } else if (activeDev) {
            headerRootBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700';
            headerRootBadge.textContent = activeDev.root_checked ? '○ Root shell not observed' : 'Root not checked';
          } else {
            headerRootBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-500 border border-slate-800';
            headerRootBadge.innerHTML = 'No Device';
          }
        }

        renderDastDeviceFleet();

        updateDastControls();
      } catch (e) {
        dastDevices = []; dastActiveDevice = null;
        const indicator = document.getElementById('dast-adb-indicator');
        if (indicator) { indicator.textContent = 'ADB inventory unknown — retry'; indicator.className = 'text-xs text-amber-400'; }
        const select = document.getElementById('header-device-select');
        if (select) select.replaceChildren(new Option('Device inventory unavailable', ''));
        document.getElementById('header-root-badge').textContent = 'Not checked';
        document.getElementById('nav-dast-device-badge').textContent = 'Unknown';
        document.getElementById('dast-fleet-count').textContent = 'Unknown';
        const fleet = document.getElementById('dast-device-fleet-list');
        if (fleet) fleet.textContent = 'Inventory unavailable. Reconnect the session or Refresh; no device is selected.';
        updateDastControls();
        showToast('Device inventory unavailable; no target selected.', 'error');
      }
    }

    async function deployFridaScriptQuick(scriptType) {
      const dev = dastActiveDevice;
      if (!dev) {
        showToast('Connect an ADB device first via Live DAST tab', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim();
      if (!pkg || pkg === 'com.target.mobile.app') { showToast('Specify your exact approved package first.', 'error'); return; }
      showToast(`Deploying Frida ${scriptType} to ${pkg} on ${escapeHtml(String(dev))}...`, 'info');
      try {
        const res = await fetch('/api/dast/frida', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dev, package_name: pkg, script_type: scriptType })
        });
        const data = await res.json();
        showToast(`Frida ${scriptType}: ${escapeHtml(String(data.status ?? ""))}`, data.status === 'executed' ? 'success' : 'error');
      } catch (err) {
        showToast(`Frida deploy error: ${err}`, 'error');
      }
    }

    function renderDastDeviceFleet() {
      const container = document.getElementById('dast-device-fleet-list');
      if (!container) return;

      if (dastDevices.length === 0) {
        container.innerHTML = `
          <div class="p-4 rounded-lg bg-card/60 border border-dashed border-borderSubtle text-center text-slate-400 space-y-2">
            <i data-lucide="smartphone" class="w-6 h-6 mx-auto text-slate-600"></i>
            <p class="text-xs text-slate-300 font-medium">No Android Devices / Emulators Detected</p>
            <p class="text-[11px] text-slate-500">Start your explicitly authorized device or emulator (AVD, Genymotion, or Corellium) and click below or connect via TCP.</p>
            <div class="pt-2">
              <button data-onclick="static93" class="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white text-[11px] font-mono">
                Connect 127.0.0.1:5555
              </button>
            </div>
          </div>
        `;
        window.lucide?.createIcons();
        return;
      }

      container.innerHTML = dastDevices.map(dev => {
        const isSelected = dev.serial === dastActiveDevice;
        const rootBadge = dev.root_checked && dev.is_rooted
          ? `<span class="px-1.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-700 text-[10px] font-mono text-emerald-300 font-semibold flex items-center gap-1">
               <span class="w-1 h-1 rounded-full bg-emerald-400"></span> # ROOT (uid=0)
             </span>`
          : `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-400">${dev.root_checked ? 'Root shell not observed' : 'Root not checked'} · ${escapeHtml(dev.status)} · ${dev.allowed ? 'server approved' : 'not approved'}</span>`;

        return `
          <button type="button" ${bindAction('click', () => selectDastDevice(dev.serial))} ${dev.allowed && dev.status === 'device' ? '' : 'disabled'} class="w-full text-left p-3 rounded-lg border cursor-pointer transition ${
            isSelected
              ? 'bg-sky-950/40 border-sky-500/60 shadow-sm'
              : 'bg-card hover:bg-slate-800/60 border-borderSubtle'
          }">
            <div class="flex items-center justify-between">
              <div class="flex items-center gap-2">
                <i data-lucide="${dev.is_emulator ? 'monitor' : 'smartphone'}" class="w-4 h-4 ${isSelected ? 'text-sky-400' : 'text-slate-400'}"></i>
                <span class="font-mono font-semibold text-white text-xs">${escapeHtml(dev.model || dev.serial)}</span>
                ${dev.is_emulator ? '<span class="text-[9px] px-1 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800 font-mono uppercase">Emulator</span>' : ''}
              </div>
              ${rootBadge}
            </div>
            <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 mt-2">
              <span>Serial: <span class="text-slate-300">${escapeHtml(dev.serial)}</span></span>
              <span>Android ${escapeHtml(dev.android_version)} (API ${escapeHtml(dev.sdk_level)})</span>
            </div>
          </button>
        `;
      }).join('');

      window.lucide?.createIcons();
    }

    function selectDastDevice(serial) {
      if (!dastDevices.some(d => d.serial === serial && d.allowed && d.status === 'device')) {
        dastActiveDevice = null; updateDastControls();
        showToast('Select an explicitly authorized device.', 'error');
        return;
      }
      dastActiveDevice = serial;
      const select = document.getElementById('header-device-select');
      if (select) select.value = serial;
      const label = document.getElementById('dast-active-target-label');
      if (label) label.textContent = serial;
      renderDastDeviceFleet(); updateDastControls();
      window.dispatchEvent(new CustomEvent('dast-device-selected', {detail: {serial}}));
      showToast(`Selected Device: ${serial}`, 'info');
    }

    async function connectDastDevice() {
      const input = document.getElementById('dast-tcp-input');
      const hostPort = input ? input.value.trim() : '127.0.0.1:5555';
      showToast(`Connecting to ${hostPort}...`, 'info');
      try {
        const res = await fetch('/api/dast/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ host_port: hostPort }),
        });
        const data = await res.json();
        if (data.status === 'success') {
          showToast(`Connected: ${escapeHtml(String(data.output ?? ""))}`, 'success');
        } else {
          showToast(`ADB: ${data.output || 'Could not connect'}`, 'info');
        }
        await refreshDastDevices();
      } catch (e) {
        showToast(`Connection error: ${e}`, 'error');
      }
    }

    async function restartDastRoot() {
      if (!window.confirm('Restart ADB with root privileges on this explicitly authorized test device?')) return;
      if (!dastActiveDevice) {
        showToast('Please select a device from the fleet first', 'error');
        return;
      }
      showToast(`Attempting adbd restart as root on ${dastActiveDevice}...`, 'info');
      try {
        const res = await fetch('/api/dast/root', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice }),
        });
        const data = await res.json();
        if (data.is_rooted) {
          showToast(`Success: Root shell verified on ${dastActiveDevice}`, 'success');
        } else {
          showToast(`Notice: ${escapeHtml(String(data.output ?? ""))}`, 'info');
        }
        await refreshDastDevices();
      } catch (e) {
        showToast(`Root switch error: ${e}`, 'error');
      }
    }

    async function installDastApk() {
      if (!window.confirm('Install this archive on the selected authorized device? Existing app data may be affected.')) return;
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const apkInput = document.getElementById('dast-input-apk');
      const apkPath = apkInput ? apkInput.value.trim() : '';
      if (!apkPath) {
        showToast('Please specify an APK path on the host', 'error');
        return;
      }

      showToast(`Installing ${apkPath} without forced runtime grants...`, 'info');
      try {
        const res = await fetch('/api/dast/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, apk_path: apkPath, grant_permissions: false }),
        });
        const data = await res.json();
        if (data.status === 'success') {
          showToast(`Installed successfully on ${dastActiveDevice}`, 'success');
        } else {
          showToast(`Install notice: ${data.output || data.message}`, 'error');
        }
      } catch (e) {
        showToast(`Install error: ${e}`, 'error');
      }
    }

    async function launchDastActivity() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || '';
      const act = document.getElementById('dast-input-activity')?.value.trim() || '';
      if (!act) {
        showToast('Specify an activity component to launch', 'error');
        return;
      }
      const fullComp = act.includes('/') ? act : `${pkg}/${act}`;
      showToast(`Launching ${fullComp}...`, 'info');

      try {
        const res = await fetch('/api/dast/launch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, component: fullComp }),
        });
        const data = await res.json();
        showToast(`Launch: ${data.status === 'success' ? 'Triggered' : data.output}`, 'info');
        setTimeout(fetchDastLogcat, 1000);
      } catch (e) {
        showToast(`Launch error: ${e}`, 'error');
      }
    }

    async function dispatchDastDeeplink() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const uri = document.getElementById('dast-input-deeplink')?.value.trim() || '';
      if (!uri) {
        showToast('Specify a deep link URI', 'error');
        return;
      }
      showToast(`Dispatching URI: ${uri}...`, 'info');

      try {
        const res = await fetch('/api/dast/deeplink', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name:document.getElementById('dast-input-package')?.value.trim(), uri: uri }),
        });
        const data = await res.json();
        showToast(`Deep Link dispatched (${escapeHtml(String(data.status ?? ""))})`, 'info');
        setTimeout(fetchDastLogcat, 1000);
      } catch (e) {
        showToast(`Deep link error: ${e}`, 'error');
      }
    }

    async function fetchDastLogcat() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || '';
      showToast(`Dumping logcat from ${dastActiveDevice}...`, 'info');

      try {
        const res = await fetch(`/api/dast/logcat?serial=${encodeURIComponent(dastActiveDevice)}&package_name=${encodeURIComponent(pkg)}&lines=250`);
        const data = await res.json();
        dastRawLogs = data.lines || [];

        renderDastTerminal(dastRawLogs);

        const counter = document.getElementById('dast-log-counter');
        if (counter) counter.textContent = `${dastRawLogs.length} lines`;

        // Process any findings discovered
        if (data.findings && data.findings.length > 0) {
          data.findings.forEach(f => {
            if (!dastFindings.some(existing => existing.title === f.title)) {
              dastFindings.unshift(f);
            }
          });
          renderDastFindings();
          showToast(`Logcat Audit: ${escapeHtml(String(data.findings.length ?? ""))} security alerts found!`, 'error');
        } else {
          showToast(`Retrieved ${dastRawLogs.length} logcat lines`, 'success');
        }
      } catch (e) {
        showToast(`Logcat error: ${e}`, 'error');
      }
    }

    function renderDastTerminal(lines) {
      const term = document.getElementById('dast-terminal');
      if (!term) return;

      if (!lines || lines.length === 0) {
        term.innerHTML = '<div class="text-slate-500">// Log buffer is currently empty.</div>';
        return;
      }

      term.innerHTML = lines.map(line => {
        let colorClass = 'text-slate-300';
        if (line.includes('FATAL EXCEPTION') || line.includes('AndroidRuntime') || line.includes('NullPointerException')) {
          colorClass = 'text-red-400 font-bold bg-red-950/30 px-1 rounded';
        } else if (line.includes(' E ') || line.includes('ERROR:')) {
          colorClass = 'text-red-400';
        } else if (line.includes(' W ') || line.includes('WARN:')) {
          colorClass = 'text-amber-400';
        } else if (line.includes(' D ')) {
          colorClass = 'text-sky-300';
        } else if (line.includes('Bearer') || line.includes('AIzaSy') || line.includes('AKIA')) {
          colorClass = 'text-emerald-300 font-semibold bg-emerald-950/50 px-1 rounded';
        }
        return `<div class="${colorClass}">${escapeHtml(line)}</div>`;
      }).join('');

      term.scrollTop = term.scrollHeight;
    }

    function filterDastTerminalLogs() {
      const filter = document.getElementById('dast-log-filter')?.value.toLowerCase() || '';
      if (!filter) {
        renderDastTerminal(dastRawLogs);
        return;
      }
      const filtered = dastRawLogs.filter(l => l.toLowerCase().includes(filter));
      renderDastTerminal(filtered);
    }

    async function clearDastLogcat() {
      if (!window.confirm('Clear the device-wide logcat buffer? This deletes logs.')) return;
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      try {
        await fetch('/api/dast/logcat/clear', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice }),
        });
        dastRawLogs = [];
        renderDastTerminal([]);
        const counter = document.getElementById('dast-log-counter');
        if (counter) counter.textContent = '0 lines';
        showToast('Device logcat buffer cleared', 'success');
      } catch (e) {
        showToast(`Clear error: ${e}`, 'error');
      }
    }

    async function captureDastScreenshot() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      showToast('Capturing screen frame...', 'info');

      try {
        const res = await fetch('/api/dast/screenshot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice }),
        });
        const data = await res.json();
        if (data.status === 'success' && data.image_b64) {
          const img = document.getElementById('dast-screenshot-img');
          const placeholder = document.getElementById('dast-screenshot-placeholder');
          if (img && placeholder) {
            img.src = data.image_b64;
            img.classList.remove('hidden');
            placeholder.classList.add('hidden');
          }
          showToast('Device frame captured successfully', 'success');
        } else {
          showToast('Screenshot capture failed', 'error');
        }
      } catch (e) {
        showToast(`Screenshot error: ${e}`, 'error');
      }
    }

    async function auditDastStorage() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      showToast(`Auditing sandbox storage (/data/data/${pkg})...`, 'info');

      try {
        const res = await fetch('/api/dast/storage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: pkg }),
        });
        const data = await res.json();
        const report = data.report || {};
        const findings = report.findings || [];

        if (findings.length > 0) {
          findings.forEach(f => {
            if (!dastFindings.some(existing => existing.title === f.title)) {
              dastFindings.unshift(f);
            }
          });
          renderDastFindings();
          showToast(`Storage Forensics: ${findings.length} cleartext flaws discovered!`, 'error');
        } else {
          showToast('No candidates reported by this bounded diagnostic; not a clean bill of health', 'success');
        }
      } catch (e) {
        showToast(`Storage audit error: ${e}`, 'error');
      }
    }

    async function auditDastProviders() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      const auth = document.getElementById('dast-input-authority')?.value.trim();
      if (!auth) {
        showToast('Please specify a Content Provider authority', 'error');
        return;
      }
      showToast(`Auditing Content Provider authority: ${auth}...`, 'info');

      try {
        const res = await fetch('/api/dast/providers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: pkg, authorities: [auth] }),
        });
        const data = await res.json();
        const findings = data.findings || [];

        if (findings.length > 0) {
          findings.forEach(f => {
            if (!dastFindings.some(existing => existing.title === f.title)) {
              dastFindings.unshift(f);
            }
          });
          renderDastFindings();
          showToast(`Provider Audit: ${findings.length} IPC/SQL flaws found!`, 'error');
        } else {
          showToast('No candidates reported in this diagnostic; authorization is not established', 'success');
        }
      } catch (e) {
        showToast(`Provider audit error: ${e}`, 'error');
      }
    }

    async function runDastFuzzSuite() {
      if (!window.confirm('Run active device fuzzing? It can launch activities and crash the scoped app. Use synthetic data only.')) return;
      if (!dastActiveDevice) {
        showToast('Select a target device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      const act = document.getElementById('dast-input-activity')?.value.trim() || '';
      const uri = document.getElementById('dast-input-deeplink')?.value.trim() || '';
      const apk = document.getElementById('dast-input-apk')?.value.trim() || '';
      const auth = document.getElementById('dast-input-authority')?.value.trim() || '';

      const btn = document.getElementById('btn-dast-run-suite');
      const statusLabel = document.getElementById('dast-fuzz-status');
      if (btn) btn.disabled = true;
      if (statusLabel) {
        statusLabel.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span> Dynamic Suite Running...';
      }

      showToast(`Initiating DAST Assessment Suite on ${dastActiveDevice}...`, 'info');

      try {
        const optStorage = document.getElementById('dast-opt-storage')?.checked ?? true;
        const optMemory = document.getElementById('dast-opt-memory')?.checked ?? true;
        const optCrawl = document.getElementById('dast-opt-crawl')?.checked ?? false;

        const payload = {
          serial: dastActiveDevice,
          package_name: pkg,
          apk_path: apk || null,
          activities: act ? [act] : [`${pkg}.MainActivity`],
          deeplinks: uri ? [uri] : [],
          authorities: auth ? [auth] : [],
          audit_storage: optStorage,
          audit_memory: optMemory,
          crawl_ui: optCrawl,
        };
        const res = await fetch('/api/dast/fuzz', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        showToast(data.message || 'DAST suite running in background', 'success');
      } catch (e) {
        showToast(`Fuzz suite error: ${e}`, 'error');
        if (btn) btn.disabled = false;
      }
    }


    function handleDastLiveEvent(data) {
      if (data.type === 'dast_progress') {
        const statusLabel = document.getElementById('dast-fuzz-status');
        if (statusLabel) {
          statusLabel.innerHTML = `<span class="w-2 h-2 rounded-full bg-sky-400 animate-pulse"></span> [${escapeHtml(String(data.stage))}] ${escapeHtml(data.message)}`;
        }
        // Append event to terminal
        const term = document.getElementById('dast-terminal');
        if (term) {
          const div = document.createElement('div');
          div.className = 'text-sky-400 font-mono font-medium';
          div.textContent = `[*] [${escapeHtml(String(data.stage))} ${escapeHtml(String(data.progress ?? ""))}%] ${escapeHtml(String(data.message ?? ""))}`;
          term.appendChild(div);
          term.scrollTop = term.scrollHeight;
        }
        if (data.progress === 100) {
          const btn = document.getElementById('btn-dast-run-suite');
          if (btn) btn.disabled = false;
          showToast('Dynamic assessment completed!', 'success');
          setTimeout(fetchDastLogcat, 500);
        }
      } else if (data.type === 'dast_finding') {
        if (!dastFindings.some(existing => existing.title === data.finding.title)) {
          dastFindings.unshift(data.finding);
        }
        renderDastFindings();
        showToast(`🚨 Dynamic Finding: ${escapeHtml(String(data.finding.title ?? ""))}`, 'error');
      }
    }

    function renderDastFindings() {
      const container = document.getElementById('dast-findings-container');
      const countBadge = document.getElementById('dast-findings-count');
      if (!container) return;

      if (countBadge) countBadge.textContent = `${dastFindings.length} Dynamic Findings`;

      if (dastFindings.length === 0) {
        container.innerHTML = `
          <div class="p-6 text-center text-slate-500 text-xs bg-card/40 rounded-lg border border-borderSubtle">
            <i data-lucide="shield-check" class="w-6 h-6 mx-auto mb-2 text-emerald-500/60"></i>
            No diagnostic evidence collected. Zero entries is not a security verdict. Run only reviewed, explicitly scoped diagnostics.
          </div>
        `;
        window.lucide?.createIcons();
        return;
      }

      container.innerHTML = dastFindings.map((f, idx) => {
        const sevColor = f.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border-red-800' :
                         f.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border-orange-800' :
                         'bg-amber-950 text-amber-300 border-amber-800';

        return `
          <div class="p-4 rounded-xl bg-card border border-borderSubtle hover:border-slate-700 transition flex flex-col space-y-3">
            <div class="flex items-start justify-between gap-4">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border ${sevColor}">${escapeHtml(String(f.severity))}</span>
                  <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700 font-semibold">${escapeHtml(String(f.cwe_id || 'CWE'))}</span>
                  <span class="text-xs text-slate-400 font-mono">CVSS ${escapeHtml(String(f.cvss_score || 'N/A'))}</span>
                  <span class="px-1.5 py-0.2 rounded bg-purple-950/80 border border-purple-800 text-[10px] font-mono text-purple-300">Live Dynamic</span>
                </div>
                <h4 class="text-sm font-semibold text-white">${escapeHtml(f.title)}</h4>
                <p class="text-xs text-slate-400 font-mono">Component: <span class="text-slate-200">${escapeHtml(f.affected_component || 'Runtime')}</span></p>
              </div>

              <!-- Triage Controls & PoC Studio link -->
              <div class="flex items-center gap-2 shrink-0">
                <button ${bindAction('click', () => inspectDastInPocStudio(f.id || 'find-dast-' + idx))} class="px-2.5 py-1 rounded bg-amber-950/70 hover:bg-amber-900 border border-amber-800 text-amber-300 text-xs font-mono flex items-center gap-1 transition">
                  <i data-lucide="zap" class="w-3 h-3 text-amber-400"></i> PoC Studio
                </button>
                <button ${bindAction('click', () => submitTriageVerdict(f.id || 'find-dast-' + idx, 'CONFIRMED'))} class="px-2.5 py-1 rounded bg-emerald-950/60 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-1">
                  <i data-lucide="check" class="w-3 h-3"></i> Confirm
                </button>
                <button ${bindAction('click', () => submitTriageVerdict(f.id || 'find-dast-' + idx, 'FALSE_POSITIVE'))} class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-400 text-xs font-mono flex items-center gap-1">
                  <i data-lucide="x" class="w-3 h-3"></i> False Positive
                </button>
              </div>
            </div>

            <!-- Description & Evidence Snippet -->
            <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(f.description || '')}</p>
            ${f.code_snippet ? `
              <div class="bg-black/80 border border-borderSubtle rounded-lg p-2.5 text-[11px] font-mono text-red-300 overflow-x-auto whitespace-pre-wrap">
                <code>${escapeHtml(f.code_snippet)}</code>
              </div>
            ` : ''}

            <!-- Remediation Guidance -->
            ${f.remediation ? `
              <div class="pt-2 border-t border-borderSubtle/60 flex items-start gap-2 text-[11px] font-mono text-slate-400">
                <i data-lucide="wrench" class="w-3.5 h-3.5 text-sky-400 shrink-0 mt-0.5"></i>
                <div><span class="text-slate-300 font-semibold">Remediation:</span> ${escapeHtml(f.remediation)}</div>
              </div>
            ` : ''}
          </div>
        `;
      }).join('');
      window.lucide?.createIcons();
    }

    function inspectDastInPocStudio(findingId) {
      const f = dastFindings.find(item => (item.id || '') === findingId || ('find-dast-' + dastFindings.indexOf(item)) === findingId);
      if (f && currentScan && currentScan.findings) {
        if (!currentScan.findings.some(item => item.id === f.id)) {
          currentScan.findings.unshift(f);
        }
      }
      switchView('findings');
      if (f) inspectFinding(f.id);
    }

    // =========================================================================
    // Advanced DAST Extensions: DeepLink Matrix, Memory Forensics, UI Crawler, Frida
    // =========================================================================

    // 1. Deep Link Fuzzing Matrix
    async function auditDastDeepLinks() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      const uri = document.getElementById('dast-input-deeplink')?.value.trim() || '';
      if (!uri) {
        showToast('Specify a deep link URI or scheme (e.g. targetapp://)', 'error');
        return;
      }
      showToast(`Running Deep Link Fuzzing Matrix on ${uri}...`, 'info');

      try {
        const res = await fetch('/api/dast/deeplinks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: pkg, deep_links: [uri] }),
        });
        const data = await res.json();
        const results = data.results || [];
        const findings = data.findings || [];

        if (findings.length > 0) {
          findings.forEach(f => {
            if (!dastFindings.some(existing => existing.title === f.title)) {
              dastFindings.unshift(f);
            }
          });
          renderDastFindings();
          showToast(`Deep Link Audit: ${findings.length} injection / crash flaws detected!`, 'error');
        } else {
          showToast(`Deep Link Matrix Complete: Exercised ${results.length} payloads safely`, 'success');
        }
        setTimeout(fetchDastLogcat, 1000);
      } catch (e) {
        showToast(`Deep Link Fuzzing error: ${e}`, 'error');
      }
    }

    // 2. Volatile RAM Forensics (CWE-316)
    async function auditDastMemory() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      showToast(`Auditing volatile process memory (/proc/<pid>/mem) for ${pkg}...`, 'info');

      try {
        const res = await fetch('/api/dast/memory', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: pkg }),
        });
        const data = await res.json();
        const report = data.report || {};
        const findings = report.findings || [];

        if (findings.length > 0) {
          findings.forEach(f => {
            if (!dastFindings.some(existing => existing.title === f.title)) {
              dastFindings.unshift(f);
            }
          });
          renderDastFindings();
          showToast(`RAM Forensics (CWE-316): ${findings.length} cleartext secrets retained in memory!`, 'error');
        } else if (report.process_found === false) {
          showToast(`No running process found for ${pkg}. Launch the app on device first.`, 'info');
        } else {
          showToast('No lingering cleartext secrets detected in volatile RAM buffers', 'success');
        }
      } catch (e) {
        showToast(`Memory audit error: ${e}`, 'error');
      }
    }

    // 3. Autonomous UI Crawler
    async function crawlDastUI() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      showToast(`Autonomous UIAutomator crawler starting for ${pkg} (5 steps)...`, 'info');

      try {
        const res = await fetch('/api/dast/crawl', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: pkg, max_steps: 5 }),
        });
        const data = await res.json();
        const rep = data.report || {};
        showToast(`UI Crawl Complete: ${rep.screens_explored || 0} screens, ${rep.dialogs_dismissed || 0} dialogs dismissed, ${rep.inputs_filled || 0} inputs filled`, 'success');
        setTimeout(fetchDastLogcat, 1000);
      } catch (e) {
        showToast(`UI Crawler error: ${e}`, 'error');
      }
    }

    // 4. Frida Dynamic Instrumentation & Hooks
    let activeFridaScriptCode = '';

    function updateDastControls() {
      const selected = dastDevices.some(d => d.serial === dastActiveDevice && d.allowed && d.status === 'device');
      const actions = [9,10,38,39,40,41,42,43,44,45,46,47,48,49,51,53,58,59,60];
      for (const id of actions) document.querySelectorAll(`[data-onclick="static${id}"]`).forEach(button => {
        button.disabled = !selected;
        button.title = selected ? 'Requires the saved exact action scope' : 'Explicitly select an online server-approved device first';
      });
      const select = document.getElementById('header-device-select');
      if (select) select.value = selected ? dastActiveDevice : '';
      const label = document.getElementById('dast-active-target-label');
      if (label) label.textContent = selected ? dastActiveDevice : 'None Selected';
      const badge = document.getElementById('frida-status-badge');
      if (badge) { badge.textContent = 'Frida process not checked'; badge.className = 'text-xs text-slate-400'; }
      document.getElementById('header-root-badge').textContent = selected ? 'Root not checked' : 'No Device';
    }

    async function checkFridaServerStatus() {
      if (!dastActiveDevice) { showToast('Select an approved online device first', 'error'); return; }
      const serial = dastActiveDevice;
      const badge = document.getElementById('frida-status-badge');
      if (badge) badge.textContent = 'Checking approved process observation…';
      try {
        const data = await (await fetch('/api/dast/frida/status?serial=' + encodeURIComponent(serial))).json();
        if (dastActiveDevice !== serial) return;
        if (badge) badge.textContent = 'Frida process: ' + data.process_state.replaceAll('_', ' ') + ' (attachment not checked)';
        showToast('Process observation only; compatibility and attachment are not verified.', 'info');
      } catch (error) {
        if (dastActiveDevice !== serial) return;
        if (badge) badge.textContent = error.status === 403 ? 'Frida observation not approved' : 'Frida status unknown — retry';
        showToast('Approve frida_status for this dedicated device in Configuration before checking. No hook was executed.', 'info');
      }
    }

    async function deployFridaScript(scriptType) {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
      showToast(`Deploying Frida hook [${scriptType}] to ${pkg}...`, 'info');

      try {
        const res = await fetch('/api/dast/frida', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: pkg, script_type: scriptType }),
        });
        const data = await res.json();
        activeFridaScriptCode = data.script || '';

        previewFridaScript(scriptType, data.script);
        showToast(`Frida [${scriptType}]: ${escapeHtml(String(data.status ?? ""))}`, data.status === 'executed' ? 'success' : 'error');
        setTimeout(fetchDastLogcat, 1000);
      } catch (e) {
        showToast(`Frida deploy error: ${e}`, 'error');
      }
    }

    async function previewFridaScript(scriptType, codeOverride) {
      const panel = document.getElementById('frida-script-preview-panel');
      const title = document.getElementById('frida-preview-title');
      const pre = document.getElementById('frida-script-code');
      if (!panel || !pre) return;

      if (!codeOverride) {
        const pkg = document.getElementById('dast-input-package')?.value.trim() || 'com.target.mobile.app';
        try {
          const res = await fetch('/api/frida/presets/' + encodeURIComponent(scriptType));
          const data = await res.json();
          activeFridaScriptCode = data.script || '';
        } catch (e) {
          activeFridaScriptCode = '// Could not load preview';
        }
      } else {
        activeFridaScriptCode = codeOverride;
      }

      if (title) title.textContent = `// Frida Hook: ${scriptType.toUpperCase()}`;
      pre.textContent = activeFridaScriptCode;
      panel.classList.remove('hidden');
      panel.scrollIntoView({ behavior: 'smooth' });
    }

    function copyFridaScript() {
      if (activeFridaScriptCode) {
        navigator.clipboard.writeText(activeFridaScriptCode);
        showToast('Frida script copied to clipboard', 'success');
      }
    }

    // =========================================================================

    window.addEventListener('DOMContentLoaded', updateDastControls);
    window.addEventListener('workspace-session-invalidated', () => { dastDevices=[]; dastActiveDevice=null; updateDastControls(); document.getElementById('dast-adb-indicator').textContent='ADB not checked — reconnect'; document.getElementById('header-device-select').replaceChildren(new Option('Reconnect session', '')); document.getElementById('dast-device-fleet-list').textContent='Session disconnected; reconnect and refresh inventory.'; document.getElementById('dast-fleet-count').textContent='Not checked'; document.getElementById('nav-dast-device-badge').textContent='Unknown'; });
