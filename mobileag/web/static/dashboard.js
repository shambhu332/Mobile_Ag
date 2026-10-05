
    // Token stays in page memory, never in a URL, cookie, localStorage or report.
    let accessToken = window.prompt('Paste the MobileAg session token shown in the server terminal:') || '';
    const nativeFetch = window.fetch.bind(window);
    window.fetch = async function(input, options = {}) {
      const url = new URL(typeof input === 'string' ? input : input.url, window.location.href);
      const headers = new Headers(options.headers || {});
      if (url.origin === window.location.origin && url.pathname.startsWith('/api/')) {
        headers.set('Authorization', 'Bearer ' + accessToken);
      }
      const response = await nativeFetch(input, {...options, headers});
      if (!response.ok) {
        const body = await response.clone().json().catch(() => ({}));
        throw new Error(body.detail || `Request failed (${response.status})`);
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
    actionCallbacks.set('static-reconnect', async function() {
      const entered = window.prompt('Paste your current server session token:');
      if (!entered) return;
      accessToken = entered;
      if (wsConnection) wsConnection.close();
      await loadInitialScan();
      connectTelemetryWebSocket();
      await loadPrivacyPolicy();
    });
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

    let activeView = 'surface';
    let currentScan = null;
    let visNetwork = null;
    let visNodes = null;
    let visEdges = null;
    let masvsChart = null;
    let activeSeverityFilter = 'ALL';
    let selectedFindingId = null;
    let wsConnection = null;
    let copilotOpen = false;

    // Toast Notification System
    function showToast(message, type = 'info') {
      const container = document.getElementById('toast-container');
      const toast = document.createElement('div');
      toast.className = `px-4 py-2.5 rounded-lg border text-xs font-mono shadow-lg transition-all transform duration-300 flex items-center gap-2 pointer-events-auto ${
        type === 'success' ? 'bg-emerald-950 border-emerald-800 text-emerald-300' :
        type === 'error' ? 'bg-red-950 border-red-800 text-red-300' :
        'bg-slate-900 border-slate-700 text-slate-200'
      }`;
      toast.textContent = String(message);
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 3500);
    }

    // View Navigation
    function switchView(viewId) {
      activeView = viewId;
      document.querySelectorAll('.view-panel').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.remove('bg-sky-950/40', 'text-sky-400', 'border', 'border-sky-800/40');
        el.classList.add('text-slate-400');
      });

      const targetView = document.getElementById(`view-${viewId}`);
      if (targetView) targetView.classList.remove('hidden');

      const activeNav = document.getElementById(`nav-${viewId}`);
      if (activeNav) {
        activeNav.classList.add('bg-sky-950/40', 'text-sky-400', 'border', 'border-sky-800/40');
        activeNav.classList.remove('text-slate-400');
      }

      if (viewId === 'dast') loadDastView();
      if (viewId === 'taint') loadTaintView();
      if (viewId === 'api') loadApiView();
      if (viewId === 'agents') loadAgentsView();
      if (viewId === 'scans') loadScansView();
      if (viewId === 'settings') loadSettingsView();
      if (viewId === 'findings') applyFindingsFilter();
      if (viewId === 'surface' && visNetwork) visNetwork.fit();

      window.lucide?.createIcons();

    }

    // Load Scan Data
    async function loadInitialScan() {
      try {
        const res = await fetch('/api/scans?limit=1&summaries=true');
        const page = await res.json();
        currentScan = page.items.length ? await (await fetch('/api/scans/' + encodeURIComponent(page.items[0].scan_id))).json() : null;
        if (!currentScan) {
          renderDashboard({package_name:"Upload an APK or IPA to begin", stats:{total:0}, findings:[]});
          return;
        }

        // Fetch dynamic graph
        try {
          const graphRes = await fetch(`/api/scans/${currentScan.scan_id}/graph`);
          const graphData = await graphRes.json();
          if (graphData && graphData.graph) {
            currentScan.attack_surface_graph = graphData.graph;
            const srcLabel = document.getElementById('graph-source-label');
            if (srcLabel) {
              srcLabel.textContent = graphData.source === 'neo4j' ? 'Source: Neo4j Live' : 'Source: Embedded';
            }
          }
        } catch (e) {
          console.warn('Graph query error:', e);
        }

        renderDashboard(currentScan);
      } catch (err) {
        renderDashboard({package_name:'Unable to load scans', stats:{total:0}, findings:[]});
        showToast('Unable to load scans: ' + err.message, 'error');
      }
    }

    function renderDashboard(scan) {
      if (!scan) return;
      scan.stats = scan.stats || {};
      const apiBadge = document.getElementById('nav-api-badge');
      if (apiBadge) apiBadge.textContent = (scan.api_endpoints || []).length + ' APIs';

      // Header values
      document.getElementById('top-package-name').textContent = scan.package_name || 'com.target.mobile.app';
      document.getElementById('top-version').textContent = 'v' + (scan.version || 'unknown');
      document.getElementById('top-framework').textContent = scan.framework || 'Not assessed';
      const obfuscation = document.getElementById('top-obfuscation');
      if (obfuscation) obfuscation.textContent = scan.obfuscation_level || 'Not assessed';

      // KPI cards
      document.getElementById('kpi-total').textContent = (scan.findings || []).length;
      document.getElementById('kpi-critical-high').textContent = (scan.stats.critical || 0) + (scan.stats.high || 0);
      document.getElementById('kpi-med-low').textContent = (scan.stats.medium || 0) + (scan.stats.low || 0);
      document.getElementById('kpi-masvs').textContent = 'Not assessed';
      document.getElementById('kpi-consensus').textContent = 'Not measured';
      document.getElementById('nav-findings-count').textContent = (scan.findings || []).length;

      // Render Modules
      renderVisNetwork(scan.attack_surface_graph || { nodes: [], edges: [] });
      renderAgentTelemetryFeed(scan.agent_telemetry || []);
      renderMasvsRadarChart(scan.masvs_compliance || {});
      applyFindingsFilter();

      window.lucide?.createIcons();
    }

    // Vis.js Network Topology
    function renderVisNetwork(graphData) {
      const container = document.getElementById('visjs-container');
      if (!window.vis) { container.textContent = 'Graph library unavailable; findings remain accessible.'; return; }
      visNodes = new vis.DataSet(graphData.nodes || []);
      visEdges = new vis.DataSet(graphData.edges || []);

      const data = { nodes: visNodes, edges: visEdges };
      const options = {
        nodes: {
          font: { color: '#E2E8F0', face: 'JetBrains Mono', size: 10 },
          borderWidth: 1.5,
        },
        edges: {
          color: { color: '#334155', highlight: '#0ea5e9', hover: '#0ea5e9' },
          font: { color: '#64748B', face: 'JetBrains Mono', size: 9, align: 'top' },
          arrows: { to: { enabled: true, scaleFactor: 0.5 } },
          smooth: { type: 'continuous' }
        },
        physics: {
          stabilization: true,
          barnesHut: { gravitationalConstant: -2800, springLength: 85 }
        },
        interaction: { hover: true }
      };

      if (visNetwork) visNetwork.destroy();
      visNetwork = new vis.Network(container, data, options);

      visNetwork.on('click', function(params) {
        if (params.nodes.length > 0) {
          const nodeId = params.nodes[0];
          selectFindingByNode(nodeId);
        }
      });
    }

    function graphFit() { if (visNetwork) visNetwork.fit({ animation: true }); }
    function graphZoomIn() { if (visNetwork) visNetwork.moveTo({ scale: visNetwork.getScale() * 1.3 }); }
    function graphZoomOut() { if (visNetwork) visNetwork.moveTo({ scale: visNetwork.getScale() * 0.7 }); }

    function selectFindingByNode(nodeId) {
      if (!currentScan || !currentScan.findings) return;
      const f = currentScan.findings.find(item => item.id === nodeId || (item.cwe_id && item.cwe_id.toLowerCase() === nodeId.toLowerCase()));
      if (f) {
        switchView('findings');
        inspectFinding(f.id);
      }
    }

    // Agent Telemetry Feed
    function renderAgentTelemetryFeed(list) {
      const feed = document.getElementById('agent-telemetry-feed');
      feed.innerHTML = '';
      list.forEach(agent => {
        const item = document.createElement('div');
        item.className = 'flex items-center justify-between p-2 rounded-lg bg-card border border-borderSubtle';
        item.innerHTML = `
          <div class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span class="font-mono font-medium text-slate-200 text-xs">${escapeHtml(String(agent.name))}</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-[11px] font-mono text-sky-400">${agent.findings > 0 ? agent.findings + ' issues' : 'clean'}</span>
            <span class="text-[10px] font-mono text-slate-500">${escapeHtml(String(agent.duration))}</span>
            <span class="px-1.5 py-0.2 rounded text-[9px] font-mono uppercase bg-emerald-950 text-emerald-400 border border-emerald-800">PASS</span>
          </div>
        `;
        feed.appendChild(item);
      });
    }

    // Chart.js MASVS Radar
    function renderMasvsRadarChart(compliance) {
      const ctx = document.getElementById('masvs-canvas');
      if (!ctx || !window.Chart) return;

      const labels = Object.keys(compliance);
      const dataValues = Object.values(compliance);

      if (masvsChart) masvsChart.destroy();
      masvsChart = new Chart(ctx, {
        type: 'radar',
        data: {
          labels: labels,
          datasets: [{
            label: 'MASVS Compliance (%)',
            data: dataValues,
            backgroundColor: 'rgba(14, 165, 233, 0.15)',
            borderColor: '#0ea5e9',
            borderWidth: 1.5,
            pointBackgroundColor: '#10b981',
            pointBorderColor: '#fff',
            pointRadius: 3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            r: {
              angleLines: { color: '#1E293B' },
              grid: { color: '#1E293B' },
              pointLabels: { color: '#94A3B8', font: { size: 9, family: 'JetBrains Mono' } },
              ticks: { display: false, min: 0, max: 100 }
            }
          },
          plugins: { legend: { display: false } }
        }
      });
    }

    // Findings Filter & Inspector
    function setSeverityFilter(sev) {
      activeSeverityFilter = sev;
      document.querySelectorAll('.sev-btn').forEach(b => {
        b.classList.remove('bg-slate-700', 'text-white');
        b.classList.add('text-slate-400');
      });
      const activeBtn = document.getElementById(`sev-${sev === 'CRITICAL' ? 'crit' : sev.toLowerCase()}`);
      if (activeBtn) {
        activeBtn.classList.add('bg-slate-700', 'text-white');
        activeBtn.classList.remove('text-slate-400');
      }
      applyFindingsFilter();
    }

    function applyFindingsFilter() {
      const query = (document.getElementById('findings-search-input')?.value || '').toLowerCase();
      const status = document.getElementById('status-filter-select')?.value || 'ALL';
      const container = document.getElementById('findings-full-list');
      if (!container || !currentScan) return;

      container.innerHTML = '';
      const list = (currentScan.findings || []).filter(f => {
        const matchesSev = activeSeverityFilter === 'ALL' || f.severity === activeSeverityFilter;
        const matchesStatus = status === 'ALL' || f.status === status;
        const matchesQuery = !query ||
          (f.title && f.title.toLowerCase().includes(query)) ||
          (f.cwe_id && f.cwe_id.toLowerCase().includes(query)) ||
          (f.affected_component && f.affected_component.toLowerCase().includes(query));
        return matchesSev && matchesStatus && matchesQuery;
      });

      if (list.length === 0) {
        container.innerHTML = `<div class="text-center py-12 text-slate-500 font-mono text-xs">No findings matching the selected filters.</div>`;
        return;
      }

      list.forEach(f => {
        const card = document.createElement('div');
        const isSelected = selectedFindingId === f.id;
        card.className = `p-3 rounded-lg border transition cursor-pointer ${
          isSelected ? 'bg-card border-sky-500' : 'bg-panel border-borderSubtle hover:border-slate-600'
        }`;
        card.addEventListener('click', () => inspectFinding(f.id));

        const sevColors = {
          CRITICAL: 'bg-red-950 text-red-400 border-red-800',
          HIGH: 'bg-orange-950 text-orange-400 border-orange-800',
          MEDIUM: 'bg-yellow-950 text-yellow-400 border-yellow-800',
          LOW: 'bg-blue-950 text-blue-400 border-blue-800',
        };

        card.innerHTML = `
          <div class="flex items-center justify-between mb-1.5">
            <div class="flex items-center gap-2">
              <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${sevColors[f.severity] || 'border-slate-700 text-slate-400'}">${escapeHtml(String(f.severity))}</span>
              <span class="text-xs font-mono font-bold text-slate-300">${escapeHtml(String(f.cwe_id))}</span>
              <span class="text-[11px] font-mono text-slate-400">CVSS ${escapeHtml(String(f.cvss_score))}</span>
            </div>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded ${f.status === 'CONFIRMED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'}">${escapeHtml(String(f.status))}</span>
          </div>
          <h4 class="text-xs font-semibold text-white mb-1">${escapeHtml(f.title)}</h4>
          <p class="text-[11px] text-slate-400 truncate font-mono">${escapeHtml(f.affected_component || f.file_path)}</p>
          <div class="flex items-center justify-between mt-2 pt-2 border-t border-borderSubtle/60 text-[10px] font-mono text-slate-400">
            <span class="flex items-center gap-1 text-amber-400 font-semibold"><i data-lucide="zap" class="w-3 h-3"></i> Review guide</span>
            <span class="flex items-center gap-1 text-emerald-400 font-semibold"><i data-lucide="terminal" class="w-3 h-3"></i> 1-Click ADB</span>
            <span class="text-slate-500">${escapeHtml(f.owasp_masvs || 'MASVS')}</span>
          </div>
        `;
        container.appendChild(card);
      });
      window.lucide?.createIcons();

      // Default inspect first finding
      if (!selectedFindingId && list.length > 0) {
        inspectFinding(list[0].id);
      }
    }

    let currentFindingSubTab = 'poc';

    function switchFindingSubTab(tab) {
      currentFindingSubTab = tab;
      document.querySelectorAll('.poc-tab-pane').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.poc-subtab-btn').forEach(btn => {
        btn.classList.remove('bg-sky-950', 'text-sky-400', 'border', 'border-sky-800');
        btn.classList.add('text-slate-400');
      });
      const targetPane = document.getElementById(`poc-pane-${tab}`);
      if (targetPane) targetPane.classList.remove('hidden');
      const targetBtn = document.getElementById(`subtab-btn-${tab}`);
      if (targetBtn) {
        targetBtn.classList.add('bg-sky-950', 'text-sky-400', 'border', 'border-sky-800');
        targetBtn.classList.remove('text-slate-400');
      }
      window.lucide?.createIcons();
    }

    function renderMarkdownSimple(md) {
      if (!md) return '';
      let html = escapeHtml(md);
      html = html.replace(/```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g, (m, lang, code) => {
        return `<pre class="bg-black/90 border border-borderSubtle p-2.5 rounded-lg text-emerald-300 font-mono text-[11px] overflow-x-auto my-2 whitespace-pre-wrap"><code>${code.trim()}</code></pre>`;
      });
      html = html.replace(/`([^`]+)`/g, '<code class="bg-black/60 text-amber-300 px-1 py-0.5 rounded text-[11px] font-mono">$1</code>');
      html = html.replace(/^### (.*$)/gim, '<h5 class="text-xs font-bold text-white mt-3 mb-1.5 flex items-center gap-1.5"><span class="w-1.5 h-1.5 rounded-full bg-sky-400"></span> $1</h5>');
      html = html.replace(/^#### (.*$)/gim, '<h6 class="text-[11px] font-semibold text-sky-400 mt-2.5 mb-1">$1</h6>');
      html = html.replace(/\*\*([^*]+)\*\*/g, '<strong class="text-white font-semibold">$1</strong>');
      html = html.replace(/^\- (.*$)/gim, '<li class="ml-4 list-disc text-slate-300 text-[11px] leading-relaxed my-0.5">$1</li>');
      html = html.replace(/^(\d+)\. (.*$)/gim, '<li class="ml-4 list-decimal text-slate-300 text-[11px] leading-relaxed my-1"><span class="text-slate-200">$2</span></li>');
      html = html.replace(/\n\n/g, '<div class="h-2"></div>');
      return html;
    }

    function getOrGeneratePocGuide(f) {
      if (f.poc_guide) return f.poc_guide;
      const pkg = document.getElementById('top-package-name')?.textContent || 'com.target.mobile.app';
      const comp = f.affected_component || 'MainActivity';
      return `### Suggested manual review (not executed): ${escapeHtml(String(f.title ?? ""))}\n\n#### Prerequisites\n- Connected Android device or emulator with ADB authorized\n- Target application (\`${pkg}\`) installed\n\n#### Steps to Reproduce\n1. Inspect target component declarations:\n   \`adb shell dumpsys package ${pkg} | grep -A 8 "${comp.split('.').pop()}"\`\n2. Issue tailored invocation probe:\n   \`adb shell am start -n ${pkg}/${comp}\`\n3. Observe execution flow and verify sink invocation in Logcat.\n\n#### Record actual results\nRecord authorization denials, observed behavior and negative controls. A successful shell invocation is not proof of ordinary-app exploitation.\n\n#### Impact\nNot established. Validate the attacker-controlled input, crossed boundary, prerequisites and reproducibility before confirming this candidate.`;
    }

    function getOrGenerateAdbCommand(f) {
      if (f.adb_command) return f.adb_command;
      const pkg = document.getElementById('top-package-name')?.textContent || 'com.target.mobile.app';
      const comp = f.affected_component || 'MainActivity';
      if (comp.includes('Activity') || comp.includes('activity')) {
        return `am start -n ${pkg}/${comp}`;
      } else if (comp.includes('Service') || comp.includes('service')) {
        return `am startservice -n ${pkg}/${comp}`;
      } else if (comp.includes('Receiver') || comp.includes('receiver')) {
        return `am broadcast -n ${pkg}/${comp}`;
      }
      return `dumpsys package ${pkg} | grep -i "${comp.split('.').pop()}"`;
    }

    function getOrGenerateFridaScript(f) {
      if (f.frida_script) return f.frida_script;
      const comp = f.affected_component || 'com.target.mobile.app.MainActivity';
      return `// Frida Hook for ${f.cwe_id || 'Vulnerability Verification'}\nJava.perform(function () {\n    try {\n        var Target = Java.use("${comp}");\n        console.log("[+] Successfully hooked: ${comp}");\n        // Intercept lifecycle methods or security gates\n    } catch (e) {\n        console.log("[-] Class hook deferred: " + e);\n    }\n});`;
    }

    function getOrGenerateProofEvidence(f) {
      return f.validation_notes
        ? 'Analyst-provided notes (not independently verified):\n' + f.validation_notes
        : 'No runtime validation evidence recorded. Static findings and generated guides are unverified review candidates.';
    }

    async function executeAdbFromPoc(command) {
      const terminal = document.getElementById('poc-adb-terminal');
      if (!terminal) return;
      const dev = dastActiveDevice;
      if (!dev) {
        terminal.innerHTML += `\n<span class="text-amber-400">[!] No connected BYOD device detected. Connect a device/emulator via Live DAST tab first.</span>`;
        return;
      }
      if (!window.confirm('Run this diagnostic command on ' + dev + '?\n' + command + '\nSample-derived commands are untrusted.')) return;
      terminal.innerHTML += `\n<span class="text-sky-400">$ adb -s ${escapeHtml(String(dev))} shell ${escapeHtml(command)}</span>\n<span class="text-slate-400">Executing on ${escapeHtml(String(dev))}...</span>`;
      terminal.scrollTop = terminal.scrollHeight;
      try {
        const res = await fetch('/api/dast/execute_adb', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dev, command: command })
        });
        const data = await res.json();
        terminal.innerHTML += `\n<span class="text-emerald-400">[+] Output:</span>\n${escapeHtml(data.output || '(No standard output)')}\n`;
        terminal.scrollTop = terminal.scrollHeight;
        showToast('ADB command finished; inspect evidence before confirming any finding.', 'success');
      } catch (err) {
        terminal.innerHTML += `\n<span class="text-red-400">[-] Execution failed: ${escapeHtml(err.message)}</span>\n`;
        terminal.scrollTop = terminal.scrollHeight;
      }
    }

    async function deployFridaFromPoc(scriptType) {
      const dev = dastActiveDevice;
      if (!dev) {
        showToast('Connect a device first via Live DAST tab', 'error');
        return;
      }
      const pkg = document.getElementById('top-package-name')?.textContent || 'com.target.mobile.app';
      showToast(`Injecting Frida hook into ${pkg}...`, 'info');
      try {
        const res = await fetch('/api/dast/frida', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dev, package_name: pkg, script_type: scriptType || 'unpinning' })
        });
        const data = await res.json();
        showToast(`Frida: ${escapeHtml(String(data.status ?? ""))} — ${data.result?.message || 'Inspect result'}`, data.status === 'executed' ? 'success' : 'error');
      } catch (err) {
        showToast(`Frida deployment error: ${err}`, 'error');
      }
    }

    function askCopilotAboutFinding(findingId) {
      const f = (currentScan.findings || []).find(item => item.id === findingId);
      if (!f) return;
      const drawer = document.getElementById('copilot-drawer');
      if (drawer && drawer.classList.contains('translate-y-[520px]')) {
        toggleCopilotDrawer();
      }
      const prompt = `Analyze ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))}, CVSS ${escapeHtml(String(f.cvss_score))}) in component ${escapeHtml(String(f.affected_component ?? ""))}. Provide step-by-step reproduction and secure Kotlin remediation.`;
      askCopilotPrompt(prompt);
    }

    function inspectFinding(findingId) {
      selectedFindingId = findingId;
      const f = (currentScan.findings || []).find(item => item.id === findingId);
      if (!f) return;

      // Update badge
      const badge = document.getElementById('detail-status-badge');
      badge.textContent = f.status;
      badge.className = `px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
        f.status === 'CONFIRMED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
        f.status === 'FALSE_POSITIVE' ? 'bg-red-950 text-red-400 border border-red-800' :
        'bg-slate-800 text-slate-300 border border-slate-700'
      }`;

      const pocGuide = getOrGeneratePocGuide(f);
      const adbCmd = getOrGenerateAdbCommand(f);
      const fridaScript = getOrGenerateFridaScript(f);
      const proofEvidence = getOrGenerateProofEvidence(f);

      // Populate Djini.ai Exploit PoC Studio
      const detailContainer = document.getElementById('detail-content');
      detailContainer.innerHTML = `
        <!-- Finding Overview Header -->
        <div class="bg-card/70 p-3.5 rounded-xl border border-borderSubtle space-y-2">
          <div class="flex items-center justify-between">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
              f.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' :
              f.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' :
              'bg-amber-950 text-amber-400 border-amber-800'
            }">${escapeHtml(String(f.severity))}</span>
            <span class="text-xs font-mono text-slate-400 font-semibold">CVSS ${escapeHtml(String(f.cvss_score || 'N/A'))}</span>
          </div>
          <h4 class="text-sm font-semibold text-white leading-snug">${escapeHtml(f.title)}</h4>
          <div class="flex items-center gap-2 font-mono text-[11px] text-slate-400 flex-wrap">
            <span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">${escapeHtml(String(f.cwe_id || 'CWE'))}</span>
            <span>•</span>
            <span class="text-sky-300 truncate max-w-xs">${escapeHtml(f.affected_component || f.file_path || 'Application')}</span>
          </div>
          <p class="text-slate-300 text-xs leading-relaxed mt-1">${escapeHtml(f.description)}</p>
        </div>

        <!-- Exploit PoC Studio Navigation Tabs -->
        <div class="flex items-center gap-1 border-b border-borderSubtle pb-1 overflow-x-auto text-[11px] font-mono">
          <button id="subtab-btn-poc" data-onclick="static85" class="poc-subtab-btn px-2.5 py-1 rounded bg-sky-950 text-sky-400 border border-sky-800 flex items-center gap-1">
            <i data-lucide="zap" class="w-3 h-3 text-amber-400"></i> Step-by-Step PoC
          </button>
          <button id="subtab-btn-adb" data-onclick="static86" class="poc-subtab-btn px-2.5 py-1 rounded text-slate-400 hover:text-white flex items-center gap-1">
            <i data-lucide="terminal" class="w-3 h-3 text-emerald-400"></i> 1-Click ADB
          </button>
          <button id="subtab-btn-frida" data-onclick="static87" class="poc-subtab-btn px-2.5 py-1 rounded text-slate-400 hover:text-white flex items-center gap-1">
            <i data-lucide="code" class="w-3 h-3 text-purple-400"></i> Frida Hook
          </button>
          <button id="subtab-btn-proof" data-onclick="static88" class="poc-subtab-btn px-2.5 py-1 rounded text-slate-400 hover:text-white flex items-center gap-1">
            <i data-lucide="check-circle-2" class="w-3 h-3 text-cyan-400"></i> Proof Evidence
          </button>
          <button id="subtab-btn-ast" data-onclick="static89" class="poc-subtab-btn px-2.5 py-1 rounded text-slate-400 hover:text-white flex items-center gap-1">
            <i data-lucide="file-code" class="w-3 h-3 text-blue-400"></i> AST Code
          </button>
          <button id="subtab-btn-fix" data-onclick="static90" class="poc-subtab-btn px-2.5 py-1 rounded text-slate-400 hover:text-white flex items-center gap-1">
            <i data-lucide="wrench" class="w-3 h-3 text-sky-400"></i> Remediation
          </button>
        </div>

        <!-- Pane 1: Step-by-Step PoC (Markdown) -->
        <div id="poc-pane-poc" class="poc-tab-pane space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono uppercase text-slate-400 font-semibold flex items-center gap-1">
              <i data-lucide="file-text" class="w-3 h-3 text-amber-400"></i> Reproduction Guide
            </span>
            <button ${bindAction('click', () => copySnippet(pocGuide))} class="text-[10px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1">
              <i data-lucide="copy" class="w-3 h-3"></i> Copy Guide
            </button>
          </div>
          <div class="bg-card p-4 rounded-xl border border-borderSubtle text-xs leading-relaxed space-y-1">
            ${renderMarkdownSimple(pocGuide)}
          </div>
        </div>

        <!-- Pane 2: 1-Click ADB Verification -->
        <div id="poc-pane-adb" class="poc-tab-pane hidden space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono uppercase text-slate-400 font-semibold flex items-center gap-1">
              <i data-lucide="terminal" class="w-3 h-3 text-emerald-400"></i> Verification CLI Command
            </span>
            <div class="flex items-center gap-2">
              <button ${bindAction('click', () => copySnippet('adb shell ' + adbCmd))} class="px-2 py-0.5 rounded bg-slate-800 text-sky-400 hover:text-sky-300 text-[10px] font-mono flex items-center gap-1">
                <i data-lucide="copy" class="w-3 h-3"></i> Copy adb
              </button>
              <button ${bindAction('click', () => executeAdbFromPoc(adbCmd))} class="px-2.5 py-0.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-mono font-semibold flex items-center gap-1 shadow-sm transition">
                <i data-lucide="play" class="w-3 h-3"></i> ▶ Run on Device
              </button>
            </div>
          </div>
          <div class="bg-black/90 p-3 rounded-lg border border-borderSubtle font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap">
            <code>adb shell ${escapeHtml(adbCmd)}</code>
          </div>
          <div>
            <div class="flex items-center justify-between mb-1 text-[10px] font-mono text-slate-400">
              <span>Interactive Device Terminal Output:</span>
              <button data-onclick="static91" class="text-slate-500 hover:text-slate-300 text-[10px]">Clear</button>
            </div>
            <div id="poc-adb-terminal" class="bg-black border border-borderSubtle rounded-lg p-3 font-mono text-[10px] text-slate-300 h-36 overflow-y-auto whitespace-pre-wrap leading-relaxed shadow-inner">
              <span class="text-slate-500">// Device execution output will appear here when you click 'Run on Device'...</span>
            </div>
          </div>
        </div>

        <!-- Pane 3: Frida Hook Script -->
        <div id="poc-pane-frida" class="poc-tab-pane hidden space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono uppercase text-slate-400 font-semibold flex items-center gap-1">
              <i data-lucide="code" class="w-3 h-3 text-purple-400"></i> Dynamic Instrumentation Hook
            </span>
            <div class="flex items-center gap-2">
              <button ${bindAction('click', () => copySnippet(fridaScript))} class="px-2 py-0.5 rounded bg-slate-800 text-purple-300 hover:text-purple-200 text-[10px] font-mono flex items-center gap-1">
                <i data-lucide="copy" class="w-3 h-3"></i> Copy Script
              </button>
              <button data-onclick="static92" class="px-2.5 py-0.5 rounded bg-purple-600 hover:bg-purple-500 text-white text-[10px] font-mono font-semibold flex items-center gap-1 shadow-sm transition">
                <i data-lucide="play" class="w-3 h-3"></i> ▶ Check preset initialization
              </button>
            </div>
          </div>
          <div class="bg-black/90 p-3 rounded-lg border border-borderSubtle font-mono text-[11px] text-purple-300 overflow-x-auto whitespace-pre-wrap">
            <pre><code>${escapeHtml(fridaScript)}</code></pre>
          </div>
          <div class="text-[10px] font-mono text-slate-400 bg-card p-2 rounded-lg border border-borderSubtle">
            <span class="text-sky-400 font-semibold">CLI Command:</span> <code>frida -U -f ${escapeHtml(document.getElementById('top-package-name')?.textContent || 'com.target.mobile.app')} -l hook.js</code>
          </div>
        </div>

        <!-- Pane 4: Proof Evidence -->
        <div id="poc-pane-proof" class="poc-tab-pane hidden space-y-3">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono uppercase text-slate-400 font-semibold flex items-center gap-1">
              <i data-lucide="check-circle-2" class="w-3 h-3 text-cyan-400"></i> Validation notes
            </span>
            <span class="px-2 py-0.5 rounded text-[9px] font-mono uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">Analyst evidence</span>
          </div>
          <div class="bg-black/90 p-3.5 rounded-lg border border-borderSubtle font-mono text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
            <code>${escapeHtml(proofEvidence)}</code>
          </div>
          <p class="text-[11px] text-slate-400 font-sans">Generated scripts, static reachability and LLM votes do not establish runtime exploitation.</p>
        </div>

        <!-- Pane 5: AST Code Context -->
        <div id="poc-pane-ast" class="poc-tab-pane hidden space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono text-slate-400 uppercase">File: <span class="text-sky-400">${escapeHtml(f.file_path || 'Source')}</span> (Line ${escapeHtml(String(f.line_number || 'N/A'))})</span>
            <button ${bindAction('click', () => copySnippet(f.code_snippet || ''))} class="text-[10px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1">
              <i data-lucide="copy" class="w-3 h-3"></i> Copy Code
            </button>
          </div>
          <div class="bg-black/90 p-3 rounded-lg border border-borderSubtle font-mono text-[11px] text-amber-300 overflow-x-auto whitespace-pre-wrap">
            <pre><code>${escapeHtml(f.code_snippet || 'No snippet available')}</code></pre>
          </div>
        </div>

        <!-- Pane 6: Remediation Guidance -->
        <div id="poc-pane-fix" class="poc-tab-pane hidden space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono text-slate-400 uppercase block">Developer Security Guidance</span>
            <button ${bindAction('click', () => askCopilotAboutFinding(f.id))} class="text-[10px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1">
              <i data-lucide="sparkles" class="w-3 h-3"></i> Refine in Copilot
            </button>
          </div>
          <div class="bg-card p-3.5 rounded-lg border border-borderSubtle text-slate-200 text-xs leading-relaxed space-y-2">
            <div>${escapeHtml(f.remediation || 'Follow OWASP Mobile Security verification criteria.')}</div>
            <div class="pt-2 border-t border-borderSubtle text-[11px] font-mono text-slate-400">
              Standard: <span class="text-emerald-400">${escapeHtml(String(f.owasp_masvs || 'MASVS-PLATFORM-1'))}</span>
            </div>
          </div>
        </div>

        <!-- Triage & Co-Pilot Action Bar -->
        <div class="pt-4 border-t border-borderSubtle flex items-center justify-between gap-2">
          <button ${bindAction('click', () => askCopilotAboutFinding(f.id))} class="px-2.5 py-1.5 rounded bg-sky-950/80 hover:bg-sky-900 text-sky-300 border border-sky-800 text-xs font-mono flex items-center gap-1.5 transition">
            <i data-lucide="sparkles" class="w-3.5 h-3.5 text-sky-400"></i> Copilot Deep Dive
          </button>
          <div class="flex items-center gap-2">
            <button ${bindAction('click', () => submitTriage(f.id, 'CONFIRMED'))} class="px-3 py-1.5 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-xs font-mono transition flex items-center gap-1">
              <i data-lucide="check" class="w-3 h-3"></i> Confirm TP
            </button>
            <button ${bindAction('click', () => submitTriage(f.id, 'FALSE_POSITIVE'))} class="px-3 py-1.5 rounded bg-red-950 hover:bg-red-900 text-red-300 border border-red-800 text-xs font-mono transition flex items-center gap-1">
              <i data-lucide="x" class="w-3 h-3"></i> False Positive
            </button>
          </div>
        </div>
      `;

      switchFindingSubTab(currentFindingSubTab || 'poc');
      window.lucide?.createIcons();
    }

    async function submitTriage(findingId, verdict) {
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(currentScan.scan_id)}/findings/${encodeURIComponent(findingId)}/feedback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verdict, revision: currentScan.revision || 0, notes: verdict === 'CONFIRMED' ? (window.prompt('Describe the reproduced impact, prerequisites and evidence:') || '') : '' })
        });
        const data = await res.json();

        currentScan.revision = data.revision;
        // Update local memory only after durable server acknowledgement.
        const f = (currentScan.findings || []).find(item => item.id === findingId);
        if (f) f.status = verdict;

        inspectFinding(findingId);
        applyFindingsFilter();
        showToast(`Triage recorded: ${verdict}`, 'success');
      } catch (err) {
        showToast('Error recording triage feedback', 'error');
      }
    }

    async function submitTriageVerdict(findingId, verdict) {
      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(currentScan.scan_id)}/findings/${encodeURIComponent(findingId)}/feedback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verdict, revision: currentScan.revision || 0, notes: verdict === 'CONFIRMED' ? (window.prompt('Describe the reproduced impact, prerequisites and evidence:') || '') : '' })
        });

        currentScan.revision = (await response.json()).revision;
        const df = dastFindings.find(item => item.id === findingId);
        if (df) df.status = verdict;

        if (currentScan && currentScan.findings) {
          const sf = currentScan.findings.find(item => item.id === findingId);
          if (sf) sf.status = verdict;
        }

        renderDastFindings();
        showToast(`DAST Triage updated: ${verdict}`, 'success');
      } catch (err) {
        showToast('Error recording triage verdict', 'error');
      }
    }

    async function copySnippet(text) {
      try {
        await navigator.clipboard.writeText(String(text));
        showToast('Text copied to clipboard', 'success');
      } catch (error) {
        showToast('Clipboard unavailable; select and copy the displayed text.', 'error');
      }
    }

    // Scans History View
    async function loadScansView() {
      const tbody = document.getElementById('scans-table-body');
      tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-slate-500">Loading scan history...</td></tr>';

      try {
        const res = await fetch('/api/scans?limit=25&summaries=true');
        const page = await res.json();
        const list = page.items;
        tbody.innerHTML = '';

        list.forEach(s => {
          const tr = document.createElement('tr');
          tr.className = 'hover:bg-card/50 transition';
          tr.innerHTML = `
            <td class="py-3 px-4 text-sky-400 font-bold">${escapeHtml(s.scan_id)}</td>
            <td class="py-3 px-4">${escapeHtml(String(s.package_name || s.app_name))}</td>
            <td class="py-3 px-4 text-slate-400">${escapeHtml(String(s.created_at || 'Just now'))}</td>
            <td class="py-3 px-4">
              <span class="px-2 py-0.5 rounded text-[10px] ${s.status === 'completed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-sky-950 text-sky-400 border border-sky-800'}">
                ${escapeHtml(String(s.status.toUpperCase()))}
              </span>
            </td>
            <td class="py-3 px-4">
              <span class="text-red-400">${s.stats.critical || 0} Crit</span> •
              <span class="text-orange-400">${s.stats.high || 0} High</span> •
              <span class="text-yellow-400">${s.stats.medium || 0} Med</span>
            </td>
            <td class="py-3 px-4 text-right">
              <button ${bindAction('click', () => loadSpecificScan(s.scan_id))} class="px-2.5 py-1 rounded bg-card hover:bg-slate-700 border border-borderSubtle text-slate-300 text-[11px]">
                Open
              </button>
            </td>
          `;
          tbody.appendChild(tr);
        });
      } catch (err) {
        tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-red-400">Failed to load scans.</td></tr>';
      }
    }

    async function loadSpecificScan(scanId) {
      try {
        const res = await fetch(`/api/scans/${scanId}`);
        currentScan = await res.json();
        selectedFindingId = null;
        selectedApiId = null;
        switchView('surface');
        renderDashboard(currentScan);
        showToast(`Loaded target: ${currentScan.package_name || currentScan.app_name}`, 'success');
      } catch (e) {
        showToast('Error loading scan details', 'error');
      }
    }

    // Agents View
    async function loadAgentsView() {
      const grid = document.getElementById('agents-grid');
      grid.innerHTML = '<div class="col-span-2 text-center py-10 text-slate-500 font-mono text-xs">Loading agents...</div>';

      try {
        const res = await fetch('/api/agents');
        const list = await res.json();
        grid.innerHTML = '';

        list.forEach(a => {
          const card = document.createElement('div');
          card.className = 'bg-panel border border-borderSubtle rounded-xl p-4 flex flex-col justify-between space-y-3';
          card.innerHTML = `
            <div>
              <div class="flex items-center justify-between mb-1.5">
                <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 uppercase">${escapeHtml(String(a.category || 'Scan capability'))}</span>
                <span class="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                  <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span> ${escapeHtml(String(a.status))}
                </span>
              </div>
              <h4 class="text-xs font-semibold text-white">${escapeHtml(String(a.name))}</h4>
              <p class="text-[11px] text-slate-400 mt-1">${escapeHtml(String(a.description))}</p>
            </div>

            <div class="pt-2 border-t border-borderSubtle flex items-center justify-between text-[11px] font-mono text-slate-400">
              <div>
                <span>Findings: <strong class="text-white">${escapeHtml(String(a.findings_count ?? 'Not measured'))}</strong></span> •
                <span>Runtime: <strong class="text-slate-300">${escapeHtml(String(a.last_runtime ?? 'Not measured'))}</strong></span>
              </div>
              <button disabled title="Individual execution is not implemented" class="px-2 py-1 rounded bg-card hover:bg-slate-700 border border-borderSubtle text-sky-400 text-[10px]">
                Capability only
              </button>
            </div>
          `;
          grid.appendChild(card);
        });
      } catch (e) {
        grid.innerHTML = '<div class="col-span-2 text-center text-red-400 font-mono text-xs">Failed to load agent metadata.</div>';
      }
    }

    function runSingleAgent(agentId) {
      showToast('Individual agent execution is not implemented. Start a full scan instead.', 'info');
    }

    function triggerAllAgents() {
      openNewScanModal();
    }

    // Settings View
    async function loadSettingsView() {
      try {
        const res = await fetch('/api/settings');
        const cfg = await res.json();
        if (cfg.llm_primary_provider) document.getElementById('cfg-llm-primary').value = cfg.llm_primary_provider;
        if (cfg.llm_fallback_provider) document.getElementById('cfg-llm-fallback').value = cfg.llm_fallback_provider;
        if (cfg.offline !== undefined) document.getElementById('cfg-offline').checked = cfg.offline;
        if (cfg.entropy_threshold !== undefined) document.getElementById('cfg-entropy').value = cfg.entropy_threshold;
        if (cfg.neo4j_uri) document.getElementById('cfg-neo4j-uri').value = cfg.neo4j_uri;
        if (cfg.enable_deep_taint !== undefined) document.getElementById('cfg-deep-taint').checked = cfg.enable_deep_taint;
        if (cfg.enable_reachability_filter !== undefined) document.getElementById('cfg-reachability').checked = cfg.enable_reachability_filter;
        if (cfg.enable_consensus_voting !== undefined) document.getElementById('cfg-consensus').checked = cfg.enable_consensus_voting;
      } catch (e) {
        console.warn('Error loading settings:', e);
      }
    }

    async function saveSettingsForm() {
      const payload = {
        offline: document.getElementById('cfg-offline').checked,
        entropy_threshold: parseFloat(document.getElementById('cfg-entropy').value),
        enable_deep_taint: document.getElementById('cfg-deep-taint').checked,
        enable_reachability_filter: document.getElementById('cfg-reachability').checked,
        enable_consensus_voting: document.getElementById('cfg-consensus').checked,
      };
      try {
        await fetch('/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        await loadPrivacyPolicy();
        showToast('Settings saved for new scans', 'success');
      } catch (err) {
        showToast('Failed to save settings', 'error');
      }
    }

    // Copilot Slide-Over Drawer
    function toggleCopilotDrawer() {
      copilotOpen = !copilotOpen;
      const drawer = document.getElementById('copilot-drawer');
      const chevron = document.getElementById('copilot-chevron');
      if (copilotOpen) {
        drawer.classList.remove('translate-y-[520px]');
        chevron.style.transform = 'rotate(180deg)';
      } else {
        drawer.classList.add('translate-y-[520px]');
        chevron.style.transform = 'rotate(0deg)';
      }
    }

    function askCopilotPrompt(promptText) {
      document.getElementById('copilot-chat-input').value = promptText;
      sendCopilotChat();
    }

    function askCopilotActivePoc() {
      const f = (currentScan && currentScan.findings && selectedFindingId)
        ? currentScan.findings.find(item => item.id === selectedFindingId)
        : (currentScan && currentScan.findings ? currentScan.findings[0] : null);
      if (f) {
        askCopilotPrompt(`Generate a step-by-step PoC reproduction guide for ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))}) in ${escapeHtml(String(f.affected_component ?? ""))}`);
      } else {
        askCopilotPrompt('Generate step-by-step reproduction PoC for the critical findings in this application');
      }
    }

    function askCopilotActiveAdb() {
      const f = (currentScan && currentScan.findings && selectedFindingId)
        ? currentScan.findings.find(item => item.id === selectedFindingId)
        : (currentScan && currentScan.findings ? currentScan.findings[0] : null);
      if (f) {
        askCopilotPrompt(`Provide the exact copy-pasteable adb verification command for ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))})`);
      } else {
        askCopilotPrompt('Give me adb commands to trigger and test exported activities');
      }
    }

    function askCopilotActiveFrida() {
      const f = (currentScan && currentScan.findings && selectedFindingId)
        ? currentScan.findings.find(item => item.id === selectedFindingId)
        : (currentScan && currentScan.findings ? currentScan.findings[0] : null);
      if (f) {
        askCopilotPrompt(`Write a production-grade Frida hook script to verify or bypass ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))})`);
      } else {
        askCopilotPrompt('Generate a universal Frida script for SSL unpinning and root bypass');
      }
    }

    function askCopilotActiveFix() {
      const f = (currentScan && currentScan.findings && selectedFindingId)
        ? currentScan.findings.find(item => item.id === selectedFindingId)
        : (currentScan && currentScan.findings ? currentScan.findings[0] : null);
      if (f) {
        askCopilotPrompt(`Show the secure Kotlin / AndroidManifest remediation diff to fix ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))})`);
      } else {
        askCopilotPrompt('Show secure coding guidelines for Android exported components and WebViews');
      }
    }

    function askCopilotBountyReport() {
      const f = (currentScan && currentScan.findings && selectedFindingId)
        ? currentScan.findings.find(item => item.id === selectedFindingId)
        : (currentScan && currentScan.findings ? currentScan.findings[0] : null);
      if (f) {
        askCopilotPrompt(`Draft a professional HackerOne / Bugcrowd bug bounty submission for ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))}, CVSS ${escapeHtml(String(f.cvss_score))}) with steps to reproduce and impact assessment.`);
      } else {
        askCopilotPrompt('Format the top findings into a professional Bug Bounty submission draft');
      }
    }

    async function sendCopilotChat() {
      const input = document.getElementById('copilot-chat-input');
      const text = input.value.trim();
      if (!text) return;
      input.value = '';

      const container = document.getElementById('copilot-messages');
      // User bubble
      const userBubble = document.createElement('div');
      userBubble.className = 'bg-sky-950/50 p-2.5 rounded-lg border border-sky-800 text-sky-200 text-right';
      userBubble.textContent = text;
      container.appendChild(userBubble);

      // Assistant thinking bubble
      const assistantBubble = document.createElement('div');
      assistantBubble.className = 'bg-card p-3 rounded-lg border border-borderSubtle text-slate-300 space-y-1';
      assistantBubble.innerHTML = '<span class="animate-pulse text-sky-400 font-mono text-[10px]">Analyzing codebase & findings...</span>';
      container.appendChild(assistantBubble);
      container.scrollTop = container.scrollHeight;

      try {
        const res = await fetch('/api/copilot', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prompt: text, scan_id: currentScan?.scan_id })
        });
        const data = await res.json();
        assistantBubble.innerHTML = formatMarkdownToHtml(data.response);
      } catch (err) {
        assistantBubble.innerHTML = '<span class="text-red-400">Failed to connect to Copilot engine.</span>';
      }
      container.scrollTop = container.scrollHeight;
    }

    function formatMarkdownToHtml(md) {
      // Basic markdown processor
      return escapeHtml(String(md))
        .replace(/^### (.*$)/gim, '<h4 class="font-bold text-white text-xs mb-1">$1</h4>')
        .replace(/\*\*(.*?)\*\*/gim, '<strong class="text-white">$1</strong>')
        .replace(/\*(.*?)\*/gim, '<em class="text-slate-300">$1</em>')
        .replace(/`([^`]+)`/gim, '<code class="px-1 py-0.5 rounded bg-appbg text-sky-300 font-mono text-[11px]">$1</code>')
        .replace(/```([a-z]*)\n([\s\S]*?)```/gim, '<pre class="bg-appbg p-2.5 rounded border border-borderSubtle font-mono text-[11px] text-sky-300 overflow-x-auto my-1.5"><code>$2</code></pre>')
        .replace(/\n/gim, '<br/>');
    }

    // Modal, Drag & Drop, and Scan Launching
    function openNewScanModal() { document.getElementById('scan-modal').classList.remove('hidden'); }
    function closeNewScanModal() { document.getElementById('scan-modal').classList.add('hidden'); }

    function handleDragOver(e) {
      e.preventDefault();
      e.stopPropagation();
      e.currentTarget.classList.add('border-sky-400', 'bg-sky-950/40');
    }

    function handleDragLeave(e) {
      e.preventDefault();
      e.stopPropagation();
      e.currentTarget.classList.remove('border-sky-400', 'bg-sky-950/40');
    }

    function handleDrop(e, autoRun = false) {
      e.preventDefault();
      e.stopPropagation();
      e.currentTarget.classList.remove('border-sky-400', 'bg-sky-950/40');
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        uploadApkFile(files[0], autoRun);
      }
    }

    function triggerQuickUpload() {
      const input = document.getElementById('quick-file-input-surface');
      if (input) input.click();
    }

    function triggerModalUpload() {
      const input = document.getElementById('modal-file-picker');
      if (input) input.click();
    }

    function handleQuickFileInput(e) {
      const file = e.target.files?.[0];
      if (file) {
        uploadApkFile(file, true);
      }
      e.target.value = '';
    }

    function handleModalFileInput(e) {
      const file = e.target.files?.[0];
      if (file) {
        uploadApkFile(file, false);
      }
      e.target.value = '';
    }

    async function uploadApkFile(file, autoRunAfterUpload = false) {
      if (!file) return;
      if (!file.name.toLowerCase().endsWith('.apk') && !file.name.toLowerCase().endsWith('.ipa') && !file.name.toLowerCase().endsWith('.zip')) {
        showToast('Please upload an .apk or .ipa file', 'error');
        return;
      }

      showToast(`Uploading ${file.name}...`, 'info');
      const spinner = document.getElementById('quick-upload-spinner-surface');
      if (spinner) spinner.classList.remove('hidden');

      const formData = new FormData();
      formData.append('file', file);

      try {
        const res = await fetch('/api/upload/apk', {
          method: 'POST',
          body: formData
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Upload failed');
        }

        showToast(`Uploaded ${escapeHtml(String(data.filename ?? ""))} (${escapeHtml(String(data.size_mb ?? ""))} MB)`, 'success');

        // Populate modal input
        const modalInput = document.getElementById('modal-apk-input');
        if (modalInput) modalInput.value = data.file_path;

        const modalUploadStatus = document.getElementById('modal-upload-status');
        if (modalUploadStatus) {
          modalUploadStatus.innerHTML = `
            <div class="flex items-center justify-between p-2 rounded bg-emerald-950/40 border border-emerald-800 text-emerald-300 text-[11px]">
              <span class="flex items-center gap-1.5"><i data-lucide="check-circle" class="w-3.5 h-3.5"></i> ${escapeHtml(data.filename)} (${escapeHtml(String(data.size_mb ?? ""))} MB)</span>
              <span class="font-semibold text-emerald-400">Ready</span>
            </div>
          `;
          window.lucide?.createIcons();
        }

        if (autoRunAfterUpload) {
          showToast('Triggering autonomous full-spectrum pipeline...', 'info');
          const runRes = await fetch('/api/scans/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              apk_path: data.file_path,
              auto_dast: false,
              auto_taint: true,
              bypass_root: false,
              bypass_ssl: false,
              serial: dastActiveDevice
            })
          });
          const runData = await runRes.json();
          showToast(`Autonomous pipeline active: ${runData.scan_id}`, 'success');
          await loadSpecificScan(runData.scan_id);
        }
      } catch (err) {
        showToast(err.message || 'Upload error', 'error');
      } finally {
        if (spinner) spinner.classList.add('hidden');
      }
    }

    async function submitNewScan() {
      const apkPath = document.getElementById('modal-apk-input')?.value.trim();
      if (!apkPath) {
        showToast('Please upload or specify target APK path', 'error');
        return;
      }
      const autoDast = document.getElementById('modal-opt-auto-dast')?.checked ?? false;
      const autoTaint = document.getElementById('modal-opt-taint')?.checked ?? true;
      const bypassRoot = document.getElementById('modal-opt-bypass-root')?.checked ?? false;
      const bypassSsl = document.getElementById('modal-opt-bypass-ssl')?.checked ?? false;

      closeNewScanModal();
      showToast('Starting configured scoped analysis...', 'info');

      try {
        const res = await fetch('/api/scans/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            apk_path: apkPath,
            auto_dast: autoDast,
            auto_taint: autoTaint,
            bypass_root: bypassRoot,
            bypass_ssl: bypassSsl,
            serial: dastActiveDevice
          })
        });
        const data = await res.json();
        showToast(`Scan launched: ${escapeHtml(String(data.scan_id ?? ""))}`, 'success');
        await loadSpecificScan(data.scan_id);
      } catch (err) {
        showToast('Failed to start scan', 'error');
      }
    }

    // Global window Drag & Drop listener
    window.addEventListener('dragover', (e) => {
      e.preventDefault();
    });
    window.addEventListener('drop', (e) => {
      if (!e.defaultPrevented && e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        const file = e.dataTransfer.files[0];
        if (file.name.toLowerCase().endsWith('.apk') || file.name.toLowerCase().endsWith('.ipa') || file.name.toLowerCase().endsWith('.zip')) {
          e.preventDefault();
          uploadApkFile(file, true);
        }
      }
    });

    // Export Reports
    function toggleExportMenu() {
      const menu = document.getElementById('export-dropdown');
      menu.classList.toggle('hidden');
    }

    function exportReportJSON() {
      toggleExportMenu();
      if (!currentScan) return;
      const blob = new Blob([JSON.stringify(currentScan, null, 2)], { type: 'application/json' });
      downloadBlob(blob, `mobileag_report_${currentScan.scan_id || 'export'}.json`);
      showToast('JSON report exported successfully', 'success');
    }

    function exportReportMarkdown() {
      toggleExportMenu();
      if (!currentScan) return;
      let md = `# MobileAg Security Audit Report\n\nTarget: ${currentScan.package_name}\nDate: ${currentScan.created_at}\n\n## Findings\n\n`;
      (currentScan.findings || []).forEach(f => {
        md += `### [${escapeHtml(String(f.severity))}] ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))})\n`;
        md += `- CVSS Score: ${escapeHtml(String(f.cvss_score))}\n`;
        md += `- Affected Component: ${escapeHtml(String(f.affected_component ?? ""))}\n`;
        md += `- Description: ${escapeHtml(String(f.description ?? ""))}\n`;
        md += `- Remediation: ${escapeHtml(String(f.remediation ?? ""))}\n\n`;
      });
      const blob = new Blob([md], { type: 'text/markdown' });
      downloadBlob(blob, `mobileag_report_${currentScan.scan_id || 'export'}.md`);
      showToast('Markdown report exported successfully', 'success');
    }

    async function exportReportSARIF() {
      toggleExportMenu();
      if (!currentScan) return;
      try {
        const scanId = currentScan.scan_id || 'scan_meesho_demo';
        const res = await fetch(`/api/scans/${scanId}/sarif`);
        const sarifData = await res.json();
        const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: 'application/json' });
        downloadBlob(blob, `mobileag_report_${scanId}.sarif`);
        showToast('SARIF v2.1.0 exported successfully', 'success');
      } catch (err) {
        showToast('Error exporting SARIF report', 'error');
      }
    }

    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }

    // Live Telemetry WebSocket
    function connectTelemetryWebSocket() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

      try {
        wsConnection = new WebSocket(wsUrl);

        wsConnection.onopen = function() {
          wsConnection.send(JSON.stringify({token: accessToken}));
          const wsLabel = document.getElementById('sidebar-ws-status');
          if (wsLabel) wsLabel.textContent = 'Live Connected';
        };

        wsConnection.onmessage = function(event) {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'scan_complete') {
              if (currentScan && currentScan.scan_id === data.scan_id) loadSpecificScan(data.scan_id);
            } else if (data.type === 'agent_progress') {
              handleLiveEvent(data);
            } else if (data.type === 'dast_progress' || data.type === 'dast_finding') {
              handleDastLiveEvent(data);
            }
          } catch (e) {
            console.warn('WS parse error:', e);
          }
        };


        wsConnection.onclose = function() {
          const wsLabel = document.getElementById('sidebar-ws-status');
          if (wsLabel) wsLabel.textContent = 'Reconnecting...';
          setTimeout(connectTelemetryWebSocket, 3000);
        };
      } catch (e) {
        console.warn('WebSocket init failed:', e);
      }
    }

    function handleLiveEvent(data) {
      // Prepend to agent telemetry feed
      const feed = document.getElementById('agent-telemetry-feed');
      if (feed) {
        const item = document.createElement('div');
        item.className = 'flex items-center justify-between p-2 rounded-lg bg-sky-950/40 border border-sky-800/40';
        item.innerHTML = `
          <div class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 rounded-full bg-sky-400 animate-ping"></span>
            <span class="font-mono font-medium text-sky-300 text-xs">${escapeHtml(String(data.stage))}</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-[11px] font-mono text-slate-300">${escapeHtml(String(data.message.substring(0, 36)))}...</span>
            <span class="px-1.5 py-0.2 rounded text-[9px] font-mono uppercase bg-sky-950 text-sky-400 border border-sky-800">${escapeHtml(String(data.progress ?? ""))}%</span>
          </div>
        `;
        feed.insertBefore(item, feed.firstChild);
      }

      // App metadata update if supplied
      if (data.app_info) {
        if (data.app_info.package_name) {
          const el = document.getElementById('top-package-name');
          if (el) el.textContent = data.app_info.package_name;
          if (currentScan) currentScan.package_name = data.app_info.package_name;
        }
        if (data.app_info.framework) {
          const el = document.getElementById('top-framework');
          if (el) el.textContent = data.app_info.framework;
          if (currentScan) currentScan.framework = data.app_info.framework;
        }
        if (data.app_info.obfuscation_level) {
          const el = document.getElementById('top-obfuscation');
          if (el) el.textContent = data.app_info.obfuscation_level;
          if (currentScan) currentScan.obfuscation_level = data.app_info.obfuscation_level;
        }
      }

      // Live finding append
      if (data.finding && currentScan) {
        currentScan.findings = currentScan.findings || [];
        if (!currentScan.findings.some(f => f.id === data.finding.id || f.title === data.finding.title)) {
          currentScan.findings.unshift(data.finding);
        }
        const totalCount = currentScan.findings.length;
        const kpiTotal = document.getElementById('kpi-total');
        if (kpiTotal) kpiTotal.textContent = totalCount;
        const navCount = document.getElementById('nav-findings-count');
        if (navCount) navCount.textContent = totalCount;

        const critHigh = currentScan.findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH').length;
        const medLow = currentScan.findings.filter(f => f.severity === 'MEDIUM' || f.severity === 'LOW').length;
        const critHighEl = document.getElementById('kpi-critical-high');
        if (critHighEl) critHighEl.textContent = critHigh;
        const medLowEl = document.getElementById('kpi-med-low');
        if (medLowEl) medLowEl.textContent = medLow;

        if (activeView === 'findings') applyFindingsFilter();
        showToast(`Discovered: ${escapeHtml(String(data.finding.title ?? ""))}`, 'info');
      }

      // Live graph node
      if (data.graph_node && visNodes) {
        if (!visNodes.get(data.graph_node.id)) visNodes.add(data.graph_node);
        if (data.graph_edge && visEdges) visEdges.add(data.graph_edge);
      }
    }

    async function checkGraphStatus() {
      try {
        const res = await fetch('/api/graph/status');
        const data = await res.json();
        const el = document.getElementById('sidebar-neo4j-status');
        if (el) {
          el.textContent = data.neo4j_connected ? 'Connected' : 'Embedded';
          el.className = data.neo4j_connected ? 'text-sky-400 font-bold' : 'text-slate-300';
        }
      } catch (e) {
        console.warn('Graph status check failed:', e);
      }
    }

    // =========================================================================
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

    async function refreshDastDevices() {
      try {
        const res = await fetch('/api/dast/devices');
        const data = await res.json();
        dastDevices = data.devices || [];

        // Update badge and indicator
        const badge = document.getElementById('nav-dast-device-badge');
        if (badge) badge.textContent = `${dastDevices.length} Devs`;

        const fleetCount = document.getElementById('dast-fleet-count');
        if (fleetCount) fleetCount.textContent = `${dastDevices.length} Connected`;

        const adbIndicator = document.getElementById('dast-adb-indicator');
        if (adbIndicator) {
          if (data.adb_available) {
            adbIndicator.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950/60 border border-emerald-800 text-emerald-400 flex items-center gap-1.5';
            adbIndicator.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> ADB Ready';
          } else {
            adbIndicator.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-950/60 border border-amber-800 text-amber-400 flex items-center gap-1.5';
            adbIndicator.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400"></span> ADB Offline';
          }
        }

        // Update header BYOD device status bar (Djini.ai style)
        const headerDevSelect = document.getElementById('header-device-select');
        if (headerDevSelect) {
          if (dastDevices.length === 0) {
            headerDevSelect.innerHTML = '<option value="">No Active Device</option>';
          } else {
            headerDevSelect.innerHTML = '<option value="">Select an authorized device</option>' + dastDevices.filter(d => d.allowed).map(d =>
              `<option value="${escapeHtml(String(d.serial))}" ${d.serial === dastActiveDevice ? 'selected' : ''}>${escapeHtml(d.model)} (${escapeHtml(String(d.serial))})</option>`
            ).join('');
          }
        }
        const headerRootBadge = document.getElementById('header-root-badge');
        if (headerRootBadge) {
          const activeDev = dastDevices.find(d => d.serial === dastActiveDevice);
          if (activeDev && activeDev.is_rooted) {
            headerRootBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800';
            headerRootBadge.innerHTML = '● Root diagnostic';
          } else if (activeDev) {
            headerRootBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700';
            headerRootBadge.innerHTML = '○ Unrooted (Shell)';
          } else {
            headerRootBadge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-500 border border-slate-800';
            headerRootBadge.innerHTML = 'No Device';
          }
        }

        renderDastDeviceFleet();

        // Selection must be explicit and still in scope after every refresh.
        if (!dastDevices.some(d => d.serial === dastActiveDevice && d.allowed)) dastActiveDevice = null;
      } catch (e) {
        console.warn('Error fetching DAST devices:', e);
        showToast('Error refreshing ADB devices', 'error');
      }
    }

    async function deployFridaScriptQuick(scriptType) {
      const dev = dastActiveDevice;
      if (!dev) {
        showToast('Connect an ADB device first via Live DAST tab', 'error');
        return;
      }
      const pkg = document.getElementById('top-package-name')?.textContent || 'com.target.mobile.app';
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
            <p class="text-[11px] text-slate-500">Start your rooted emulator (AVD, Genymotion, or Corellium) and click below or connect via TCP.</p>
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
        const rootBadge = dev.is_rooted
          ? `<span class="px-1.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-700 text-[10px] font-mono text-emerald-300 font-semibold flex items-center gap-1">
               <span class="w-1 h-1 rounded-full bg-emerald-400"></span> # ROOT (uid=0)
             </span>`
          : `<span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] font-mono text-slate-400">Shell (non-root)</span>`;

        return `
          <div ${bindAction('click', () => selectDastDevice(dev.serial))} class="p-3 rounded-lg border cursor-pointer transition ${
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
          </div>
        `;
      }).join('');

      window.lucide?.createIcons();
    }

    function selectDastDevice(serial) {
      if (!dastDevices.some(d => d.serial === serial && d.allowed)) {
        dastActiveDevice = null;
        showToast('Select an explicitly authorized device.', 'error');
        return;
      }
      dastActiveDevice = serial;
      const select = document.getElementById('header-device-select');
      if (select) select.value = serial;
      const label = document.getElementById('dast-active-target-label');
      if (label) label.textContent = serial;
      renderDastDeviceFleet();
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

      showToast(`Installing ${apkPath} with runtime permissions (-g)...`, 'info');
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
          body: JSON.stringify({ serial: dastActiveDevice, uri: uri }),
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
            No dynamic runtime vulnerabilities recorded yet. Launch intent fuzzing to discover unhandled crashes or token leaks.
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

    async function checkFridaServerStatus() {
      if (!dastActiveDevice) {
        showToast('Select a device first', 'error');
        return;
      }
      const badge = document.getElementById('frida-status-badge');
      if (badge) {
        badge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse"></span> Checking...';
      }
      try {
        const res = await fetch('/api/dast/frida', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ serial: dastActiveDevice, package_name: 'com.android.systemui', script_type: 'unpinning' }),
        });
        const data = await res.json();
        const isRunning = data.result && data.result.frida_server_running;
        if (badge) {
          if (isRunning) {
            badge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-950/60 border border-emerald-800 text-emerald-300 flex items-center gap-1.5';
            badge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> frida-server Online';
            showToast('frida-server verified running on target device', 'success');
          } else {
            badge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-purple-950/60 border border-purple-800 text-purple-300 flex items-center gap-1.5';
            badge.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-purple-400"></span> Script Generator Ready';
            showToast('Frida payload generator ready (frida-server daemon idle)', 'info');
          }
        }
      } catch (e) {
        showToast(`Frida check notice: ${e}`, 'info');
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
          const res = await fetch('/api/dast/frida', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ serial: dastActiveDevice || 'preview', package_name: pkg, script_type: scriptType }),
          });
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
    // 5. Static Taint & Dataflow Studio
    // =========================================================================
    const TAINT_SAMPLES = {
      uxss: `package com.target.app;

import android.content.Intent;
import android.os.Bundle;
import android.webkit.WebView;
import androidx.appcompat.app.AppCompatActivity;

public class VulnerableWebActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web);

        WebView webView = findViewById(R.id.webview);
        webView.getSettings().setJavaScriptEnabled(true);

        // Untrusted source: Intent extra string
        String targetUrl = getIntent().getStringExtra("target_url");

        // Intermediate variable propagation
        String validatedUrl = targetUrl;

        // Critical Sink: Unvalidated WebView URL execution (CWE-749 UXSS)
        webView.loadUrl(validatedUrl);
    }
}`,
      sqli: `package com.target.app;

import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;

public class InsecureDatabaseHandler {
    public void queryUserRecords(Intent incoming, SQLiteDatabase db) {
        // Untrusted source: Intent query parameter
        String searchFilter = incoming.getStringExtra("search_query");

        // Intermediate tainted propagation
        String sqlQuery = "SELECT * FROM accounts WHERE username = '" + searchFilter + "'";

        // Critical Sink: Unparameterized SQL Query (CWE-89 SQLi)
        db.rawQuery(sqlQuery, null);
    }
}`,
      redirect: `package com.target.app;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class InsecureProxyActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Untrusted source: arbitrary parcelable Intent from untrusted caller
        Intent forwardedIntent = (Intent) getIntent().getParcelableExtra("extra_intent");

        // Critical Sink: Arbitrary IPC Intent Redirection (CWE-927)
        startActivity(forwardedIntent);
    }
}`,
      traversal: `package com.target.app;

import android.content.Intent;
import java.io.File;
import java.io.FileInputStream;

public class FileViewerActivity {
    public void openSharedDocument(Intent intent) {
        // Untrusted source: deep link query parameter
        String filename = intent.getData().getQueryParameter("filepath");

        // Critical Sink: Arbitrary File Access (CWE-22 Path Traversal)
        File targetFile = new File("/data/data/com.target.app/files/", filename);
        openFileInput(targetFile.getName());
    }
}`,
      command: `package com.target.app;

import android.content.Intent;

public class DiagnosticHandler {
    public void executePing(Intent intent) throws Exception {
        // Untrusted source: network host string from intent
        String host = intent.getStringExtra("ping_host");

        // Critical Sink: Command Injection (CWE-78)
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}`
    };

    function loadTaintView() {
      const input = document.getElementById('taint-source-input');
      const lineCounter = document.getElementById('taint-line-count');
      if (input && !input.dataset.listenerBound) {
        input.dataset.listenerBound = 'true';
        input.addEventListener('input', () => {
          if (lineCounter) lineCounter.textContent = input.value.split('\n').length;
        });
      }
      if (input && !input.value.trim()) {
        loadSelectedTaintSample('uxss');
      }
    }

    function loadSelectedTaintSample(overrideType) {
      const selector = document.getElementById('taint-sample-selector');
      const input = document.getElementById('taint-source-input');
      const lineCounter = document.getElementById('taint-line-count');
      const type = overrideType || (selector ? selector.value : 'uxss');

      if (selector && overrideType) selector.value = overrideType;

      if (type === 'clear') {
        if (input) input.value = '';
        if (lineCounter) lineCounter.textContent = '0';
        return;
      }

      if (input && TAINT_SAMPLES[type]) {
        input.value = TAINT_SAMPLES[type];
        if (lineCounter) lineCounter.textContent = input.value.split('\n').length;
      }
    }

    async function runTaintAnalysis() {
      const input = document.getElementById('taint-source-input');
      const filePathInput = document.getElementById('taint-file-path');
      const btn = document.getElementById('btn-run-taint');
      const code = input ? input.value : '';
      const filePath = filePathInput ? filePathInput.value.trim() : 'VulnerableActivity.java';

      if (!code.trim()) {
        showToast('Please paste or select source code to analyze', 'error');
        return;
      }

      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="w-3 h-3 rounded-full bg-white animate-spin"></span> Tracking Flows...';
      }

      showToast('Tracing source-to-sink dataflows...', 'info');

      try {
        const res = await fetch('/api/analysis/taint', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ source_code: code, file_path: filePath }),
        });
        const data = await res.json();
        const findings = data.findings || [];

        renderTaintFindings(findings);
        showToast(`Taint Analysis: Discovered ${findings.length} tainted sinks!`, findings.length > 0 ? 'error' : 'success');
      } catch (e) {
        showToast(`Taint Analysis error: ${e}`, 'error');
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<i data-lucide="play" class="w-3.5 h-3.5"></i> Analyze Dataflow';
          window.lucide?.createIcons();
        }
      }
    }

    function renderTaintFindings(findings) {
      const container = document.getElementById('taint-findings-container');
      const badge = document.getElementById('taint-findings-badge');
      const statSinks = document.getElementById('taint-stat-sinks');
      const statSev = document.getElementById('taint-stat-sev');
      const statConf = document.getElementById('taint-stat-conf');

      if (!container) return;

      if (badge) badge.textContent = `${findings.length} Flow${findings.length === 1 ? '' : 's'}`;
      if (statSinks) statSinks.textContent = findings.length;

      if (findings.length === 0) {
        if (statSev) statSev.textContent = 'CLEAN';
        container.innerHTML = `
          <div class="p-6 text-center text-slate-500 text-xs bg-card/40 rounded-lg border border-borderSubtle">
            <i data-lucide="shield-check" class="w-6 h-6 mx-auto mb-2 text-emerald-400"></i>
            No source-to-sink dataflow vulnerabilities detected in the analyzed snippet. Inputs appear properly sanitized.
          </div>
        `;
        window.lucide?.createIcons();
        return;
      }

      const hasCrit = findings.some(f => f.severity === 'CRITICAL');
      const hasHigh = findings.some(f => f.severity === 'HIGH');
      if (statSev) statSev.textContent = hasCrit ? 'CRITICAL' : (hasHigh ? 'HIGH' : 'MEDIUM');

      container.innerHTML = findings.map((f, idx) => {
        const sevColor = f.severity === 'CRITICAL' ? 'bg-red-950/80 text-red-300 border-red-800' :
                         f.severity === 'HIGH' ? 'bg-orange-950/80 text-orange-300 border-orange-800' :
                         'bg-yellow-950/80 text-yellow-300 border-yellow-800';

        return `
          <div class="bg-card border border-borderSubtle rounded-xl p-4 space-y-3 font-mono text-xs">
            <div class="flex items-start justify-between gap-3">
              <div>
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${sevColor}">${escapeHtml(String(f.severity))}</span>
                  <span class="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 border border-slate-700">${escapeHtml(f.cwe_id)}</span>
                  ${f.owasp_masvs ? `<span class="px-1.5 py-0.2 rounded bg-sky-950 text-[10px] text-sky-300 border border-sky-800">${escapeHtml(f.owasp_masvs)}</span>` : ''}
                </div>
                <h5 class="text-sm font-semibold text-white mt-1.5">${escapeHtml(f.title)}</h5>
                <p class="text-[11px] text-slate-400 font-sans mt-1 leading-relaxed">${escapeHtml(f.description.split('\\n\\n')[0] || f.description)}</p>
              </div>
              <div class="text-right shrink-0">
                <div class="text-[10px] text-slate-400">CVSS v3.1</div>
                <div class="text-sm font-bold text-red-400">${f.cvss_score ? f.cvss_score.toFixed(1) : '8.8'}</div>
              </div>
            </div>

            <!-- Taint Trace Snippet -->
            ${f.code_snippet ? `
              <div class="bg-black/80 rounded-lg p-2.5 border border-borderSubtle">
                <div class="text-[10px] text-slate-400 mb-1 flex items-center justify-between">
                  <span>Sink Line ${escapeHtml(String(f.line_number || 'N/A'))}:</span>
                  <span class="text-sky-400 font-semibold">${escapeHtml(f.file_path || 'Source')}</span>
                </div>
                <code class="text-amber-300 text-[11px] leading-relaxed block">${escapeHtml(f.code_snippet)}</code>
              </div>
            ` : ''}

            <!-- Remediation -->
            ${f.remediation ? `
              <div class="pt-2 border-t border-borderSubtle/60 flex items-start gap-2 text-[11px] text-slate-300 font-sans">
                <i data-lucide="check-circle-2" class="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5"></i>
                <div><span class="font-semibold text-white">Remediation:</span> ${escapeHtml(f.remediation)}</div>
              </div>
            ` : ''}
          </div>
        `;
      }).join('');

      window.lucide?.createIcons();
    }

    function escapeHtml(text) {
      const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
      return String(text ?? "").replace(/[&<>"']/g, m => map[m]);
    }

    // =====================================================================
    // API SECURITY STUDIO & OWASP FUZZING LOGIC
    // =====================================================================
    let currentApiEndpoints = [];
    let selectedApiId = null;
    let currentApiMethodFilter = 'ALL';
    let currentApiSubTab = 'owasp';

    async function loadApiView() {
      const scanId = currentScan?.scan_id;
      if (!scanId) { showToast('Select a scan first.', 'info'); return; }
      try {
        const res = await fetch(`/api/scans/${scanId}/apis`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        currentApiEndpoints = data.endpoints || [];

        // Update sidebar badge
        const badge = document.getElementById('nav-api-badge');
        if (badge) badge.textContent = `${currentApiEndpoints.length} APIs`;

        renderApiInventory();
        if (!selectedApiId && currentApiEndpoints.length > 0) {
          selectApiEndpoint(currentApiEndpoints[0].id);
        }
      } catch (err) {
        console.error('Failed to load API endpoints:', err);
        showToast('Error loading API endpoints inventory');
      }
    }

    function setApiMethodFilter(method) {
      currentApiMethodFilter = method;
      document.querySelectorAll('.api-filter-btn').forEach(btn => {
        btn.classList.remove('bg-purple-950', 'text-purple-300', 'border', 'border-purple-800');
        btn.classList.add('text-slate-400');
      });
      const activeBtn = document.getElementById(`api-filter-${method.toLowerCase()}`);
      if (activeBtn) {
        activeBtn.classList.add('bg-purple-950', 'text-purple-300', 'border', 'border-purple-800');
        activeBtn.classList.remove('text-slate-400');
      }
      filterApiEndpoints();
    }

    function filterApiEndpoints() {
      const q = (document.getElementById('api-search-input')?.value || '').toLowerCase().trim();
      const statusFilter = document.getElementById('api-status-filter')?.value || 'ALL';

      const filtered = currentApiEndpoints.filter(ep => {
        if (currentApiMethodFilter !== 'ALL' && ep.method.toUpperCase() !== currentApiMethodFilter) return false;
        if (statusFilter !== 'ALL' && ep.status !== statusFilter) return false;
        if (!q) return true;
        return (
          (ep.url && ep.url.toLowerCase().includes(q)) ||
          (ep.path && ep.path.toLowerCase().includes(q)) ||
          (ep.host && ep.host.toLowerCase().includes(q)) ||
          (ep.owasp_api && ep.owasp_api.toLowerCase().includes(q)) ||
          (ep.source && ep.source.toLowerCase().includes(q))
        );
      });

      renderApiInventory(filtered);
    }

    function getMethodBadgeClass(method) {
      const m = (method || 'GET').toUpperCase();
      switch (m) {
        case 'GET': return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80';
        case 'POST': return 'bg-sky-950/80 text-sky-300 border-sky-800/80';
        case 'PUT': return 'bg-amber-950/80 text-amber-300 border-amber-800/80';
        case 'DELETE': return 'bg-rose-950/80 text-rose-300 border-rose-800/80';
        case 'PATCH': return 'bg-purple-950/80 text-purple-300 border-purple-800/80';
        default: return 'bg-slate-800 text-slate-300 border-slate-700';
      }
    }

    function renderApiInventory(list = currentApiEndpoints) {
      const container = document.getElementById('api-endpoints-list');
      if (!container) return;

      if (!list || list.length === 0) {
        container.innerHTML = `
          <div class="p-8 text-center text-slate-500 font-mono text-xs">
            <i data-lucide="search-x" class="w-8 h-8 mx-auto mb-2 text-slate-600"></i>
            No API endpoints match the selected filter criteria.
          </div>
        `;
        window.lucide?.createIcons();
        return;
      }

      container.innerHTML = list.map(ep => {
        const isSelected = selectedApiId === ep.id;
        const methodBadge = getMethodBadgeClass(ep.method);
        const isVuln = ep.status === 'VULNERABLE';
        const statusBadge = isVuln
          ? `<span class="px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800 font-mono text-[10px]">Unverified candidate</span>`
          : `<span class="px-1.5 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800 font-mono text-[10px]">Not assessed</span>`;

        return `
          <div ${bindAction('click', () => selectApiEndpoint(ep.id))} class="p-3 rounded-lg border transition cursor-pointer ${isSelected ? 'bg-purple-950/20 border-purple-500/60 shadow-lg' : 'bg-card border-borderSubtle hover:border-slate-700'} space-y-2">
            <div class="flex items-center justify-between gap-2">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${methodBadge}">${escapeHtml(ep.method)}</span>
                <span class="font-mono text-xs font-semibold text-white truncate max-w-xs md:max-w-md" title="${escapeHtml(ep.url)}">${escapeHtml(ep.path || ep.url)}</span>
              </div>
              <div>${statusBadge}</div>
            </div>

            <div class="flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span class="truncate max-w-[220px] text-slate-300"><i data-lucide="server" class="w-3 h-3 inline mr-1 text-slate-500"></i>${escapeHtml(ep.host || 'api.target')}</span>
              <span class="text-purple-300/80 truncate max-w-[200px]"><i data-lucide="lock" class="w-3 h-3 inline mr-1 text-slate-500"></i>${escapeHtml(ep.auth_type || 'None')}</span>
            </div>

            <div class="pt-1.5 border-t border-borderSubtle/50 flex items-center justify-between text-[10px] font-mono">
              <span class="text-slate-500 truncate max-w-[260px]">${escapeHtml(ep.source || 'Decompiled Bytecode')}</span>
              <span class="${isVuln ? 'text-amber-400 font-semibold' : 'text-slate-400'}">${escapeHtml(ep.owasp_api || 'Discovered endpoint')}</span>
            </div>
          </div>
        `;
      }).join('');

      window.lucide?.createIcons();
    }

    function selectApiEndpoint(apiId) {
      selectedApiId = apiId;
      renderApiInventory();

      const ep = currentApiEndpoints.find(e => e.id === apiId);
      if (!ep) return;

      const badge = document.getElementById('api-detail-status-badge');
      if (badge) {
        if (ep.status === 'VULNERABLE') {
          badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800';
          badge.textContent = 'OWASP FLAW DETECTED';
        } else {
          badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
          badge.textContent = 'SECURE GATEWAY';
        }
      }

      renderApiWorkbench(ep);
    }

    function renderApiWorkbench(ep) {
      const container = document.getElementById('api-workbench-content');
      if (!container) return;

      const methodBadge = getMethodBadgeClass(ep.method);
      const isVuln = ep.status === 'VULNERABLE';

      container.innerHTML = `
        <!-- Endpoint Header Card -->
        <div class="bg-card p-3.5 rounded-lg border border-borderSubtle space-y-2.5">
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-2 flex-1 min-w-0">
              <span class="px-2 py-0.5 rounded font-mono font-bold text-[11px] border ${methodBadge}">${escapeHtml(ep.method)}</span>
              <span class="font-mono text-xs text-white font-semibold truncate select-all" title="${escapeHtml(ep.url)}">${escapeHtml(ep.url)}</span>
            </div>
            <button ${bindAction('click', () => copyApiCurl(ep.id))} class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono flex items-center gap-1 border border-slate-700 shrink-0 transition" title="Copy cURL Command">
              <i data-lucide="terminal" class="w-3.5 h-3.5 text-sky-400"></i>
              <span>cURL</span>
            </button>
          </div>

          <div class="grid grid-cols-3 gap-2 text-[11px] font-mono pt-2 border-t border-borderSubtle">
            <div>
              <span class="text-slate-500 block">Host:</span>
              <span class="text-slate-300 truncate block">${escapeHtml(ep.host || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Authentication:</span>
              <span class="text-purple-300 truncate block">${escapeHtml(ep.auth_type || 'None')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Source Trace:</span>
              <span class="text-slate-300 truncate block">${escapeHtml(ep.source || 'Retrofit')}</span>
            </div>
          </div>
        </div>

        <!-- Action Buttons Toolbar -->
        <div class="flex items-center gap-2">
          <button ${bindAction('click', () => sendApiReplayRequest(ep.id))} id="btn-replay-req" class="flex-1 py-2 px-3 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs font-mono flex items-center justify-center gap-2 shadow-lg transition">
            <i data-lucide="play" class="w-3.5 h-3.5 fill-current"></i>
            <span>Send / Replay Request</span>
          </button>

          <button ${bindAction('click', () => runApiFuzzing(ep.id))} id="btn-fuzz-api" class="flex-1 py-2 px-3 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs font-mono flex items-center justify-center gap-2 shadow-lg transition">
            <i data-lucide="zap" class="w-3.5 h-3.5 fill-current text-amber-300"></i>
            <span>Run OWASP Top 10 Fuzzing</span>
          </button>
        </div>

        <!-- Studio Sub-Tabs Nav -->
        <div class="border-b border-borderSubtle flex items-center gap-1 text-xs font-mono">
          <button data-onclick="static94" id="api-subtab-btn-owasp" class="api-subtab-btn px-3 py-1.5 rounded-t-lg bg-purple-950 text-purple-300 border-t border-x border-purple-800 font-semibold flex items-center gap-1.5">
            <i data-lucide="shield-alert" class="w-3.5 h-3.5 text-amber-400"></i>
            <span>OWASP Analysis</span>
          </button>
          <button data-onclick="static95" id="api-subtab-btn-request" class="api-subtab-btn px-3 py-1.5 rounded-t-lg text-slate-400 hover:text-white flex items-center gap-1.5">
            <i data-lucide="send" class="w-3.5 h-3.5 text-sky-400"></i>
            <span>Request & cURL</span>
          </button>
          <button data-onclick="static96" id="api-subtab-btn-response" class="api-subtab-btn px-3 py-1.5 rounded-t-lg text-slate-400 hover:text-white flex items-center gap-1.5">
            <i data-lucide="radio" class="w-3.5 h-3.5 text-emerald-400"></i>
            <span>Response Preview</span>
          </button>
          <button data-onclick="static97" id="api-subtab-btn-remediation" class="api-subtab-btn px-3 py-1.5 rounded-t-lg text-slate-400 hover:text-white flex items-center gap-1.5">
            <i data-lucide="check-circle" class="w-3.5 h-3.5 text-teal-400"></i>
            <span>Remediation</span>
          </button>
        </div>

        <!-- Subtab 1: OWASP API Analysis -->
        <div id="api-pane-owasp" class="api-tab-pane space-y-3">
          <div class="p-3.5 rounded-lg border ${isVuln ? 'bg-rose-950/30 border-rose-900/60' : 'bg-emerald-950/30 border-emerald-900/60'} space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-mono text-xs font-bold ${isVuln ? 'text-rose-300' : 'text-emerald-300'}">${escapeHtml(ep.owasp_api || 'API Gateway')}</span>
              <span class="font-mono text-[10px] px-1.5 py-0.5 rounded ${isVuln ? 'bg-rose-900 text-rose-200' : 'bg-emerald-900 text-emerald-200'}">${escapeHtml(ep.cwe || 'Not assessed')}</span>
            </div>
            <p class="text-slate-300 text-xs leading-relaxed font-sans">${escapeHtml(ep.description || 'Discovered endpoint; server authorization has not been tested.')}</p>
          </div>

          <!-- Parameters Audit -->
          ${ep.parameters && ep.parameters.length > 0 ? `
            <div class="space-y-1.5">
              <div class="text-[11px] font-mono text-slate-400 font-semibold">Extracted Parameters & Risk Classification:</div>
              <div class="bg-card rounded-lg border border-borderSubtle overflow-hidden">
                <table class="w-full text-left font-mono text-[11px]">
                  <thead class="bg-slate-900/80 text-slate-400 border-b border-borderSubtle">
                    <tr>
                      <th class="p-2">Name</th>
                      <th class="p-2">Location</th>
                      <th class="p-2">Sample</th>
                      <th class="p-2">Risk Tag</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-borderSubtle/50 text-slate-300">
                    ${ep.parameters.map(p => `
                      <tr>
                        <td class="p-2 text-sky-300 font-bold">${escapeHtml(p.name)}</td>
                        <td class="p-2 text-slate-400">${escapeHtml(p.type)}</td>
                        <td class="p-2 text-amber-300">${escapeHtml(p.sample || 'N/A')}</td>
                        <td class="p-2"><span class="px-1 py-0.2 rounded bg-amber-950 text-amber-300 text-[10px]">${escapeHtml(p.risk || 'Standard')}</span></td>
                      </tr>
                    `).join('')}
                  </tbody>
                </table>
              </div>
            </div>
          ` : ''}

          <!-- Live OWASP Fuzzing Output Box -->
          <div id="api-live-fuzz-results" class="space-y-2 pt-2 border-t border-borderSubtle">
            <div class="flex items-center justify-between text-[11px] font-mono">
              <span class="text-slate-400">Autonomous Fuzzing Audit:</span>
              <span id="api-fuzz-status-text" class="text-purple-400">Ready to execute</span>
            </div>
            <div class="p-3 bg-card/60 rounded-lg border border-borderSubtle font-mono text-xs text-slate-400 space-y-1.5">
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>TLS/SSL Transport Encryption Check</span></div>
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>BOLA / IDOR Sequential Identifier Probing</span></div>
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>PII & Response Payload Leakage Audit (SSN, Passwords, Keys)</span></div>
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>BFLA Client Privileged Route Escalation Check</span></div>
            </div>
          </div>
        </div>

        <!-- Subtab 2: Request & cURL Inspector -->
        <div id="api-pane-request" class="api-tab-pane hidden space-y-3">
          <div class="space-y-2">
            <div class="flex items-center gap-2">
              <select id="api-req-method" class="bg-card border border-borderSubtle rounded-lg px-2.5 py-1.5 text-xs font-mono text-white focus:outline-none focus:border-sky-500">
                <option value="GET" ${ep.method === 'GET' ? 'selected' : ''}>GET</option>
                <option value="POST" ${ep.method === 'POST' ? 'selected' : ''}>POST</option>
                <option value="PUT" ${ep.method === 'PUT' ? 'selected' : ''}>PUT</option>
                <option value="DELETE" ${ep.method === 'DELETE' ? 'selected' : ''}>DELETE</option>
                <option value="PATCH" ${ep.method === 'PATCH' ? 'selected' : ''}>PATCH</option>
              </select>
              <input type="text" id="api-req-url" value="${escapeHtml(ep.url)}" class="flex-1 bg-card border border-borderSubtle rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-sky-500" />
            </div>

            <!-- Headers Textarea -->
            <div>
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Request Headers (JSON or Raw):</label>
              <textarea id="api-req-headers" rows="3" class="w-full bg-slate-900 border border-borderSubtle rounded-lg p-2.5 font-mono text-xs text-sky-300 focus:outline-none focus:border-sky-500">${escapeHtml(ep.auth_type === 'Bearer Token' ? '{\n  "Authorization": "Bearer mock_token_for_audit",\n  "Accept": "application/json"\n}' : '{\n  "Content-Type": "application/json"\n}')}</textarea>
            </div>

            <!-- Body Textarea -->
            <div>
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Request Body (JSON / Form):</label>
              <textarea id="api-req-body" rows="4" placeholder="{}" class="w-full bg-slate-900 border border-borderSubtle rounded-lg p-2.5 font-mono text-xs text-emerald-300 focus:outline-none focus:border-sky-500">${escapeHtml(ep.method === 'POST' ? '{\n  "username": "admin",\n  "query": "{ products { id } }"\n}' : '')}</textarea>
            </div>

            <!-- Pre-generated cURL Command Box -->
            <div>
              <div class="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                <span>Reproducible cURL Command:</span>
                <button ${bindAction('click', () => copyApiCurl(ep.id))} class="text-sky-400 hover:underline">Copy</button>
              </div>
              <pre class="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap">${escapeHtml(ep.curl_cmd || `curl -X ${ep.method} "${ep.url}"`)}</pre>
            </div>
          </div>
        </div>

        <!-- Subtab 3: Response Preview -->
        <div id="api-pane-response" class="api-tab-pane hidden space-y-3">
          <div class="flex items-center justify-between bg-card p-2.5 rounded-lg border border-borderSubtle font-mono text-xs">
            <div class="flex items-center gap-2">
              <span class="text-slate-400">Status:</span>
              <span id="api-resp-status-badge" class="px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">200 OK</span>
            </div>
            <div class="flex items-center gap-3 text-[11px]">
              <span id="api-resp-mode-badge" class="px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800">Sample preview — not an observed response</span>
              <span id="api-resp-duration" class="text-slate-400">Not measured</span>
            </div>
          </div>

          <!-- Response Headers -->
          <div>
            <div class="text-[11px] font-mono text-slate-400 mb-1">Response Headers:</div>
            <pre id="api-resp-headers-view" class="p-2.5 bg-slate-900 rounded-lg border border-borderSubtle font-mono text-[11px] text-slate-300 overflow-x-auto">No response headers captured</pre>
          </div>

          <!-- Response Body -->
          <div>
            <div class="text-[11px] font-mono text-slate-400 mb-1">Response Body:</div>
            <pre id="api-resp-body-view" class="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto whitespace-pre-wrap max-h-60">${escapeHtml(ep.sample_response || 'No response captured; replay requires exact server-side scope.')}</pre>
          </div>
        </div>

        <!-- Subtab 4: Defensive Remediation -->
        <div id="api-pane-remediation" class="api-tab-pane hidden space-y-3 font-mono text-xs">
          <div class="p-3 rounded-lg bg-card border border-borderSubtle space-y-2">
            <div class="font-bold text-emerald-400 font-sans text-xs">🛡️ Backend Architecture Hardening:</div>
            <ul class="list-disc pl-4 space-y-1 text-slate-300 text-[11px] font-sans">
              <li><strong>Enforce Object-Level RBAC:</strong> Verify requesting user identity against the database row ownership, never relying solely on client path IDs.</li>
              <li><strong>Migrate to Non-Sequential IDs:</strong> Replace predictable sequential integers with cryptographically secure UUID v4 strings.</li>
              <li><strong>Data Serialization Filters:</strong> Exclude PII, internal roles, and password hashes from API responses using DTO projection filters.</li>
            </ul>
          </div>

          <div class="space-y-1">
            <div class="text-[11px] font-mono text-slate-400">Mobile Client Defensive Guard (OkHttp / Retrofit Kotlin):</div>
            <pre class="p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px] font-mono text-sky-300 overflow-x-auto whitespace-pre-wrap">val certPinner = CertificatePinner.Builder()
    .add("${escapeHtml(ep.host || 'YOUR_AUTHORIZED_HOST')}", "sha256/k2v657xUM4Ivng6GeDiRC6afkiUjOGKqUFPG9NVSX68=")
    .build()

val okHttpClient = OkHttpClient.Builder()
    .certificatePinner(certPinner)
    .addInterceptor { chain ->
        val req = chain.request().newBuilder()
            .header("Cache-Control", "no-store")
            .header("X-Client-Platform", "Android-Native")
            .build()
        chain.proceed(req)
    }
    .build()</pre>
          </div>
        </div>
      `;

      window.lucide?.createIcons();
    }

    function switchApiSubTab(tab) {
      currentApiSubTab = tab;
      document.querySelectorAll('.api-tab-pane').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.api-subtab-btn').forEach(btn => {
        btn.classList.remove('bg-purple-950', 'text-purple-300', 'border-t', 'border-x', 'border-purple-800', 'font-semibold');
        btn.classList.add('text-slate-400');
      });

      const targetPane = document.getElementById(`api-pane-${tab}`);
      if (targetPane) targetPane.classList.remove('hidden');

      const targetBtn = document.getElementById(`api-subtab-btn-${tab}`);
      if (targetBtn) {
        targetBtn.classList.add('bg-purple-950', 'text-purple-300', 'border-t', 'border-x', 'border-purple-800', 'font-semibold');
        targetBtn.classList.remove('text-slate-400');
      }

      window.lucide?.createIcons();
    }

    async function sendApiReplayRequest(apiId) {
      const ep = currentApiEndpoints.find(e => e.id === apiId);
      if (!ep) return;

      const btn = document.getElementById('btn-replay-req');
      const originalHtml = btn ? btn.innerHTML : '';
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i><span>Sending...</span>`;
        window.lucide?.createIcons();
      }

      const url = document.getElementById('api-req-url')?.value || ep.url;
      const method = document.getElementById('api-req-method')?.value || ep.method;
      let headers = {};
      try {
        const rawHeaders = document.getElementById('api-req-headers')?.value;
        if (rawHeaders) headers = JSON.parse(rawHeaders);
      } catch (e) {
        headers = { "Authorization": "Bearer mock_token_for_audit" };
      }
      const body = document.getElementById('api-req-body')?.value || undefined;

      try {
        const res = await fetch('/api/apis/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, method, headers, body, timeout: 4.0 }),
        });
        const data = await res.json();

        // Switch to Response tab and update values
        switchApiSubTab('response');

        const statusBadge = document.getElementById('api-resp-status-badge');
        if (statusBadge) {
          statusBadge.textContent = `${data.status_code || 200} ${data.status_code === 200 ? 'OK' : 'RESPONSE'}`;
          statusBadge.className = data.status_code >= 400
            ? 'px-2 py-0.5 rounded font-bold bg-rose-950 text-rose-300 border border-rose-800'
            : 'px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
        }

        const modeBadge = document.getElementById('api-resp-mode-badge');
        if (modeBadge) {
          modeBadge.textContent = data.mode === 'live' ? 'OBSERVED HTTP RESPONSE' : 'No live response verified';
          modeBadge.className = data.mode === 'live'
            ? 'px-1.5 py-0.2 rounded bg-sky-950 text-sky-300 border border-sky-800'
            : 'px-1.5 py-0.2 rounded bg-purple-950 text-purple-300 border border-purple-800';
        }

        const durBadge = document.getElementById('api-resp-duration');
        if (durBadge) durBadge.textContent = data.duration_ms == null ? 'Not measured' : `${data.duration_ms} ms`;

        const headersView = document.getElementById('api-resp-headers-view');
        if (headersView) headersView.textContent = JSON.stringify(data.headers || {}, null, 2);

        const bodyView = document.getElementById('api-resp-body-view');
        if (bodyView) {
          try {
            const parsed = JSON.parse(data.body);
            bodyView.textContent = JSON.stringify(parsed, null, 2);
          } catch (e) {
            bodyView.textContent = data.body || '(Empty Response)';
          }
        }

        showToast(`Request executed: HTTP ${data.status_code || 200}`);
      } catch (err) {
        console.error('Request replay failed:', err);
        showToast('API replay failed: ' + err.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
          window.lucide?.createIcons();
        }
      }
    }

    async function runApiFuzzing(apiId) {
      const ep = currentApiEndpoints.find(e => e.id === apiId);
      if (!ep) return;

      const btn = document.getElementById('btn-fuzz-api');
      const originalHtml = btn ? btn.innerHTML : '';
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i><span>Fuzzing...</span>`;
        window.lucide?.createIcons();
      }

      switchApiSubTab('owasp');
      const resultsContainer = document.getElementById('api-live-fuzz-results');
      const statusText = document.getElementById('api-fuzz-status-text');
      if (statusText) statusText.textContent = 'Auditing OWASP API Top 10 rules...';

      try {
        const res = await fetch('/api/apis/fuzz', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: ep.url,
            method: ep.method,
            headers: ep.auth_type === 'Bearer Token' ? { "Authorization": "Bearer mock_token_for_audit" } : {},
            response_status: 200,
            response_body: ep.sample_response,
          }),
        });
        const data = await res.json();

        if (statusText) {
          statusText.textContent = `Completed (${escapeHtml(String(data.findings_count))} review candidates detected)`;
          statusText.className = data.findings_count > 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold';
        }

        if (resultsContainer) {
          resultsContainer.innerHTML = `
            <div class="flex items-center justify-between text-[11px] font-mono">
              <span class="text-slate-400">Autonomous Fuzzing Audit:</span>
              <span class="${data.findings_count > 0 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}">${escapeHtml(String(data.findings_count))} Unverified candidates</span>
            </div>
            ${data.findings.length > 0 ? data.findings.map(f => `
              <div class="p-3 bg-rose-950/20 border border-rose-900/60 rounded-lg space-y-1 text-xs">
                <div class="flex items-center justify-between">
                  <span class="font-bold text-rose-300 font-mono">${escapeHtml(f.title)}</span>
                  <span class="px-1.5 py-0.2 rounded bg-rose-900 text-rose-200 text-[10px] font-mono font-bold">${escapeHtml(f.cwe_id || 'CWE')}</span>
                </div>
                <p class="text-slate-300 text-[11px] font-sans leading-relaxed">${escapeHtml(f.description)}</p>
                ${f.remediation ? `
                  <div class="pt-1 text-[10px] font-mono text-emerald-400"><span class="font-bold">Fix:</span> ${escapeHtml(f.remediation)}</div>
                ` : ''}
              </div>
            `).join('') : `
              <div class="p-3 bg-emerald-950/20 border border-emerald-900/60 rounded-lg text-xs font-mono text-emerald-300 flex items-center gap-2">
                <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i>
                <span>No OWASP API Top 10 vulnerabilities detected on this endpoint.</span>
              </div>
            `}
          `;
          window.lucide?.createIcons();
        }

        showToast(`OWASP API Audit completed: ${escapeHtml(String(data.findings_count))} flaws identified`);
      } catch (err) {
        console.error('Fuzzing error:', err);
        showToast('Fuzzing failed: ' + err.message);
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
          window.lucide?.createIcons();
        }
      }
    }

    async function fuzzAllApiEndpoints() {
      const btn = document.getElementById('btn-audit-all-apis');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i><span>Auditing...</span>`;
      }

      showToast('Starting autonomous OWASP API Top 10 assessment on all endpoints...');
      let totalFlaws = 0;
      for (const ep of currentApiEndpoints) {
        try {
          const res = await fetch('/api/apis/fuzz', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              url: ep.url,
              method: ep.method,
              headers: ep.auth_type === 'Bearer Token' ? { "Authorization": "Bearer mock_token_for_audit" } : {},
              response_body: ep.sample_response,
            }),
          });
          const data = await res.json();
          totalFlaws += (data.findings_count || 0);
        } catch (e) {
          console.warn('Endpoint fuzzing check failed for', ep.url, e);
        }
      }

      showToast(`Audit complete: ${totalFlaws} OWASP API flaws evaluated across ${currentApiEndpoints.length} endpoints.`);
      if (selectedApiId) selectApiEndpoint(selectedApiId);

      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="zap" class="w-3.5 h-3.5 text-amber-400"></i><span>Audit All</span>`;
        window.lucide?.createIcons();
      }
    }

    function copyApiCurl(apiId) {
      const ep = currentApiEndpoints.find(e => e.id === apiId);
      if (!ep) return;
      const cmd = ep.curl_cmd || `curl -X ${ep.method} "${ep.url}"`;
      navigator.clipboard.writeText(cmd).then(() => {
        showToast('cURL command copied to clipboard!');
      }).catch(() => {
        showToast('Failed to copy to clipboard');
      });
    }

    // Close export dropdown on click outside
    window.addEventListener('click', (e) => {
      const menu = document.getElementById('export-dropdown');
      if (menu && !menu.contains(e.target) && !e.target.closest('button[data-onclick="static98"]')) {
        menu.classList.add('hidden');
      }
    });

    async function loadPrivacyPolicy() {
      const badge = document.getElementById('privacy-mode');
      try {
        const cfg = await (await fetch('/api/settings')).json();
        badge.textContent = cfg.offline ? 'Offline (no LLM/OSV)' : 'Cloud/OSV enabled: ' + cfg.approved_llm_providers.join(', ');
      } catch (error) { badge.textContent = 'Policy unavailable: reconnect session'; }
    }

    // Initialize on page load
    window.addEventListener('DOMContentLoaded', () => {
      loadInitialScan();
      loadPrivacyPolicy();
      checkGraphStatus();
      connectTelemetryWebSocket();
      refreshDastDevices();
    });
