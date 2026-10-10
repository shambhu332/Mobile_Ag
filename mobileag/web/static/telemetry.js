/* MobileAg telemetry.js — ordered local classic-script module; shared workspace state is in workspace.js. */
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
              if(currentScan?.scan_id===data.scan_id)handleLiveEvent(data);
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
          if(accessToken)setTimeout(connectTelemetryWebSocket, 3000);else if(wsLabel)wsLabel.textContent='Disconnected: connect session';
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
        while(feed.children.length>100)feed.lastElementChild.remove();
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

        // Match the KPI labels and server report semantics: only explicit
        // analyst-confirmed status contributes to confirmed severity totals.
        const confirmedFindings = currentScan.findings.filter(f =>
          String(f.status || '').toUpperCase() === 'CONFIRMED');
        const critHigh = confirmedFindings.filter(f =>
          ['CRITICAL', 'HIGH'].includes(String(f.severity || '').toUpperCase())).length;
        const medLow = confirmedFindings.filter(f =>
          ['MEDIUM', 'LOW'].includes(String(f.severity || '').toUpperCase())).length;
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
