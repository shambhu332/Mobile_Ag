/* MobileAg workspace.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    let activeView = 'overview';
    let currentScan = null;
    let visNetwork = null;
    let visNodes = null;
    let visEdges = null;
    let masvsChart = null;
    let activeSeverityFilter = 'ALL';
    let selectedFindingId = null;
    let wsConnection = null;
    let copilotOpen = false;

    // Display server-validated attestations, never a model/live status alone.
    // These remain analyst claims, not independently verified exploit proof.
    function isAnalystAttested(finding) {
      const evidence = finding.evidence_assessment;
      return finding.status === 'CONFIRMED' && evidence?.basis === 'analyst_attested'
        && evidence.artifact_binding === 'checked'
        && evidence.independently_verified === false
        && Array.isArray(evidence.validation_errors) && evidence.validation_errors.length === 0;
    }

    function liveObservation(finding) {
      return {...finding, status: 'UNVERIFIED',
        reported_status: finding.reported_status || finding.status,
        evidence_assessment: {basis: 'not_proven', artifact_binding: 'not_verified',
          independently_verified: false, validation_errors: ['observation_not_analyst_triage']}};
    }

    function refreshAttestationKpis(scan) {
      const attested = (scan?.findings || []).filter(isAnalystAttested);
      for (const [id, severities] of [['kpi-critical-high', ['CRITICAL', 'HIGH']], ['kpi-med-low', ['MEDIUM', 'LOW']]]) {
        const element = document.getElementById(id);
        if (element) element.textContent = attested.filter(f => severities.includes(String(f.severity || '').toUpperCase())).length;
      }
    }

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
      setTimeout(() => toast.remove(), 3500);
    }

    // View Navigation
    function switchView(viewId) {
      activeView = viewId;
      for(const id of ['static-scan-context','scan-assessment-state']){const el=document.getElementById(id);if(el)el.style.display=viewId==='assessment'?'none':'';}
      document.querySelectorAll('.view-panel').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.nav-item').forEach(el => {
        el.classList.remove('bg-sky-950/40', 'text-sky-400', 'border', 'border-sky-800/40');
        el.classList.add('text-slate-400');
      });

      const targetView = document.getElementById(`view-${viewId}`);
      if (targetView) { targetView.classList.remove('hidden'); targetView.scrollTop = 0; }

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
      window.dispatchEvent(new Event('workspace-view-changed'));

    }

    // Load Scan Data
    async function loadInitialScan() {
      try {
        const res = await fetch('/api/scans?limit=1&summaries=true');
        const page = await res.json();
        currentScan = page.items.length ? await (await fetch('/api/scans/' + encodeURIComponent(page.items[0].scan_id))).json() : null;
        if (!currentScan) {
          renderDashboard({package_name:"Upload an APK or IPA to begin", stats:{total:0}, findings:[]});
          document.getElementById("nav-overview").click();
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
      scan ||= {};
      scan.stats ||= {};
      let assessment=document.getElementById('scan-assessment-state');
      if(!assessment){assessment=document.createElement('p');assessment.id='scan-assessment-state';assessment.className='workflow-panel';assessment.setAttribute('role','status');document.getElementById('main-workspace').prepend(assessment);}
      assessment.style.display=activeView==='assessment'?'none':'';
      assessment.textContent='Job: '+(scan.status||'not started')+'. Static candidates are not exploit proof. '+(scan.errors||[]).join(' ');
      if(document.getElementById('job-scan-id'))document.getElementById('job-scan-id').value=scan.scan_id||'';
      if (!scan) return;
      scan.stats = scan.stats || {};
      const apiBadge = document.getElementById('nav-api-badge');
      if (apiBadge) apiBadge.textContent = (scan.api_endpoints || []).length + ' APIs';

      // Header values
      document.getElementById('top-package-name').textContent = scan.package_name || 'No package identified';
      document.getElementById('top-version').textContent = 'v' + (scan.version || 'unknown');
      document.getElementById('top-framework').textContent = scan.framework || 'Not assessed';
      const obfuscation = document.getElementById('top-obfuscation');
      if (obfuscation) obfuscation.textContent = scan.obfuscation_level || 'Not assessed';

      // KPI cards
      document.getElementById('kpi-total').textContent = (scan.findings || []).length;
      // These cards are explicitly labelled "Confirmed". Derive them from
      // per-finding triage status rather than trusting potentially stale or
      // legacy aggregate stats that may count provisional candidates.
      refreshAttestationKpis(scan);
      // Optional legacy metrics are absent from the focused workbench UI.
      const masvsKpi=document.getElementById('kpi-masvs');if(masvsKpi)masvsKpi.textContent='Not assessed';
      const consensusKpi=document.getElementById('kpi-consensus');if(consensusKpi)consensusKpi.textContent='Not measured';
      document.getElementById('nav-findings-count').textContent = (scan.findings || []).length;

      // Populate Resilience Score KPI
      if (scan.scan_id) {
        fetch(`/api/scans/${scan.scan_id}/resilience`)
          .then(r => r.json())
          .then(data => {
            const scoreEl = document.getElementById('kpi-resilience-score');
            const gradeEl = document.getElementById('kpi-resilience-grade');
            if (scoreEl && typeof data.overall_score === 'number') {
              scoreEl.textContent = `${data.overall_score}%`;
            } else if (scoreEl) {
              scoreEl.textContent = 'Not validated';
            }
            if (gradeEl && data.grade) {
              gradeEl.textContent = data.grade === 'Not validated' ? data.grade : `Grade ${data.grade}`;
            }
          })
          .catch(() => {});
      }

      // Render Modules
      renderVisNetwork(scan.attack_surface_graph || { nodes: [], edges: [] });
      renderAgentTelemetryFeed(scan.agent_telemetry || []);
      renderMasvsRadarChart(scan.masvs_compliance || {});
      applyFindingsFilter();
      window.dispatchEvent(new Event('workspace-scan-changed'));

      window.lucide?.createIcons();
    }

    // Vis.js Network Topology
    function renderVisNetwork(graphData) {
      if(visNetwork?.destroy)visNetwork.destroy();visNetwork=null;
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

      visNetwork.on('click', handleGraphNodeClick);
    }

    function graphFit() { if (visNetwork) visNetwork.fit({ animation: true }); }
    function graphZoomIn() { if (visNetwork) visNetwork.moveTo({ scale: visNetwork.getScale() * 1.3 }); }
    function graphZoomOut() { if (visNetwork) visNetwork.moveTo({ scale: visNetwork.getScale() * 0.7 }); }

    function handleGraphNodeClick(params) {
      if (!Array.isArray(params?.nodes) || params.nodes.length === 0) return;
      const nodeId = params.nodes[0];
      const graphNode = visNodes?.get(nodeId);
      selectFindingByNode(nodeId, graphNode?.finding_id);
    }

    function selectFindingByNode(nodeId, findingId = null) {
      if (!currentScan || !currentScan.findings) return;
      const normalizedNodeId = String(nodeId || '').toLowerCase();
      const f = currentScan.findings.find(item =>
        (findingId && item.id === findingId) || item.id === nodeId ||
        (typeof item.cwe_id === 'string' && item.cwe_id.toLowerCase() === normalizedNodeId));
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
