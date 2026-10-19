/* MobileAg history-settings.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    // Scans History View
    let scanHistoryOffset=0;
    async function loadScansView() {
      const tbody = document.getElementById('scans-table-body');
      tbody.setAttribute('aria-busy','true');
      tbody.innerHTML = '<tr><td colspan="6" class="p-4 text-center text-slate-500">Loading scan history...</td></tr>';

      try {
        const res = await fetch('/api/scans?limit=25&summaries=true&offset='+scanHistoryOffset);
        const page = await res.json();
        const list = page.items;
        let pager=document.getElementById('scan-history-pager');
        if(!pager){pager=document.createElement('div');pager.id='scan-history-pager';pager.className='workflow-actions';tbody.closest('table').after(pager);}
        pager.replaceChildren();
        const count=document.createElement('span');count.textContent=`${page.total?scanHistoryOffset+1:0}–${Math.min(scanHistoryOffset+25,page.total)} of ${page.total}`;pager.append(count);
        for(const [label,delta]of [['Previous',-25],['Next',25]]){const b=document.createElement('button');b.type='button';b.textContent=label;b.disabled=delta<0?scanHistoryOffset===0:scanHistoryOffset+25>=page.total;b.addEventListener('click',()=>{scanHistoryOffset=Math.max(0,scanHistoryOffset+delta);loadScansView();});pager.append(b);}
        tbody.innerHTML = '';

        if(!list.length)tbody.innerHTML='<tr><td colspan="6">No scans on this page. Upload an APK or IPA to begin.</td></tr>';
        list.forEach(s => {
          s.stats ||= {};
          const tr = document.createElement('tr');
          tr.className = 'hover:bg-card/50 transition';
          tr.innerHTML = `
            <td class="py-3 px-4 text-sky-400 font-bold">${escapeHtml(s.scan_id)}</td>
            <td class="py-3 px-4">${escapeHtml(String(s.package_name || s.app_name))}</td>
            <td class="py-3 px-4 text-slate-400">${escapeHtml(String(s.created_at || 'Just now'))}</td>
            <td class="py-3 px-4">
              <span class="px-2 py-0.5 rounded text-[10px] ${s.status === 'completed' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-sky-950 text-sky-400 border border-sky-800'}">
                ${escapeHtml(String((s.status||'unknown').toUpperCase()))}
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
        tbody.replaceChildren();const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;tr.append(td);tbody.append(tr);window.MobileAgUI.state(td,'Unable to load scan history',err.message,'error',loadScansView);
      }finally{tbody.setAttribute('aria-busy','false');}
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
        showToast('Could not load scan: '+e.message, 'error');
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
              <span title="Individual execution is not implemented" class="px-2 py-1 rounded bg-card hover:bg-slate-700 border border-borderSubtle text-sky-400 text-[10px]">
                Capability only
              </span>
            </div>
          `;
          grid.appendChild(card);
        });
      } catch (e) {
        window.MobileAgUI.state(grid,'Capabilities unavailable',e.message,'error',loadAgentsView);
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
      let status=document.getElementById('settings-status');if(!status){status=document.createElement('p');status.id='settings-status';status.setAttribute('role','status');document.getElementById('view-settings').prepend(status);}status.textContent='Loading saved settings…';
      try {
        const res = await fetch('/api/settings');
        const cfg = await res.json();
        if (cfg.offline !== undefined) document.getElementById('cfg-offline').checked = cfg.offline;
        if (cfg.entropy_threshold !== undefined) document.getElementById('cfg-entropy').value = cfg.entropy_threshold;
        if (cfg.neo4j_uri) document.getElementById('cfg-neo4j-uri').value = cfg.neo4j_uri;
        if (cfg.enable_deep_taint !== undefined) document.getElementById('cfg-deep-taint').checked = cfg.enable_deep_taint;
        if (cfg.enable_reachability_filter !== undefined) document.getElementById('cfg-reachability').checked = cfg.enable_reachability_filter;
        if (cfg.enable_consensus_voting !== undefined) document.getElementById('cfg-consensus').checked = cfg.enable_consensus_voting;
        status.textContent='Saved settings loaded. Provider credentials and worker policy stay server-controlled.';
      } catch (e) {
        status.textContent='Settings unavailable: '+e.message+'. Reconnect or select Configuration to retry.';
      }
    }

    let settingsSaving=false;
    async function saveSettingsForm() {
      if(settingsSaving)return;settingsSaving=true;
      const button=document.querySelector('button[data-onclick="static35"]'),original=button.innerHTML;button.disabled=true;button.textContent='Saving…';
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
        showToast('Settings were not saved: '+err.message, 'error');
      }finally{settingsSaving=false;button.disabled=false;button.innerHTML=original;window.lucide?.createIcons();}
    }
