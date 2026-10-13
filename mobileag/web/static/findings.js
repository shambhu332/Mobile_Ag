/* MobileAg findings.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    // Findings Filter & Inspector
    function setSeverityFilter(sev) {
      activeSeverityFilter = sev;
      document.querySelectorAll('.sev-btn').forEach(b => {
        b.classList.remove('bg-slate-700', 'text-white');
        b.classList.add('text-slate-400');
      });
      const activeBtn = document.getElementById(`sev-${sev === 'CRITICAL' ? 'crit' : sev === 'MEDIUM' ? 'med' : sev.toLowerCase()}`);
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
      if(!container)return;
      if(!currentScan){window.MobileAgUI?.state(container,'No scan selected','Start an assessment or open a saved scan to review its candidates.');return;}

      container.innerHTML = '';
      const list = (currentScan.findings || []).filter(f => {
        const matchesSev = activeSeverityFilter === 'ALL' || f.severity === activeSeverityFilter;
        const matchesStatus = status === 'ALL' || f.status === status;
        const matchesQuery = !query ||
          (f.title && f.title.toLowerCase().includes(query)) ||
          (f.cwe_id && f.cwe_id.toLowerCase().includes(query)) ||
          (f.affected_component && f.affected_component.toLowerCase().includes(query)) ||
          (f.file_path && f.file_path.toLowerCase().includes(query));
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
        card.setAttribute('role','button');card.tabIndex=0;card.setAttribute('aria-label',String(f.title||'Review candidate'));
        card.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();inspectFinding(f.id);}});
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
      html = html.replace(/^\- (.*$)/gim, '<ul><li class="ml-4 list-disc text-slate-300 text-[11px] leading-relaxed my-0.5">$1</li></ul>');
      html = html.replace(/^(\d+)\. (.*$)/gim, '<ol start="$1"><li class="ml-4 list-decimal text-slate-300 text-[11px] leading-relaxed my-1"><span class="text-slate-200">$2</span></li></ol>');
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
      if(f.validation_evidence)return 'Structured analyst attestation (not independently verified):\n'+JSON.stringify(f.validation_evidence,null,2);
      return f.validation_notes
        ? 'Analyst-provided notes (not independently verified):\n' + f.validation_notes
        : 'No runtime validation evidence recorded. Static findings and generated guides are unverified review candidates.';
    }

    async function executeAdbFromPoc(command) {
      const terminal = document.getElementById('poc-adb-terminal');
      if (!terminal) return;
      const dev = dastActiveDevice;
      if (!dev) {
        terminal.innerHTML += `\n<span class="text-amber-400">[!] No explicitly selected authorized device. Connect a device/emulator via Device Diagnostics first.</span>`;
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
        showToast('Connect a device first via Device Diagnostics', 'error');
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
      badge.textContent = isAnalystAttested(f) ? 'CONFIRMED · analyst attested' : f.status;
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
          <button id="subtab-btn-exploit" ${bindAction('click', () => switchFindingSubTab('exploit'))} class="poc-subtab-btn px-2.5 py-1 rounded text-slate-400 hover:text-white flex items-center gap-1">
            <i data-lucide="shield-alert" class="w-3 h-3 text-rose-400"></i> Exploit PoC (Kotlin)
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
          <div tabindex="0" role="region" aria-label="Validation evidence notes" class="bg-black/90 p-3.5 rounded-lg border border-borderSubtle font-mono text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-inner">
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
              <i data-lucide="sparkles" class="w-3 h-3"></i> Local evidence summary
            </button>
          </div>
          <div class="bg-card p-3.5 rounded-lg border border-borderSubtle text-slate-200 text-xs leading-relaxed space-y-2">
            <div>${escapeHtml(f.remediation || 'Follow OWASP Mobile Security verification criteria.')}</div>
            <div class="pt-2 border-t border-borderSubtle text-[11px] font-mono text-slate-400">
              Standard: <span class="text-emerald-400">${escapeHtml(String(f.owasp_masvs || 'MASVS-PLATFORM-1'))}</span>
            </div>
          </div>
        </div>

        <!-- Pane 7: Standalone Exploit PoC (Kotlin) -->
        <div id="poc-pane-exploit" class="poc-tab-pane hidden space-y-2">
          <div class="flex items-center justify-between">
            <span class="text-[10px] font-mono uppercase text-slate-400 font-semibold flex items-center gap-1">
              <i data-lucide="shield-alert" class="w-3 h-3 text-rose-400"></i> Synthesized Exploit Script
            </span>
            <button id="btn-copy-exploit-code" class="text-[10px] font-mono text-sky-400 hover:text-sky-300 flex items-center gap-1">
              <i data-lucide="copy" class="w-3 h-3"></i> Copy Exploit Code
            </button>
          </div>
          <div id="poc-exploit-box" class="bg-black/90 p-3 rounded-lg border border-borderSubtle font-mono text-[11px] text-rose-300 overflow-x-auto whitespace-pre-wrap">
            <code>// Loading synthesized exploit...</code>
          </div>
        </div>

        <!-- Triage & Co-Pilot Action Bar -->
        <div class="pt-4 border-t border-borderSubtle flex items-center justify-between gap-2">
          <button ${bindAction('click', () => askCopilotAboutFinding(f.id))} class="px-2.5 py-1.5 rounded bg-sky-950/80 hover:bg-sky-900 text-sky-300 border border-sky-800 text-xs font-mono flex items-center gap-1.5 transition">
            <i data-lucide="sparkles" class="w-3.5 h-3.5 text-sky-400"></i> Summarize recorded evidence
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

      if (currentScan?.scan_id) {
        fetch(`/api/scans/${encodeURIComponent(currentScan.scan_id)}/findings/${encodeURIComponent(f.id)}/poc`)
          .then(r => r.json())
          .then(data => {
            const box = document.getElementById('poc-exploit-box');
            const copyBtn = document.getElementById('btn-copy-exploit-code');
            if (box) {
              if (data.available && data.kotlin_exploit_code) {
                box.innerHTML = `<code>${escapeHtml(data.kotlin_exploit_code)}</code>`;
                if (copyBtn) copyBtn.addEventListener('click', () => copySnippet(data.kotlin_exploit_code));
              } else {
                box.innerHTML = `<span class="text-slate-500">// ${escapeHtml(data.message || 'No standalone Kotlin exploit template available for this category.')}</span>`;
              }
            }
          })
          .catch(() => {});
      }

      window.MobileAgEvidence?.finding(detailContainer, f);
      switchFindingSubTab(currentFindingSubTab || 'poc');
      window.lucide?.createIcons();
    }

    async function submitTriage(findingId, verdict) {
      const decision=verdict==='CONFIRMED'?await window.MobileAgUI.askNotes(currentScan):{notes:''};if(decision===null)return;
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(currentScan.scan_id)}/findings/${encodeURIComponent(findingId)}/feedback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verdict, revision: currentScan.revision || 0, ...decision })
        });
        const data = await res.json();
        if (data.status !== 'saved' || !data.finding) throw new Error('Invalid triage acknowledgement');

        currentScan.revision = data.revision;
        // Update local memory only after durable server acknowledgement.
        const f = (currentScan.findings || []).find(item => item.id === findingId);
        if (f) Object.assign(f, data.finding);
        refreshAttestationKpis(currentScan);

        inspectFinding(findingId);
        applyFindingsFilter();
        showToast(`Triage recorded: ${verdict}`, 'success');
      } catch (err) {
        showToast('Triage was not saved: '+err.message, 'error');
      }
    }

    async function submitTriageVerdict(findingId, verdict) {
      const decision=verdict==='CONFIRMED'?await window.MobileAgUI.askNotes(currentScan):{notes:''};if(decision===null)return;
      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(currentScan.scan_id)}/findings/${encodeURIComponent(findingId)}/feedback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ verdict, revision: currentScan.revision || 0, ...decision })
        });

        const data = await response.json();
        if (data.status !== 'saved' || !data.finding) throw new Error('Invalid triage acknowledgement');
        currentScan.revision = data.revision;
        const df = dastFindings.find(item => item.id === findingId);
        if (df) Object.assign(df, data.finding);

        if (currentScan && currentScan.findings) {
          const sf = currentScan.findings.find(item => item.id === findingId);
          if (sf) Object.assign(sf, data.finding);
        }
        refreshAttestationKpis(currentScan);

        renderDastFindings();
        showToast(`DAST Triage updated: ${verdict}`, 'success');
      } catch (err) {
        showToast('Triage was not saved: '+err.message, 'error');
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
