/* MobileAg api.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    // API SECURITY STUDIO & OWASP FUZZING LOGIC
    // =====================================================================
    let currentApiEndpoints = [];
    let selectedApiId = null;
    let currentApiMethodFilter = 'ALL';
    let currentApiSubTab = 'owasp';

    async function loadApiView() {
      const scanId = currentScan?.scan_id;
      if(!scanId){currentApiEndpoints=[];selectedApiId=null;window.MobileAgUI?.state(document.getElementById('api-endpoints-list'),'No scan selected','Open a saved scan or start an assessment to inspect discovered routes.');return;}
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
        window.MobileAgUI.state(document.getElementById('api-endpoints-list'),'API inventory unavailable',err.message,'error',loadApiView);
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
          <div role="button" tabindex="0" aria-label="${escapeHtml('Inspect '+ep.method+' '+(ep.path||ep.url))}" ${bindAction('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selectApiEndpoint(ep.id);}})} ${bindAction('click', () => selectApiEndpoint(ep.id))} class="p-3 rounded-lg border transition cursor-pointer ${isSelected ? 'bg-purple-950/20 border-purple-500/60 shadow-lg' : 'bg-card border-borderSubtle hover:border-slate-700'} space-y-2">
            <div class="flex items-center justify-between gap-2">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${methodBadge}">${escapeHtml(ep.method)}</span>
                <span class="font-mono text-xs font-semibold text-white truncate max-w-xs md:max-w-md" title="${escapeHtml(ep.url)}">${escapeHtml(ep.path || ep.url)}</span>
              </div>
              <div>${statusBadge}</div>
            </div>

            <div class="flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span class="truncate max-w-[220px] text-slate-300"><i data-lucide="server" class="w-3 h-3 inline mr-1 text-slate-500"></i>${escapeHtml(ep.host || 'api.target')}</span>
              <span class="text-purple-300/80 truncate max-w-[200px]"><i data-lucide="lock" class="w-3 h-3 inline mr-1 text-slate-500"></i>${escapeHtml(ep.auth_type || 'Not assessed')}</span>
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
          badge.textContent = 'UNVERIFIED CANDIDATE';
        } else {
          badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800';
          badge.textContent = 'NOT ASSESSED';
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
              <span class="text-purple-300 truncate block">${escapeHtml(ep.auth_type || 'Not assessed')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Source Trace:</span>
              <span class="text-slate-300 truncate block">${escapeHtml(ep.source || 'Not recorded')}</span>
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
            <span>Analyze captured transaction</span>
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

          <div class="evidence-hint">
            <p>Offline captured-response analysis does not contact the endpoint. Use only an authorized synthetic/staging capture; redact credentials and user data.</p>
            <label>Observed HTTP status<input id="api-observed-status" type="number" min="100" max="599" placeholder="Enter the actual captured status" /></label>
            <label>Redacted observed body<textarea id="api-observed-body" rows="4" placeholder="Paste only synthetic or redacted observed data"></textarea></label>
            <label><input id="api-observed-confirm" type="checkbox" /> I confirm this is an actual authorized capture, not a generated example.</label>
          </div>
          <!-- Live OWASP Fuzzing Output Box -->
          <div id="api-live-fuzz-results" class="space-y-2 pt-2 border-t border-borderSubtle">
            <div class="flex items-center justify-between text-[11px] font-mono">
              <span class="text-slate-400">Captured-response heuristics:</span>
              <span id="api-fuzz-status-text" class="text-purple-400">Observed response required</span>
            </div>
            <div class="p-3 bg-card/60 rounded-lg border border-borderSubtle font-mono text-xs text-slate-400 space-y-1.5">
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>TLS/SSL Transport Encryption Check</span></div>
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>Authorization/ownership needs a separate controlled-account test</span></div>
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>PII & Response Payload Leakage Audit (SSN, Passwords, Keys)</span></div>
              <div class="flex items-center gap-2"><i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span>Privilege boundaries require independent server-side validation</span></div>
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
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Request headers (valid JSON; dedicated test credentials only):</label>
              <textarea id="api-req-headers" rows="3" class="w-full bg-slate-900 border border-borderSubtle rounded-lg p-2.5 font-mono text-xs text-sky-300 focus:outline-none focus:border-sky-500">${escapeHtml('{\n  "Accept": "application/json"\n}')}</textarea>
            </div>

            <!-- Body Textarea -->
            <div>
              <label class="block text-[11px] font-mono text-slate-400 mb-1">Request Body (JSON / Form):</label>
              <textarea id="api-req-body" rows="4" placeholder="{}" class="w-full bg-slate-900 border border-borderSubtle rounded-lg p-2.5 font-mono text-xs text-emerald-300 focus:outline-none focus:border-sky-500">${''}</textarea>
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
              <span id="api-resp-status-badge" class="px-2 py-0.5 rounded font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">Not observed</span>
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
      } catch(e){showToast('Invalid headers JSON. No request was sent.','error');if(btn){btn.disabled=false;btn.innerHTML=originalHtml;}return;}
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
          statusBadge.textContent = `${data.status_code ?? 'not observed'} ${data.status_code === 200 ? 'OK' : 'RESPONSE'}`;
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

        showToast(`Request executed: HTTP ${data.status_code ?? 'not observed'}`);
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

      const capturedStatus=Number(document.getElementById('api-observed-status')?.value);
      if(!document.getElementById('api-observed-confirm')?.checked||!Number.isInteger(capturedStatus)||capturedStatus<100||capturedStatus>599){showToast('Supply an actual observed status and explicitly confirm the authorized capture. No target request was sent.','info');return;}
      const capturedBody=document.getElementById('api-observed-body')?.value||'';
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
            headers: {},
            response_status: capturedStatus,
            response_body: capturedBody,
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
              <span class="text-slate-400">Captured-response heuristics:</span>
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
                <span>No candidates were found by these captured-response rules. Authorization and business logic remain untested.</span>
              </div>
            `}
          `;
          window.lucide?.createIcons();
        }

        showToast(`OWASP API Audit completed: ${escapeHtml(String(data.findings_count))} unverified candidates identified`);
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

    async function fuzzAllApiEndpoints(){showToast('Plan exact read-only API requests in Start Assessment. Discovery alone never authorizes tests.','info');document.getElementById('nav-assessment').click();}

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
