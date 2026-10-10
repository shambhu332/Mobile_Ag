/* MobileAg taint.js — ordered local classic-script module; shared workspace state is in workspace.js. */
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

        // Modeled source: Intent extra string (external reachability is unverified)
        String targetUrl = getIntent().getStringExtra("target_url");

        // Intermediate variable propagation
        String candidateUrl = targetUrl;

        // Navigation sink candidate: validate scheme/host and effective guards (CWE-829 mapping is provisional)
        webView.loadUrl(candidateUrl);
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
        if(statConf)statConf.textContent='Not measured';
        if (statSev) statSev.textContent = 'NOT ASSESSED';
        container.innerHTML = `
          <div class="p-6 text-center text-slate-500 text-xs bg-card/40 rounded-lg border border-borderSubtle">
            <i data-lucide="shield-check" class="w-6 h-6 mx-auto mb-2 text-emerald-400"></i>
            No source-to-sink candidates were found by these heuristics. This does not establish that inputs are sanitized or the app is secure.
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
