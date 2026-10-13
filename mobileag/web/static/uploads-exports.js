/* MobileAg uploads-exports.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    // Modal, Drag & Drop, and Scan Launching
    function openNewScanModal() { document.getElementById('nav-assessment').click(); }
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
        return {error:'Please upload an APK, IPA or ZIP archive.'};
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

        showToast(`Uploaded ${String(data.filename ?? '')} (${String(data.size_mb ?? '')} MB)`, 'success');

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

        window.dispatchEvent(new CustomEvent('assessment-uploaded',{detail:{path:data.file_path,filename:data.filename,platform:data.platform}}));
        if (autoRunAfterUpload) {
          document.getElementById('nav-assessment').click();
          showToast('Upload ready. Approve APK/API scope and stages before starting tests.', 'info');
        }
        return data;
      } catch (err) {
        showToast(err.message || 'Upload error', 'error');
        return {error:err.message || 'Upload error'};
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
        showToast('Failed to start scan: '+err.message, 'error');
        document.getElementById('scan-modal').classList.remove('hidden');
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
      document.getElementById('export-menu-button').setAttribute('aria-expanded',String(!menu.classList.contains('hidden')));
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
      let md = `# MobileAg Security Audit Report\n\nTarget: ${currentScan.package_name}\nDate: ${currentScan.created_at}\nRevision: ${currentScan.revision || 0}\nArtifact SHA-256: ${currentScan.artifact_sha256 || "not recorded"}\n\nStatic candidates are not exploit proof.\n\n## Findings\n\n`;
      (currentScan.findings || []).forEach(f => {
        md += `### [${escapeHtml(String(f.severity))}] ${escapeHtml(String(f.title ?? ""))} (${escapeHtml(String(f.cwe_id))})\n`;
        md += `- Status: ${String(f.status || "UNVERIFIED")}\n- Validation notes: ${String(f.validation_notes || "None")}\n`;
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
        const scanId = currentScan.scan_id;
        if(!scanId)throw new Error('Select a real scan first');
        const res = await fetch(`/api/scans/${scanId}/sarif`);
        const sarifData = await res.json();
        const blob = new Blob([JSON.stringify(sarifData, null, 2)], { type: 'application/json' });
        downloadBlob(blob, `mobileag_report_${scanId}.sarif`);
        showToast('SARIF v2.1.0 exported successfully', 'success');
      } catch (err) {
        showToast('Error exporting SARIF report', 'error');
      }
    }

    async function exportReportCycloneDX() {
      toggleExportMenu();
      if (!currentScan) return;
      try {
        const scanId = currentScan.scan_id;
        if (!scanId) throw new Error('Select a real scan first');
        const res = await fetch(`/api/scans/${scanId}/cyclonedx`);
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        downloadBlob(blob, `mobileag_sbom_${scanId}_cyclonedx.json`);
        showToast('CycloneDX v1.5 SBOM exported successfully', 'success');
      } catch (err) {
        showToast('Error exporting CycloneDX SBOM', 'error');
      }
    }

    async function exportReportOpenAPI() {
      toggleExportMenu();
      if (!currentScan) return;
      try {
        const scanId = currentScan.scan_id;
        if (!scanId) throw new Error('Select a real scan first');
        const res = await fetch(`/api/scans/${scanId}/openapi`);
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        downloadBlob(blob, `mobileag_apis_${scanId}_openapi.json`);
        showToast('OpenAPI 3.0 specification exported successfully', 'success');
      } catch (err) {
        showToast('Error exporting OpenAPI specification', 'error');
      }
    }

    document.getElementById('btn-export-cyclonedx')?.addEventListener('click', exportReportCycloneDX);
    document.getElementById('btn-export-openapi')?.addEventListener('click', exportReportOpenAPI);

    function downloadBlob(blob, filename) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }
