/* Overview presentation only. Upload stores an artifact; it never starts testing. */
(() => {
  const make = (tag, text, parent, className = '') => {
    const element = document.createElement(tag);
    if (text !== undefined && text !== null) element.textContent = String(text);
    if (className) element.className = className;
    parent?.append(element);
    return element;
  };

  function button(text, parent, action, className = 'console-button') {
    const element = make('button', text, parent, className);
    element.type = 'button';
    element.addEventListener('click', action);
    return element;
  }

  function icon(name, parent, className = 'console-icon') {
    const element = make('i', '', parent, className);
    element.dataset.lucide = name;
    element.setAttribute('aria-hidden', 'true');
    return element;
  }

  function navigate(view) {
    document.getElementById('nav-' + view)?.click();
    document.getElementById('workspace-title')?.focus();
  }

  const assessmentNav = document.getElementById('nav-assessment');
  const workspace = document.getElementById('view-surface')?.parentElement;
  if (!assessmentNav || !workspace || document.getElementById('view-overview')) return;

  const nav = button('', null, () => switchView('overview'), 'nav-item console-overview-nav');
  nav.id = 'nav-overview';
  icon('layout-dashboard', nav);
  make('span', 'Overview', nav);
  assessmentNav.before(nav);

  const root = make('div', '', workspace, 'view-panel h-full overflow-y-auto hidden console-overview');
  root.id = 'view-overview';

  const top = make('div', '', root, 'console-overview-grid');
  const uploadCard = make('section', '', top, 'console-card console-upload-card');
  uploadCard.setAttribute('aria-labelledby', 'console-upload-title');
  const uploadHeader = make('div', '', uploadCard, 'console-card-header');
  const uploadHeading = make('div', '', uploadHeader);
  make('h2', 'Analyze your mobile app', uploadHeading).id = 'console-upload-title';
  make('p', 'A clear starting point for your next security review.', uploadHeading, 'console-muted');
  make('span', 'APK & IPA', uploadHeader, 'console-pill');

  const dropzone = make('div', '', uploadCard, 'console-dropzone');
  dropzone.id = 'console-dropzone';
  dropzone.setAttribute('role', 'group');
  dropzone.setAttribute('aria-label', 'Upload an authorized mobile application');
  const uploadGlyph = make('div', '', dropzone, 'console-upload-glyph');
  icon('cloud-upload', uploadGlyph);
  make('h3', 'Drop your application here', dropzone);
  make('p', 'Choose an authorized Android APK or iOS IPA.', dropzone, 'console-muted');
  const file = make('input', '', dropzone);
  file.id = 'console-upload-file';
  file.type = 'file';
  file.accept = '.apk,.ipa';
  file.hidden = true;
  file.setAttribute('aria-label', 'Choose an authorized APK or IPA');
  const choose = button('Select application', dropzone, () => file.click(), 'console-button console-button-primary');
  choose.id = 'console-upload-button';
  make('p', 'Upload first. Review scope. Start only when you approve.', dropzone, 'console-upload-hint');

  const uploadStatus = make('p', 'Uploading alone never runs tests or selects a device.', uploadCard, 'console-upload-status');
  uploadStatus.id = 'console-upload-status';
  uploadStatus.setAttribute('role', 'status');
  uploadStatus.setAttribute('aria-live', 'polite');
  const uploadFooter = make('div', '', uploadCard, 'console-card-footer');
  make('span', 'Offline static analysis · Explicit live-test scope', uploadFooter, 'console-muted');
  button('Review assessment scope', uploadFooter, () => navigate('assessment'), 'console-text-button');

  const activity = make('section', '', top, 'console-card console-activity-card');
  activity.setAttribute('aria-labelledby', 'console-activity-title');
  const activityHeader = make('div', '', activity, 'console-card-header');
  make('h2', 'Current activity', activityHeader).id = 'console-activity-title';
  icon('activity', activityHeader);
  const activityBody = make('div', '', activity, 'console-activity-body');
  const activityActions = make('div', '', activity, 'console-card-footer');
  button('View scan history', activityActions, () => navigate('scans'), 'console-text-button');

  const metricsSection = make('section', '', root, 'console-metrics-section');
  metricsSection.setAttribute('aria-labelledby', 'console-metrics-title');
  const metricHeader = make('div', '', metricsSection, 'console-section-heading');
  make('h2', 'Candidate severity', metricHeader).id = 'console-metrics-title';
  const metricContext = make('p', '', metricHeader, 'console-muted');
  const metricGrid = make('div', '', metricsSection, 'console-metrics-grid');
  const metrics = new Map();
  for (const [severity, label] of [['CRITICAL', 'Critical'], ['HIGH', 'High'], ['MEDIUM', 'Medium'], ['LOW', 'Low'], ['INFO', 'Info']]) {
    const card = make('article', '', metricGrid, 'console-metric console-metric-' + severity.toLowerCase());
    card.dataset.severity = severity;
    const title = make('h3', label, card);
    title.id = 'console-severity-' + severity.toLowerCase();
    card.setAttribute('aria-labelledby', title.id);
    const value = make('p', '—', card, 'console-metric-value');
    value.id = 'console-count-' + severity.toLowerCase();
    make('p', 'Recorded candidates', card, 'console-muted');
    metrics.set(severity, value);
  }
  make('p', 'Severity describes review priority. Static candidates and zero counts are not a security verdict.', metricsSection, 'console-evidence-note');

  const lower = make('div', '', root, 'console-overview-grid console-overview-bottom');
  const selected = make('section', '', lower, 'console-card console-selected-card');
  selected.setAttribute('aria-labelledby', 'console-selected-title');
  const selectedHeader = make('div', '', selected, 'console-card-header');
  make('h2', 'Selected scan', selectedHeader).id = 'console-selected-title';
  const selectedStatus = make('span', 'No scan selected', selectedHeader, 'console-pill');
  const selectedBody = make('div', '', selected, 'console-selected-body');
  const selectedActions = make('div', '', selected, 'console-card-footer');
  const review = button('Review findings', selectedActions, () => navigate('findings'), 'console-button');
  const coverage = button('Inspect coverage', selectedActions, () => navigate('surface'), 'console-text-button');

  const next = make('section', '', lower, 'console-card console-workflow-card');
  next.setAttribute('aria-labelledby', 'console-workflow-title');
  const nextHeader = make('div', '', next, 'console-card-header');
  make('h2', 'Your workflow', nextHeader).id = 'console-workflow-title';
  const workflow = make('ol', '', next, 'console-workflow-list');
  for (const [number, title, description, destination] of [
    ['01', 'Prepare your assessment', 'Upload an owned app and approve exact scope.', 'assessment'],
    ['02', 'Configure your workspace', 'Check tools, scope and optional AI setup.', 'settings'],
    ['03', 'Review the evidence', 'Inspect candidates and record actual reproduction.', 'findings']
  ]) {
    const item = make('li', '', workflow);
    make('span', number, item, 'console-workflow-number').setAttribute('aria-hidden', 'true');
    const body = make('div', '', item);
    button(title, body, () => navigate(destination), 'console-text-button');
    make('p', description, body, 'console-muted');
  }

  let uploading = false;
  const connected = () => Boolean(localSessionActive);

  function updateUploadControls() {
    const disabled = uploading || !connected();
    choose.disabled = disabled;
    file.disabled = disabled;
    dropzone.dataset.busy = String(uploading);
    dropzone.setAttribute('aria-busy', String(uploading));
    choose.textContent = uploading ? 'Uploading application…' : 'Select application';
  }

  async function upload(files) {
    if (uploading) return;
    if (!connected()) {
      uploadStatus.textContent = 'Connect to your local session before uploading an application.';
      return;
    }
    if (!files?.length) return;
    if (files.length !== 1) {
      uploadStatus.textContent = 'Choose one application at a time. No file was uploaded.';
      return;
    }
    const selectedFile = files[0];
    if (!/\.(apk|ipa)$/i.test(selectedFile.name)) {
      uploadStatus.textContent = 'Choose an Android .apk or iOS .ipa file. No file was uploaded.';
      return;
    }
    uploading = true;
    updateUploadControls();
    uploadStatus.textContent = 'Uploading and validating ' + selectedFile.name + '. No testing has started.';
    try {
      const result = await uploadApkFile(selectedFile, false);
      if (result?.error || !result?.file_path) {
        uploadStatus.textContent = result?.error || 'Upload was not completed. Try again.';
        return;
      }
      if (!connected()) {
        uploadStatus.textContent = 'Upload completed. Reconnect your session before reviewing or starting any tests.';
        return;
      }
      if (result.platform === 'ios' || /\.ipa$/i.test(selectedFile.name)) {
        uploadStatus.textContent = 'IPA uploaded. Review the advanced offline static settings; testing starts only after an explicit Start.';
        document.getElementById('scan-modal')?.classList.remove('hidden');
      } else {
        uploadStatus.textContent = 'APK uploaded. Review exact scope and explicitly approve any tests in Start Assessment.';
        navigate('assessment');
      }
    } catch (error) {
      uploadStatus.textContent = error?.message || 'Upload failed. No testing was started.';
    } finally {
      uploading = false;
      file.value = '';
      updateUploadControls();
    }
  }

  file.addEventListener('change', () => {
    const files = [...file.files];
    file.value = '';
    upload(files);
  });
  dropzone.addEventListener('dragover', event => {
    event.preventDefault();
    event.stopPropagation();
    if (!uploading && connected()) dropzone.classList.add('console-drag-active');
  });
  dropzone.addEventListener('dragleave', event => {
    if (!dropzone.contains(event.relatedTarget)) dropzone.classList.remove('console-drag-active');
  });
  dropzone.addEventListener('drop', event => {
    event.preventDefault();
    event.stopPropagation();
    dropzone.classList.remove('console-drag-active');
    upload(event.dataTransfer?.files);
  });

  function renderScan() {
    const scan = currentScan?.scan_id ? currentScan : null;
    const findings = scan && Array.isArray(scan.findings) ? scan.findings : null;
    for (const [severity, value] of metrics) {
      value.textContent = findings ? String(findings.filter(finding => String(finding.severity || '').toUpperCase() === severity).length) : '—';
    }
    metricContext.textContent = findings ? findings.length + ' recorded candidates in the selected job' : scan ? 'Finding counts not recorded for this job' : 'No scan selected';
    review.disabled = !scan;
    coverage.disabled = !scan;
    selectedBody.replaceChildren();
    activityBody.replaceChildren();
    if (!scan) {
      selectedStatus.textContent = 'No scan selected';
      selectedStatus.dataset.status = 'empty';
      make('h3', 'Your next review starts here', selectedBody);
      make('p', 'Upload an authorized application or open a recorded job from Scan History.', selectedBody, 'console-muted');
      const emptyIcon = make('div', '', activityBody, 'console-empty-icon');
      icon('inbox', emptyIcon);
      make('h3', 'No scan selected', activityBody);
      make('p', 'Select a recorded job to see its actual status. No background assessment is implied.', activityBody, 'console-muted');
    } else {
      const status = String(scan.status || 'Not recorded');
      selectedStatus.textContent = status.replaceAll('_', ' ');
      selectedStatus.dataset.status = status.toLowerCase();
      const description = make('dl', '', selectedBody, 'console-scan-details');
      for (const [label, value] of [
        ['Application', scan.package_name || 'Not identified'],
        ['Version', scan.version || 'Not recorded'],
        ['Scan ID', scan.scan_id],
        ['Recorded', scan.created_at || 'Not recorded'],
        ['Artifact SHA-256', scan.artifact_sha256 || 'Not recorded']
      ]) {
        const row = make('div', '', description);
        make('dt', label, row);
        make('dd', value, row);
      }
      make('span', 'SELECTED JOB', activityBody, 'console-eyebrow');
      make('h3', scan.package_name || scan.scan_id, activityBody);
      make('p', status.replaceAll('_', ' '), activityBody, 'console-activity-status');
      make('p', scan.scan_id, activityBody, 'console-muted');
      make('p', 'Job completion does not establish exploitability. Review coverage and evidence before drawing conclusions.', activityBody, 'console-evidence-note');
    }
    window.lucide?.createIcons();
  }

  window.addEventListener('workspace-scan-changed', renderScan);
  window.addEventListener('workspace-session-connected', updateUploadControls);
  window.addEventListener('workspace-session-invalidated', () => {
    dropzone.classList.remove('console-drag-active');
    updateUploadControls();
    uploadStatus.textContent = 'Session disconnected. Reconnect before uploading an application.';
  });
  updateUploadControls();
  renderScan();
  // Select the initial view only after the presentation-only overview exists.
  switchView(activeView);
})();
