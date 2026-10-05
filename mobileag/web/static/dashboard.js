/* MobileAg dashboard.js — ordered local classic-script module; shared workspace state is in workspace.js. */
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
        badge.textContent = 'Web static: offline (no model/OSV)';
      } catch (error) { badge.textContent = 'Policy unavailable: reconnect session'; }
    }

    // Initialize on page load
    window.addEventListener('DOMContentLoaded', async () => {
      showConnectionForm();
      await connectionReady;
      loadInitialScan();
      loadPrivacyPolicy();
      checkGraphStatus();
      connectTelemetryWebSocket();
      refreshDastDevices();
    });
