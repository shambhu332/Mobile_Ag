/* MobileAg copilot.js — ordered local classic-script module; shared workspace state is in workspace.js. */
    // Copilot Slide-Over Drawer
    function toggleCopilotDrawer() {
      copilotOpen = !copilotOpen;
      const drawer = document.getElementById('copilot-drawer');
      const chevron = document.getElementById('copilot-chevron');
      drawer.hidden=!copilotOpen;
      document.getElementById('evidence-summary-button').setAttribute('aria-expanded',String(copilotOpen));
      if(copilotOpen)document.getElementById('copilot-chat-input').focus();else document.getElementById('evidence-summary-button').focus();
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

    function askCopilotActivePoc(){askCopilotPrompt('Summarize the recorded candidates and coverage of the selected scan.');}

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
      if(!currentScan?.scan_id){showToast('Select a recorded scan before requesting its local evidence summary.','info');return;}
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
      assistantBubble.innerHTML = '<span class="animate-pulse text-sky-400 font-mono text-[10px]">Reading recorded evidence (local, no AI call)...</span>';
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
        assistantBubble.innerHTML = '<span class="text-red-400">Unable to load evidence summary. Select a scan, check your session and retry.</span>';
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
