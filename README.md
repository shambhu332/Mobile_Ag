# MobileAg

Autonomous multi-agent mobile application security testing framework powered by LLMs and active runtime DAST.

MobileAg combines static code analysis (SAST), dynamic application security testing (DAST), multi-model LLM consensus auditing, and runtime sandbox forensics to detect vulnerabilities across Android applications with high precision and low false-positive rates.

---

## Key Features

### 1. Hybrid SAST Analysis Engine
- **Multi-LLM Consensus Engine**: Uses Gemini, OpenAI, Claude, DeepSeek, and Grok to analyze code and vote on findings to eliminate false positives.
- **5-Layer False Positive Filter**: Validates reachability, input sanitizers, historical pattern memory (Qdrant vector store), and LLM multi-model consensus.
- **Network Security Config Audit**: Detects user trust anchors, expired certificate pins, and cleartext traffic exemptions.
- **Binary Security Audits**: Evaluates native ELF/`.so` libraries for stack canaries (`__stack_chk_fail`), NX bit, RELRO, and PIE.
- **Cross-Platform Support**: Specialized scanners for React Native bundle secrets, Hermes bytecode, and routed deep links.
- **Android Keystore & Biometric Hardening**: Audits `KeyGenParameterSpec` for `setUserAuthenticationRequired(true)` and `BiometricPrompt` `CryptoObject` binding.

### 2. Dynamic Application Security Testing (DAST)
- **Rooted Device & Emulator Orchestration**: Direct ADB integration supporting rooted emulators (`su -c`) and automated component lifecycle testing.
- **Component & Intent Fuzzing**: Targeted intent extra mutation using keys extracted from static bytecode analysis (`getStringExtra`, `getIntExtra`), boundary values, and malformed URI payloads.
- **Live Logcat Telemetry**: Real-time logcat auditing for sensitive credential leakage (Bearer tokens, JWTs, API keys - CWE-532) and unhandled runtime exceptions/crashes (CWE-755).
- **Traffic & Proxy Auditing**: Analyzes HTTP transactions for cleartext communication (CWE-319), sensitive query parameters (CWE-598), and missing cache headers (CWE-524).
- **Sandbox Storage Forensics (`StorageAuditor`)**: Inspects `/data/data/<package_name>/` post-execution for unencrypted SQLite databases (CWE-312), plaintext SharedPreferences secrets (CWE-312), and cached authorization headers (CWE-524).
- **Dynamic Content Provider Auditing (`ProviderAuditor`)**: Probes exported providers (`content query`) for unauthorized data extraction (CWE-926) and raw SQL syntax error disclosure (CWE-89).

### 3. Interactive Web Security Dashboard
- **Modern AppSec Interface**: Real-time vulnerability management, attack surface graph visualization, and interactive DAST workbench.
- **Live WebSocket Telemetry**: Stream logcat feeds, fuzz execution logs, and sandbox forensic findings directly to the UI (`ws://127.0.0.1:8080/ws/telemetry`).
- **Interactive Device Control**: Connect remote ADB devices, enable root mode, launch components, fire custom deep links, take screenshots, and trigger dynamic audits directly from the browser.

### 4. PoC & Verification Automation
- **Frida Script Generation**: Synthesizes app-specific Frida hooks for runtime verification and SSL unpinning.
- **Step-by-Step PoC Guides**: Generates Markdown reproduction guides for confirmed vulnerabilities.
- **Version Diffing**: Compares two APK versions to highlight newly exposed attack surfaces, removed permission guards, and changed dependencies.

---

## Prerequisites

- **Python 3.11+**
- **Android SDK Platform-Tools (`adb`)** in `PATH`
- **`apktool`** and **`jadx`** in `PATH` (for APK decompilation)
- *Optional*: Rooted Android emulator (e.g., Android 9–14 AVD with root/su) or physical test device
- *Optional*: Docker Compose for Neo4j attack graph & Qdrant vector memory
- *Optional*: Ghidra for headless native binary deconstruction (`/opt/ghidra`)

---

## Installation & Setup

1. **Clone the repository and install dependencies**:
   ```bash
   git clone https://github.com/shambhu332/Mobile_Ag.git
   cd Mobile_Ag
   pip install -e .
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Add your API keys for Gemini, OpenAI, Anthropic, DeepSeek, or Grok
   ```

3. **(Optional) Launch Knowledge Graph & Vector Store**:
   ```bash
   docker compose up -d
   ```

---

## Usage

### 1. Launch the Web Security Dashboard
```bash
python -m mobileag.cli web --port 8080
```
Open [http://127.0.0.1:8080](http://127.0.0.1:8080) in your browser.

### 2. Run a Full SAST Scan
```bash
python -m mobileag.cli scan --apk target.apk --output ./results
```

### 3. Run Dynamic Analysis & DAST on a Device / Rooted Emulator
```bash
# Basic component & intent fuzzing
python -m mobileag.cli dast --serial emulator-5554 --pkg com.example.app

# Full DAST suite with sandbox storage forensics and Content Provider auditing
python -m mobileag.cli dast \
  --serial emulator-5554 \
  --pkg com.example.app \
  --audit-storage \
  --authorities com.example.app.provider \
  --activities com.example.app.MainActivity,com.example.app.DeepLinkActivity
```

### 4. Compare APK Versions (Differential Auditing)
```bash
python -m mobileag.cli diff --old v1.apk --new v2.apk --output ./diff_results
```

---

## Testing

Run the full automated test suite:
```bash
pytest -v
```

---

## Architecture & MASVS Mapping

MobileAg aligns findings with the **OWASP Mobile Application Security Verification Standard (MASVS)**:
- `MASVS-STORAGE`: Secure storage, SharedPreferences, SQLite encryption (CWE-312, CWE-524, CWE-922)
- `MASVS-CRYPTO`: Keystore parameter specifications, cipher modes, hardcoded keys (CWE-305, CWE-327, CWE-798)
- `MASVS-PLATFORM`: IPC, Intent redirection, exported providers/activities (CWE-926, CWE-927)
- `MASVS-NETWORK`: Cleartext traffic, TLS configurations, certificate pinning (CWE-319, CWE-295, CWE-598)
- `MASVS-CODE`: Buffer overflow mitigations, SQL injection, input validation (CWE-119, CWE-89)

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed pipeline schematics and design documentation.
