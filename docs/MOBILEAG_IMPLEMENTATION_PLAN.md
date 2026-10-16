# MobileAg Master Technical Architecture & Implementation Blueprint

## Purpose and Scope
This document provides an exhaustive, step-by-step technical implementation roadmap for expanding the **MobileAg** mobile security testing and assessment platform. It bridges the capabilities of commercial market leaders (**NowSecure**, **Oversecured**, **Appknox**, **Data Theorem**, **Guardsquare**, **Ostorlab**, and **Approov**) into MobileAg’s local-first, evidence-bound architecture.

Every section details:
- **Architectural Design & Purpose**
- **Exact File Locations & Target Modules**
- **Technical Algorithms & Data Flow**
- **Integration Points with MobileAg Core**

---

```
MobileAg Master Blueprint Architecture
├── 1. Advanced Static Analysis & Taint Tracking
│   ├── Inter-Procedural & Cross-File Call Graph Engine
│   ├── Component Lifecycle-Aware Flow Tracing
│   └── Android IPC Vulnerability Auditing (PendingIntent, FileProvider, Task Hijacking)
├── 2. Multi-Framework & Non-Dalvik Binary Analysis
│   ├── Flutter Dart Snapshot Symbol & String Extractor
│   ├── React Native Hermes (.hbc) Bytecode Decompiler
│   ├── Unity IL2CPP Reconstructor (Metadata + libil2cpp.so)
│   └── iOS Mach-O & Swift Metadata Analyzer
├── 3. Advanced Dynamic Instrumentation & Frida Harness
│   ├── Universal Stealth & Port-Randomized Frida Daemon
│   ├── Multi-Layer TLS/SSL Unpinning (Java, Native BoringSSL, Flutter)
│   ├── In-Memory Crypto & Key Lifecycle Harvester
│   └── Runtime Memory Forensics & Cleartext Cache Auditor
├── 4. Automated IPC Fuzzing & Exploit PoC Synthesis
│   ├── Dynamic Deep Link & Custom Scheme Mutation Fuzzer
│   ├── ContentProvider Traversal & Injection Fuzzer
│   └── Compilable Exploit PoC Generator (Oversecured/OVAA Parity)
├── 5. Mobile Backend API & Token Security Engine
│   ├── Automated API Cataloger & OpenAPI 3.0 / HAR Exporter
│   ├── Automated BOLA / IDOR Dual-Session Replay Fuzzer
│   └── Mobile Token & Session Lifecycle Auditor
├── 6. Binary Hardening & RASP Resilience Scoring
│   ├── 6-Vector MASVS-RESILIENCE Scoring Engine
│   ├── Obfuscation Ratio & Control Flow Flattening Calculator
│   └── Anti-Tampering, Anti-Debugging & Root Evasion Evaluator
├── 7. Autonomous Dynamic UI Exploration (Smart Crawler)
│   ├── Semantic UI Form Filling (Credentials, Search, Forms)
│   ├── OS Permission & Biometric Prompt Bypass
│   └── UI State Hashing & Loop Prevention
├── 8. Mobile SBOM, Supply Chain & Privacy Manifests
│   ├── Standardized CycloneDX v1.5 & SPDX 2.3 Generators
│   ├── Real-Time OSV Advisory Enrichment (Offline / Authorized Online)
│   └── Apple Privacy Manifest (PrivacyInfo.xcprivacy) & Google Play Data Safety Auditor
└── 9. Dashboard, Telemetry & Reporting Engine
    ├── WebSocket/SSE Real-Time Telemetry Stream
    ├── Interactive Attack Surface Graph Visualization (Vis.js / Neo4j)
    └── Enterprise Exporting (SARIF 2.1.0, Executive PDF, Professional Markdown)
```

---

## 1. Advanced Static Analysis: Inter-Procedural Taint & IPC Engine

### 1.1 Inter-Procedural Cross-File Call Graph & Taint Engine
* **Objective**: Overcome the single-file analysis barrier. Trace untrusted sources through arbitrary class wrappers, utility delegates, and helper chains to dangerous execution sinks.
* **Target Files**:
  - `mobileag/analysis/symbol_resolver.py` (New)
  - `mobileag/analysis/call_graph.py` (Enhancement)
  - `mobileag/analysis/java_ast_taint.py` (Enhancement)
  - `mobileag/analysis/taint_engine.py` (Enhancement)
* **Technical Implementation**:
  1. **Global Symbol Registry**: During initial decompilation, parse all class declarations and record their Fully Qualified Class Name (FQCN), superclasses, implemented interfaces, method signatures, and field declarations into an in-memory SQLite/KV store.
  2. **Inter-Procedural Call Linking**: When method `ClassA.entry()` calls `helper.process(input)`, resolve `helper`’s declared type via the Symbol Registry. Propagate the taint status of parameter `input` to the formal parameter of `ClassB.process()`.
  3. **Android Lifecycle Roots**: A bounded subset of exact callback signatures (`onNewIntent`, `onReceive`, `onStartCommand`, `onHandleIntent`, `onActivityResult`, `onBind`, `onUnbind`) now seeds incoming `Intent` parameters only when the parsed superclass chain reaches the expected Android base. This is not a complete lifecycle CFG, manifest-reachability, or component-registration analysis; other callbacks and callback variants remain unsupported.
  4. **Source-to-Sink Mapping**: Maintain strict evidence bounds:
     - *Smali source-to-sink model*: `Activity.getIntent()`/`Context.getIntent()`, bounded exact-signature lifecycle `Intent` callback parameters, `ContentResolver.query()`, and public Smali method parameters annotated with `@JavascriptInterface` are modeled as source candidates (the latter still needs bridge registration, enabled JavaScript, frame-origin and loaded-content review). Intent extra getters (`getStringExtra`, typed extras, `getExtras`/`getBundleExtra`) and `Intent.getData()`/`getDataString()`/`getScheme()`/`getAction()`/`getType()`/`getClipData()`, Bundle/Uri/Cursor accessors, and `ClipData` item/URI accessors derive taint only from an already-tainted receiver; `Uri.toString()` preserves that taint. A locally constructed or otherwise untainted Intent does not seed these accessors. This describes the bounded Smali register-flow model, not equivalent precision in Java AST/lexical analysis. External-content candidates flow from an already-tainted URI passed to selected `ContentResolver` open methods, or an already-tainted path passed through bounded `File`/`Path` conversions to selected stream constructors or NIO `Files` readers, through bounded read APIs. This does not prove path accessibility, URI reachability/grants, or attacker control of returned bytes.
     - *Sinks*: `startActivity()`, `Runtime.getRuntime().exec()`, `SQLiteDatabase.rawQuery()`, `WebView.loadUrl()`, `PendingIntent.send()`.

### 1.2 Android IPC Vulnerabilities: PendingIntent, FileProvider & Intent Redirection
* **Objective**: Detect advanced Android-specific IPC misconfigurations that commercial scanners frequently test.
* **Target Files**:
  - `mobileag/analysis/intent_redirection_auditor.py` (New)
  - `mobileag/analysis/pending_intent_auditor.py` (New)
  - `mobileag/analysis/fileprovider_auditor.py` (New)
* **Technical Implementation**:
  1. **Intent Redirection**: Detect when an exported component receives an Intent, extracts an embedded `Parcelable` Intent (`intent.getParcelableExtra(...)`), and passes it directly to `startActivity()` or `sendBroadcast()` without validating the target component or package name.
  2. **PendingIntent Mutability**: Verify that all `PendingIntent.getActivity/getBroadcast/getService` invocations specify `FLAG_IMMUTABLE` (Android 12+ mandate) or properly protect mutable intents (`FLAG_MUTABLE`) against unauthorized fill-in attacks.
  3. **FileProvider Path Traversal**: Parse `res/xml/` FileProvider path definitions. Flag dangerous configurations exposing the filesystem root (`<root-path path="." />`) or shared external storage (`<external-path path="." />`) combined with `android:grantUriPermissions="true"`.
  4. **Task affinity review**: Inventory activities' effective affinity, its origin (component, application, package default, or uniquely resolved alias target), and `launchMode`. Emit only a static review lead for exported activities/aliases with an observed non-default literal effective affinity. Alias target resolution fails closed when the target is missing or ambiguous. An absent activity value normally inherits the application/package default; `singleTask` is not a blanket mitigation and task-hijacking impact requires target-build/runtime evidence. See Android's [tasks and back stack guide](https://developer.android.com/guide/components/activities/tasks-and-back-stack), [`<activity>` reference](https://developer.android.com/guide/topics/manifest/activity-element), and [`<activity-alias>` reference](https://developer.android.com/guide/topics/manifest/activity-alias-element).

---

## 2. Multi-Framework & Non-Dalvik Binary Analysis

Traditional Dalvik-only decompilers fail when analyzing modern cross-platform applications. This phase implements dedicated extraction for Flutter, React Native, Unity, and iOS.

### 2.1 Flutter Dart Snapshot Extractor
* **Objective**: Recover routes, API endpoints, encryption keys, and business logic from stripped Flutter binaries.
* **Target Files**:
  - `mobileag/analysis/flutter_engine.py` (New)
* **Technical Implementation**:
  1. Check for `lib/arm64-v8a/libapp.so` and `libflutter.so`.
  2. Extract the Dart Snapshot Snapshot Hash from `libflutter.so`.
  3. Parse the Dart AOT Snapshot data section to recover:
     - Embedded string pools (recovering API URLs, authorization headers, hardcoded credentials).
     - Named route registries (identifying hidden or administrative application screens).
     - Bundled asset paths from `assets/flutter_assets/`.

### 2.2 React Native Hermes (`.hbc`) Bytecode Decompiler
* **Objective**: Decompile and audit optimized Hermes bytecode bundles.
* **Target Files**:
  - `mobileag/analysis/hermes_analyzer.py` (New)
  - `mobileag/analysis/react_native_scanner.py` (Enhancement)
* **Technical Implementation**:
  1. Inspect `assets/index.android.bundle` for the Hermes magic number `0x1F480120`.
  2. Read the Hermes bytecode version and invoke bounded disassembly (`hermes-dec` or `hbctool`) to extract:
     - Decompiled JavaScript control flow.
     - Hardcoded API tokens, OAuth client secrets, and environment configurations.
  3. Execute MobileAg’s AST and secret auditors on the recovered JavaScript files.

### 2.3 Unity IL2CPP Metadata & Binary Reconstructor
* **Objective**: Reconstruct class definitions, method names, and strings from Unity games and fintech apps.
* **Target Files**:
  - `mobileag/analysis/il2cpp_auditor.py` (New)
* **Technical Implementation**:
  1. Locate `lib/arm64-v8a/libil2cpp.so` and `assets/bin/Data/Managed/Metadata/global-metadata.dat`.
  2. Parse the IL2CPP metadata header to resolve string literal tables, method definitions, and type definitions.
  3. Export a reconstructed C# symbol table header (`dump.cs`) to expose backend endpoints and native encryption algorithms.

### 2.4 iOS Mach-O & Swift Metadata Analyzer
* **Objective**: Provide native iOS IPA binary analysis on parity with Android capabilities.
* **Target Files**:
  - `mobileag/analysis/ios_analyzer.py` (Enhancement)
  - `mobileag/analysis/macho_parser.py` (New)
* **Technical Implementation**:
  1. Parse Mach-O load commands, `__TEXT` segments, and `__cstring` tables.
  2. Extract Swift 5 runtime metadata (`__swift5_types`, `__swift5_proto`, `__swift5_fieldmd`) to reconstruct Swift class and struct definitions.
  3. Audit `Info.plist` for misconfigured App Transport Security (ATS) exceptions (`NSAllowsArbitraryLoads = true`) and dangerous custom URL schemes.

---

## 3. Dynamic Instrumentation & Runtime Frida Harness

### 3.1 Universal Stealth Instrumentation Daemon
* **Objective**: Run dynamic Frida tests reliably without triggering commercial anti-Frida or anti-debugging defenses.
* **Target Files**:
  - `mobileag/dast/frida_stealth.py` (New)
  - `mobileag/dast/frida_runner.py` (Enhancement)
  - `mobileag/dast/adb_manager.py` (Enhancement)
* **Technical Implementation**:
  1. **Binary Renaming & Socket Randomization**:
     - Automatically push a randomized-name binary (e.g., `mag_daemon_8492`) via ADB.
     - Bind to an ephemeral Unix domain socket or non-standard port instead of default TCP `27042`.
  2. **Thread & Memory Camouflage**:
     - Inject an early initialization hook that patches `pthread_create` to rename `gum-js-loop` threads.
     - Intercept `/proc/self/maps` and `/proc/self/status` reads to mask Frida-related memory mappings (`frida-agent.so`).

### 3.2 Universal Multi-Engine TLS/SSL Unpinning
* **Objective**: Enable full proxy interception across Java, native C++, and Flutter network stacks.
* **Target Files**:
  - `mobileag/dast/unpinning_engine.py` (New)
  - `mobileag/generators/templates/frida/unpinning.js` (Enhancement)
* **Technical Implementation**:
  1. **Java Layer**:
     - Hook `javax.net.ssl.TrustManagerFactory.getTrustManagers()`.
     - Hook `okhttp3.CertificatePinner.check()`.
     - Bypass `NetworkSecurityConfigProvider`.
  2. **Native C/C++ Layer**:
     - Hook OpenSSL/BoringSSL verification callbacks (`SSL_CTX_set_custom_verify`, `SSL_set_verify`).
  3. **Flutter Engine**:
     - Scan memory for `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so` and patch the return value to bypass pinning.

### 3.3 In-Memory Cryptography & Key Harvester
* **Objective**: Extract live encryption keys, initialization vectors, and plaintext payloads at runtime.
* **Target Files**:
  - `mobileag/dast/crypto_harvester.py` (New)
* **Technical Implementation**:
  1. Hook `javax.crypto.Cipher.init(int opmode, Key key, AlgorithmParameterSpec params)`:
     - Log algorithm name, mode (flagging `ECB`), and key size.
     - Capture raw key bytes from `SecretKeySpec.getEncoded()`.
  2. Hook `javax.crypto.Cipher.doFinal(byte[] input)` to capture unencrypted plaintext data before it is encrypted or after it is decrypted.
  3. Hook `net.sqlcipher.database.SQLiteDatabase.openOrCreateDatabase` to harvest local database encryption passwords.

---

## 4. Automated IPC Fuzzing & Exploit PoC Synthesis

### 4.1 Deep Link & Custom Scheme Mutation Fuzzer
* **Objective**: Verify if exported deep link handlers are vulnerable to open redirection, parameter tampering, or unauthorized state changes.
* **Target Files**:
  - `mobileag/dast/deeplink_intent_fuzzer.py` (New)
* **Technical Implementation**:
  1. Extract all declared URI schemes (`scheme://host/path?param=`) from the manifest and bytecode.
  2. Mutate parameters using defined payload suites:
     - External URL redirection payloads (`https://attacker.com`, `javascript:alert(1)`).
     - Path traversal strings (`../../sensitive_file`).
     - SQL injection probes (`' OR '1'='1`).
  3. Execute fuzzing runs via ADB:
     ```bash
     adb shell am start -W -a android.intent.action.VIEW -d "<payload>"
     ```
  4. Correlate with `logcat` dumps, WebView navigation events, and process crash logs to verify vulnerability execution.

### 4.2 ContentProvider Fuzzer & Traversal Tester
* **Objective**: Test exported ContentProviders for directory traversal and SQL injection vulnerabilities.
* **Target Files**:
  - `mobileag/dast/provider_fuzzer.py` (New)
  - `mobileag/dast/provider_auditor.py` (Enhancement)
* **Technical Implementation**:
  1. Identify all ContentProviders with `android:exported="true"`.
  2. Probe each provider with `adb shell content query` and `adb shell content read`:
     - Path Traversal: `content://<authority>/../../../../data/data/<package>/databases/app.db`
     - Projection/Selection SQLi: `content://<authority>/users --projection "* FROM users WHERE 1=1 --"`
  3. Verify whether file descriptors or database rows are leaked without required permissions.

### 4.3 Automated Exploit PoC Generator (Oversecured / OVAA Parity)
* **Objective**: Generate standalone, compilable exploit code proving the real-world impact of discovered vulnerabilities.
* **Target Files**:
  - `mobileag/generators/poc_apk_synthesizer.py` (New)
  - `mobileag/generators/templates/poc/` (Templates)
* **Technical Implementation**:
  1. For every confirmed high-severity IPC flaw, synthesize a complete Android exploit module:
     - Standalone Kotlin/Java activity source code.
     - `AndroidManifest.xml` targeting the vulnerable component.
     - Exact `Intent` construction with extras, flags, and URI parameters.
  2. Output both a standalone `.kt` script and a ready-to-run ADB exploit command line.

---

## 5. Mobile Backend API & Token Security Engine

### 5.1 Dynamic API Cataloger & OpenAPI 3.0 Exporter
* **Objective**: Map the entire attack surface of backend APIs utilized by the mobile application.
* **Target Files**:
  - `mobileag/dast/api_cataloger.py` (New)
  - `mobileag/dast/traffic_auditor.py` (Enhancement)
* **Technical Implementation**:
  1. Capture all HTTP/HTTPS transactions routed through `mobileag/dast/mitm_proxy.py`.
  2. Deduplicate requests by method, host, path template, and query parameter signatures.
  3. Infer request/response JSON schemas and auto-generate an **OpenAPI 3.0 specification (`openapi.json`)**.
  4. Flag "Shadow APIs" (undocumented endpoints seen in traffic that are not declared in mobile code).

### 5.2 Automated BOLA / IDOR Dual-Session Replay Fuzzer
* **Objective**: Automatically detect Broken Object Level Authorization across mobile APIs.
* **Target Files**:
  - `mobileag/dast/bola_fuzzer.py` (New)
  - `mobileag/dast/api_security_tester.py` (Enhancement)
* **Technical Implementation**:
  1. Accept two authorized test session tokens from the Test Plan (`Session_A` and `Session_B`).
  2. Identify API endpoints containing resource identifiers (e.g., `/api/v2/orders/94821` or `?account_id=104`).
  3. Replay requests for User A's resources using User B's authentication tokens.
  4. If the server returns HTTP 200 with User A's private data, generate a verified BOLA/IDOR finding with full HTTP request/response evidence.

### 5.3 Mobile Token & Session Lifecycle Auditor
* **Objective**: Audit mobile authentication tokens, JWT lifecycle claims, cleartext transmission, and session revocation.
* **Target Files**:
  - `mobileag/dast/token_session_auditor.py` (New)
  - `mobileag/dast/api_security_tester.py` (Enhancement)
* **Technical Implementation**:
  1. Parse JWT header and payload claims to flag insecure algorithm `none` (CWE-347) and weak symmetric keys (CWE-327).
  2. Inspect expiration claims (`exp`, `iat`) to detect missing expiration, expired tokens in use, or excessive lifetimes (CWE-613).
  3. Flag cleartext HTTP transmission of authorization tokens (CWE-319) and tokens passed in URL query strings (CWE-598).
  4. Detect session token reuse after logout or de-authentication requests (CWE-613).
  5. Calculate Shannon entropy to identify predictable, low-entropy session IDs (CWE-330).
  6. Opt-in offline HS256/HS384/HS512 verification using an explicitly researcher-supplied key; report only comparison status, enforce JWA minimum key byte length, and never infer server acceptance or key entropy from length.

---

## 6. Binary Hardening & RASP Resilience Scoring

### 6.1 6-Vector MASVS-RESILIENCE Scoring Engine
* **Objective**: Benchmark binary resilience against reverse engineering and tampering (Guardsquare/Promon parity).
* **Target Files**:
  - `mobileag/analysis/rasp_resilience_auditor.py` (New)
  - `mobileag/analysis/binary_protection_auditor.py` (Enhancement)
* **Technical Implementation**:
  Compute an aggregate **Resilience Score (0–100%)** based on six automated checks:

| Vector | Technical Metric | Evaluation Standard |
| :--- | :--- | :--- |
| **Identifier Obfuscation** | Ratio of short/scrambled identifiers (`a.b.c()`) vs. human-readable names. | MASVS-RESILIENCE-1 |
| **Control Flow Complexity** | Cyclomatic complexity and presence of switch-based state dispatchers. | MASVS-RESILIENCE-2 |
| **String Pool Entropy** | Shannon entropy calculation across string pools to detect string encryption. | MASVS-RESILIENCE-3 |
| **Anti-Root / Jailbreak** | Presence of heuristic checks for `su`, Magisk, Zygisk, and root packages. | MASVS-RESILIENCE-4 |
| **Anti-Debugging** | Enforcement of `debuggable="false"` and native `ptrace(PTRACE_TRACEME)` calls. | MASVS-RESILIENCE-5 |
| **Tamper Resistance** | Verification of APK signature check calls (`PackageManager.GET_SIGNATURES`). | MASVS-RESILIENCE-6 |

---

## 7. Autonomous Dynamic UI Exploration (Smart Crawler)

### 7.1 Semantic UI Form Filling & Navigation
* **Objective**: Replace dumb random monkey clicks with intelligent UI exploration that can navigate authentication forms and permission prompts.
* **Target Files**:
  - `mobileag/dast/smart_crawler.py` (New)
  - `mobileag/dast/ui_crawler.py` (Enhancement)
* **Technical Implementation**:
  1. **UI Hierarchy Parsing**: Dump the active view hierarchy via `uiautomator dump` or Android Accessibility services.
  2. **Semantic Element Recognition**:
     - Inputs matching `user|email|phone` or `pass|pin|secret` may be filled only with researcher-supplied synthetic values and an explicit `allow_test_credential_entry` opt-in; otherwise return `WAIT`.
     - Permission/consent buttons matching `allow|grant|accept` are recognized but must return `WAIT` for operator review; never auto-consent or tap them.
  3. **State Hashing & Loop Prevention**:
     - Compute a truncated SHA-256 state key over the activity and sorted resource IDs (or short visible labels for elements without IDs); raw labels are not persisted by the state counter.
     - Track visited state counts. Repeated-state `BACK` navigation, exploratory taps, and form submission are separate opt-ins; defaults return `WAIT`.

---

## 8. Mobile SBOM, Supply Chain & Privacy Compliance

### 8.1 Standardized CycloneDX v1.5 & SPDX 2.3 Exporter
* **Objective**: Generate enterprise-grade Software Bill of Materials for mobile applications.
* **Target Files**:
  - `mobileag/analysis/sbom_generator.py` (New)
  - `mobileag/analysis/dependency_scanner.py` (Enhancement)
* **Technical Implementation**:
  1. Catalog all Maven/Gradle libraries, embedded JNI native libraries (`.so`), and npm dependencies.
  2. Generate standard Package URLs (PURL): `pkg:maven/com.squareup.okhttp3/okhttp@4.9.3`.
  3. Export valid CycloneDX v1.5 JSON/XML and SPDX 2.3 manifests.
  4. Query the Open Source Vulnerabilities (OSV) database to attach known CVEs to inventoried components.

### 8.2 Privacy Manifest & Google Play Data Safety Auditor
* **Objective**: Verify compliance with Apple Privacy Manifests and Google Play Data Safety declarations.
* **Target Files**:
  - `mobileag/analysis/privacy_manifest_auditor.py` (New)
* **Technical Implementation**:
  1. **iOS Privacy Manifests**:
     - Parse `PrivacyInfo.xcprivacy`.
     - Cross-check declared API categories (`NSPrivacyAccessedAPITypeUserDefaults`, `SystemBootTime`) against actual binary calls to detect undeclared tracking APIs.
  2. **Android Data Safety**:
     - Correlate requested dangerous permissions (`ACCESS_FINE_LOCATION`, `READ_CONTACTS`) and third-party tracking SDKs with declared privacy disclosures.

---

## 9. Dashboard, Telemetry & Enterprise Reporting

### 9.1 Real-Time WebSocket Telemetry Streaming
* **Objective**: Provide live visual feedback of dynamic testing progress on the web dashboard.
* **Target Files**:
  - `mobileag/web/app.py` (Enhancement)
  - `mobileag/web/static/telemetry.js` (Enhancement)
* **Technical Implementation**:
  1. Implement a FastAPI WebSocket route (`/ws/scans/{scan_id}/telemetry`).
  2. Stream real-time events: tool execution status, Frida hook detections, captured HTTP requests, and crawler screenshots.

### 9.2 Interactive Attack Surface Graph (Vis.js / Neo4j)
* **Objective**: Visualize relationships between components, permissions, deep links, and APIs.
* **Target Files**:
  - `mobileag/knowledge/neo4j_graph.py` (Enhancement)
  - `mobileag/web/static/interface.js` (Enhancement)
* **Technical Implementation**:
  1. Render an interactive network graph of the mobile application:
     - Nodes: Activities, Services, ContentProviders, Receivers, API Endpoints, Local Databases.
     - Edges: Intents, URI Grants, Network Calls, Data Flows.
  2. Highlight vulnerable paths in red with click-to-expand evidence panels.

---

## Comprehensive Implementation Schedule & Status

> **Audit correction (refreshed 2026-10-15): this blueprint is not 100% complete.** The
> `[COMPLETED]` labels and the old “zero false-positive / fail-closed” claims
> below were not supported by the existence of files or unit tests. At baseline commit `728a007`, `python -m pytest -q` reported **892 passed**
> (57.51 s). After bounded native ELF SBOM inventory, the full suite in the
> pinned Python 3.14 validation environment reports **902 passed** (39.04 s).
> These are primarily mocked/synthetic regressions and do not establish device coverage,
> exploitability, completeness, or production readiness. The implementation
> names below indicate bounded prototypes unless the capability is separately
> demonstrated and measured. Do not use the original status tree as a release
> gate or claim of feature parity.

### Verified implementation status

| Blueprint area | Checkout evidence | Status / remaining work |
|---|---|---|
| Static call graph and taint | `call_graph.py`, `symbol_resolver.py`, `taint_engine.py`; synthetic tests include `test_smali_call_graph.py` and `test_smali_register_flow_benchmark.py` | **Partial.** Heuristic bounded analysis; no claim of arbitrary cross-language, whole-program or lifecycle-complete tracing. Smali source/sink recognition matches exact owner + method names; WebView sinks include `loadUrl`, `loadData`, `loadDataWithBaseURL`, and `postUrl`. Local may-flow propagates taint through supported exact-signature invocation arguments into static/instance callee parameter registers (including wide parameter slots), with source/sink file and line evidence. Intent extra/data/metadata accessors (`getStringExtra()`/typed extras/`getExtras()`, `getData()`/`getDataString()`/`getScheme()`/`getAction()`/`getType()`/`getClipData()`), Bundle/Uri getters, Cursor value getters (`getString`, `getBlob`, and primitive value accessors), and bounded ClipData item/URI getters derive taint only when their receiver already carries taint, avoiding unconditional source treatment for arbitrary internal objects; `Uri.toString()` preserves the taint. External-content candidates now require a tainted URI passed to selected `ContentResolver` open methods or a tainted path passed through a bounded `File(String)`/`File.toPath()` conversion to selected file-stream constructors / `Files.readString` / `Files.readAllBytes` / `Files.newInputStream` / `Files.newBufferedReader` (with `Paths.get` preserving taint); taint propagates through a bounded set of stream/reader constructors and scalar/array `read`, `readLine`, `readAllBytes`, and selected Scanner methods. Synthetic regressions exercise URI → ContentResolver → reader → `readLine` and a char-array `read` → array load → StringBuilder → WebView sink. This models a candidate read from a selected path/URI input, not proof that the path resolves to content accessible to the app, that a URI is reachable or granted, that returned bytes are attacker-controlled, or that the source is authentic; platform API availability is also unresolved. Bounded array-element taint tracks stores and loads through array-register aliases, but does not distinguish indexes or prove array/object identity. Primitive register moves and supported arithmetic operators preserve taint as a conservative may-flow. Supported String transformations plus bounded StringBuilder/StringBuffer constructor, mutator, and toString operations preserve taint through local object-register aliases; builder identity across fields and calls is unresolved. Exact static-field reads/writes and bounded method-return summaries propagate tainted register values between exact methods, but not callee heap side effects; instance fields and heap identity are not modeled. A limited set of exact Android callback signatures (`onNewIntent`, `onReceive`, `onStartCommand`, `onHandleIntent`, `onActivityResult`, `onBind`, and `onUnbind`) seeds the incoming `Intent` parameter for derived accessors only when the parsed superclass chain reaches the expected Android callback base; synthetic negative controls now verify a same-named callback on a non-Android class and a normal helper `Intent` parameter are not treated as lifecycle roots. This does not prove component registration, export state, caller privileges, or runtime reachability. Public `@JavascriptInterface` annotated method parameters are seeded as untrusted-source candidates, but annotation presence does not establish WebView bridge registration, enabled JavaScript, target API behavior, frame origin, loaded content, or reachability. This is not full interprocedural taint: instance fields and heap side effects, virtual dispatch/overrides, sanitizers, exception semantics, platform reachability and authorization are unresolved; budgets and skipped methods are exposed. The synthetic local-register evaluator now also covers a provider Cursor flow, NIO path reads, and hard-negative untainted URI/path controls; it still measures only public individual CWE/sink-line cases (including duplicate CWEs and conditional branches), not blind or independent accuracy, cross-file accuracy, APK recall, or field false-positive rates. Independent corpora and broad unsupported-syntax accounting remain open. |
| IPC / FileProvider | `manifest_auditor.py`, `intent_redirection_auditor.py`, `pending_intent_auditor.py`, `fileprovider_auditor.py` | **Implemented as candidate analyzers.** Findings require component reachability, effective platform permission/grant behavior, and caller-controlled input validation; manifest patterns alone are not exploits. FileProvider XML scanning now uses bounded no-symlink inventory reads (5,000 entries, 2 MiB/file, 32 MiB total), filters to `res/xml*`, avoids duplicate recursive/direct matches, exposes coverage, and reports parse/size/root-shape errors. Intent-redirection lexical scans now use the same file/entry/total bounds, skip symlinks, expose partial coverage, and reject forward-in-time extraction matches; method scope and component reachability remain unresolved, so findings are review candidates only. PendingIntent Java/Kotlin scans now use bounded no-symlink reads with coverage surfaced in the scan and receive the parsed target SDK. Missing mutability on target API 31+ is reported as an INFO compatibility lead (expected Android 12+ creation failure if executed), not a CWE-927 exploit claim; unknown/older targets retain a bounded mutability review candidate. Token distribution, receiver capability, and runtime path still require review. Task-affinity inventory now resolves an alias to exactly one parsed activity using canonicalized component names; it inherits affinity and launch mode from that target per Android's alias semantics and emits an INFO lead only for an exported alias with a literal non-default effective affinity. Missing/ambiguous targets withhold effective alias values and findings. This is not a StrandHogg exploit verdict or a blanket `singleTask` recommendation. Deep-link mutation generation now bounds input/query count, percent-encodes payloads while preserving other parameters, and the ADB launcher quotes each remote-shell argument; execution still requires an explicit serial and just-in-time scope guard. Launcher stdout/stderr are drained with a 4 KiB retained prefix per stream and are not persisted in results; observed byte count/truncation is exposed. The helper does not collect logcat/crash tombstones or establish exploitability, and generic activity-manager errors are not labeled crashes. Provider fuzz probes now require an explicit serial and per-command scope guard, validate authority/package/projection input, issue read-only SQL probe cases against both selection and projection fields, and quote remote shell arguments; they drain stdout/stderr concurrently while retaining at most 4 KiB per stream, expose observed byte counts/truncation, and omit raw provider output from result records. Neither these probes nor the other candidate analyzers establish runtime exploitability; FileProvider binary resources are not decoded. |
| Flutter / Hermes / IL2CPP | `flutter_engine.py`, `hermes_analyzer.py`, `il2cpp_auditor.py` | **Partial string/metadata probes, not decompilers.** Flutter binary reads now have both per-file and 32 MiB aggregate byte budgets; printable-string iteration is capped at 100,000 per binary and distinct endpoint/route/secret-marker output is capped, with explicit truncation errors. Asset/tree inventory is bounded, symlink inputs are skipped, and truncation, scan status, byte counts, and errors are exposed. Flutter still scans only bounded printable strings, not Dart snapshot structures. Hermes bundle reads now use one bounded no-follow read, cap retained strings/endpoints, redact credential-like values in returned samples, and report truncation/read state; `function_count` remains unknown rather than a misleading zero. The Hermes pass is still printable-string extraction, not a structured Hermes string-table parser or bytecode decompiler. IL2CPP now bounds tree and metadata reads, skips symlink paths, reports partial scan state and caps output candidates; magic/version plus printable strings are still not parsed IL2CPP tables, and class-like names are only lexical candidates (not reconstructed types). Credential-like matches emit redacted review markers rather than raw/candidate values. No Dart snapshot reconstruction, Hermes control-flow decompilation, or IL2CPP type/method table reconstruction is implemented. |
| iOS Mach-O / Swift | `macho_parser.py`, `ios_analyzer.py` | **Partial structural parser and bounded Swift name/field inventory.** The bounded thin 32/64-bit passes validate header/load-command and `LC_SEGMENT`/`LC_SEGMENT_64` section bounds, inventory dylib load commands and bounded `LC_SYMTAB` names, recognize Swift section names from actual section records, and extract capped printable strings only from parsed `__cstring` file ranges. A bounded `__swift5_types` pass resolves direct relative entries for class/struct/enum context descriptors and emits valid UTF-8 nominal type-name candidates. A bounded `__swift5_protos` pass now resolves direct protocol descriptor entries and emits protocol-name candidates; relative-indirectable entries remain partial and are not dereferenced. When direct field metadata is present, the parser validates the `__swift5_fieldmd` section/record bounds and returns UTF-8 field-name candidates grouped by type; it does not resolve field types or reconstruct declarations. Malformed ranges and unresolved names produce partial status. This is not full metadata/type/field/protocol reconstruction; protocol conformances from `__swift5_proto`, requirement signatures, and associated-type semantics remain unparsed. Parse status/errors and section/import/symbol/Swift type/field/protocol inventories are exposed with the iOS analysis summary; legacy whole-file Swift section-name, URL, and framework strings remain lexical candidates distinct from parsed section/import evidence. Fat/FAT64 architecture tables now receive bounded slice-count/range and table-vs-slice CPU agreement validation; complete `__TEXT`/cstring coverage above the 15 MiB input cap and robust independent malformed-corpus validation remain incomplete. Synthetic fixtures prove only these specific cases, not universal Mach-O compatibility.
| Frida stealth, TLS bypass, crypto harvesting | `dast/frida_stealth.py`, `unpinning_engine.py`, `crypto_harvester.py` | **Not accepted as a completed or safe feature.** Scripts are generators; no current-device validation is implied. Anti-detection/evasion and bypass behavior are outside this plan's completion criteria. Preserve explicit scope and do not treat modified-lab observations as ordinary-app proof. |
| IPC fuzzing / PoC synthesis | `deeplink_intent_fuzzer.py`, `provider_fuzzer.py`, `generators/poc_apk_synthesizer.py` | **Prototype / not proof-grade.** Provider probes now report read/query success and SQL errors as observations, not vulnerability verdicts. Generated PoCs still need parameter validation and evidence-bound review; no gate establishes independent confirmation before generation. The dashboard now defers the generated-PoC request until the researcher explicitly opens that finding’s PoC tab; the read-only loopback navigator allows only the matching bounded GET route. Dynamic use requires exact authorization and human review. |
| API catalog / BOLA / token review | `api_cataloger.py`, `bola_fuzzer.py`, `token_session_auditor.py`, scoped capture/export endpoints | **Partial.** Catalog/schema inference and token heuristics do not establish server-side authorization flaws. Captured, redacted HTTP traffic can be exported as observed OpenAPI/HAR inventory; export routes are session-authenticated and separate from device-action middleware. The offline `/api/dast/traffic/audit` endpoint optionally compares supplied captured transactions with typed static endpoint declarations; it sends no requests and reports `not_requested` when declarations are absent. Traffic-audit findings normalize identifier-shaped paths and omit URL userinfo/query values rather than copying captured URLs into evidence. Shadow-API review normalizes numeric/UUID/email/token-shaped route IDs, supports method-specific declarations and canonical origin matching (including omission of default HTTP/HTTPS ports), and omits userinfo, query values, and raw ID-shaped path values; declarations supplied as path-only strings are origin/method wildcards. These remain unverified leads because static endpoint extraction may be incomplete. BOLA candidate extraction is offline-only and bounds URLs to 8,192 characters, query metadata to 100 fields, and candidate values to 256 characters; malformed authorities and over-limit query sets fail closed. TrafficAuditor caps sensitive-query parsing at 256 fields and emits an explicit incomplete-coverage lead rather than treating an over-limit URL as a clean CWE-598 review. The evaluator requires an explicit researcher-provided account-A marker; generic HTTP 200 is inconclusive. Result records omit raw resource IDs, credentials, and endpoint query/fragment data, template recognized identifier path segments, and retain only a digest rather than the response body; response hashing and canary comparison are capped at 1 MiB of text and explicitly mark truncated/invalid input. An offline dual-session observation comparator now requires the same supplied canary in successful A and B responses, but does not verify account identity, request equivalence, ownership, or server authorization. It remains an evaluator, not a replay system; no network requests are performed. JWT parsing is bounded and claim findings are explicitly unverified; output omits raw tokens and arbitrary header/claim values, retains only algorithm/lifecycle/claim-name indicators, and sanitizes endpoint URLs. An opt-in offline verifier now supports HS256/HS384/HS512 only with an explicitly supplied local key and constant-time comparison; asymmetric algorithms, key discovery, server acceptance, and key entropy/strength beyond JWA's minimum byte length are not assessed. The verifier is not automatically applied to captured traffic. Logout/reuse is only a same-token, status-sequence observation, not proof a protected resource was authorized. OpenAPI grouping preserves canonical per-origin servers, omits userinfo/default ports, and brackets IPv6 literals for valid server URLs. Captured route paths replace numeric, canonical UUID, email-shaped, and token-shaped opaque segments (at least 24 mixed alphanumeric/underscore/hyphen characters) with required string path parameters; this heuristic may parametrize long route slugs and does not cover shorter or differently encoded IDs. JSON shape inference omits value-like object keys (UUIDs, long tokens/IDs, numeric IDs, and email-shaped keys) and marks that redaction; property values are never exported. Query-key signatures are deduplicated separately and merged as observed parameters, without exporting observed path/query values in the OpenAPI document. Generated documents are validated locally with pinned `openapi-spec-validator` 0.9.0. Malformed authorities/ports, overlong URLs, and unsupported schemes are excluded from OpenAPI endpoint modeling and counted under `invalidURLs`/`unmodeledRequests`; query metadata is parsed centrally and capped at 100 fields with 256-character names; traffic-catalog adapters do not expand query strings before the cap, and over-limit captures are counted as unmodeled instead of producing partial query signatures. Cataloger HAR retention is separately capped at 10,000 transactions, 2 MiB per transaction, and 16 MiB estimated aggregate; over-budget transactions are omitted while bounded endpoint modeling continues when inputs permit, and the capture estimates/omission counts are exposed. JSON shape inference also rejects bodies over a 1 Mi-character cap before decoding. Bounded HAR export still redacts captured values. HTTPS capture and dual-session replay remain open. |
| RASP / resilience | `rasp_resilience_auditor.py` | **Bounded Smali string/name inventory only.** Aggregate and per-vector scores/pass states are withheld (`null`); control-flow assessment is explicitly unknown rather than inferred from obfuscation, and string entropy is not treated as proof of encryption. Traversal/read limits and partial coverage are exposed by the API. Candidate strings do not establish reachable/effective defenses. No MASVS conformance or runtime resistance is demonstrated. |
| Smart UI crawler | `smart_crawler.py`, `ui_crawler.py` | **Safety correction made in this revision.** No hard-coded credentials. Permission/consent prompts always stop at `WAIT`; researcher-supplied test credential entry, form submission, exploratory taps, and repeated-state `BACK` navigation each require explicit opt-in. Runtime UI observation now requires an explicit serial, validated package name, and just-in-time scope guard; the background DAST workflow propagates that guard. Legacy tap/text helpers are inert and issue no ADB commands; the observer only returns planned-action review data. Both hierarchy parsers cap input at 2 Mi characters and reject more than 5,000 nodes; DTD/entity declarations are rejected, and over-limit/malformed input produces no partial action candidates. This is bounded parser behavior, not an assurance of safe or accurate UI interpretation. |
| SBOM / privacy | `sbom_generator.py`, `dependency_scanner.py`, `privacy_manifest_auditor.py` | **Partial.** Bounded Maven/npm inventory and opt-in OSV lookup are implemented in `dependency_scanner.py`; lookup is blocked in offline mode and results remain unverified. Dependency scans now inventory bounded ELF `ET_DYN` `.so` candidates by path, SHA-256, class and machine; native release versions and vulnerability advisories are not inferred. Pinned CycloneDX 1.5 JSON/XSD (including its SPDX and JSF dependencies) and SPDX 2.3 JSON schemas validate populated synthetic JSON/XML output offline in regression tests. The normative XSD test exposed and fixed an XML element-order defect when component hashes/licenses were present. iOS privacy-manifest inventory now parses bounded manifests across the app/framework tree, reports parse/shape errors and per-manifest declarations, and avoids coercing malformed tracking values to true. Android Data Safety review now parses actual permission XML elements (rather than substring matches) and bounds Java/Kotlin/Smali inventory with no-follow reads and explicit partial-coverage metadata on emitted leads. These are static indicators only: this does not inspect binary API use, prove manifest completeness, establish SDK execution/data sharing, or determine any Play Console declaration or privacy compliance. HAR recognized credential fields are redacted before export. |
| Telemetry / graph / exports | `web/app.py`, `knowledge/neo4j_graph.py`, reporting modules | **Partial.** Session-authenticated `/ws/scans/{scan_id}/telemetry` is implemented with subscription isolation; `/ws/telemetry` remains the authenticated legacy aggregate stream. HAR exports now redact recognized credential fields. Synthetic browser navigation now verifies all eleven dashboard sections, explicit PoC retrieval, and axe checks at desktop/mobile viewports; test-plan legend contrast was corrected. This scoped browser check is not a complete WCAG claim. This does not demonstrate production-scale telemetry, complete graph data flow, OpenAPI conformance, or release readiness. |

### Safety and completion boundary

The blueprint's stealth/anti-detection daemon, TLS/certificate-pinning bypass,
raw cryptographic-key/plaintext harvesting, and automatic acceptance of OS
permission/biometric prompts are **not completion targets**. They can defeat
security controls, expose secrets, or consent on behalf of a user. Existing
generators/prototypes are not authorization to execute them and must not be
described as complete. Safe dynamic work remains researcher-selected, scoped,
transparent, and subject to operator review. No target/device activity is
implied by this plan.

The API capture additions in the 2026-10-15 checkout expose observed, redacted
transactions as OpenAPI/HAR inventory through authenticated endpoints. OpenAPI
includes bounded JSON shape inference without example values; it describes
observations, not a complete backend contract. Generated OpenAPI documents
are now checked with pinned `openapi-spec-validator` during export and in
regressions. Proxy capture retention is bounded by transaction count and
an estimated in-memory byte budget, with omission/eviction counts exposed.
HTTPS interception and automatic replay/fuzzing remain absent.

### Release gates still required

1. Define measurable acceptance criteria per feature and identify unsupported
   formats, parser failures, truncation, false positives, and false negatives.
2. Validate generated CycloneDX/SPDX/OpenAPI outputs against their normative
   schemas/specifications, not only local object-shape assertions. This is now
   regression-gated for populated synthetic CycloneDX 1.5 JSON/XML and SPDX 2.3
   JSON documents, using hash-pinned local schema fixtures and no schema network
   retrieval. OpenAPI 3.0 generation invokes a pinned offline validator and has
   positive/negative regression coverage. This does not validate every optional
   field combination, establish SBOM inventory completeness, or prove an inferred
   API document is a complete backend contract.
3. Add independent blind/hard-negative corpora and instance/location matching;
   never equate passing synthetic fixtures with zero false positives.
4. For dynamic stages, capture exact authorized artifact/device/build/account,
   positive and negative controls, and attributable evidence. No device or live
   target validation was run for this checkout audit.
5. Keep operator approval at permission, credential entry, external network,
   instrumentation, generated-PoC review, and data-changing boundaries. Do not mark a feature done
   based only on a module, generated script, or mocked command.

### Sensitive-value output handling

On 2026-10-15, synthetic probes confirmed the Flutter, Hermes, and IL2CPP
string scanners previously returned credential-like text and matched values
in their result objects. They now return only a generic redacted review marker;
regressions assert synthetic credential literals do not appear in that output.
This narrows accidental report/API exposure but does not prove that all
downstream logs, caches, or other analyzers are free of secrets. Static
credential candidates remain unverified and must be reviewed locally against
the preserved artifact; do not copy secrets into durable evidence.

### iOS Privacy Manifest parsing boundary

The iOS manifest pass now inspects at most 128 manifests and 50,000 tree
entries, reads only regular non-symlink manifest files up to 2 MiB, and
preserves per-manifest declarations so a tracking declaration in one framework
cannot be incorrectly paired with domains from another. Results report
`absent`, `parsed`, `partial`, or `invalid` plus bounded error codes. These are
parser/inventory statuses only; required-reason API call analysis and validation
against current Apple submission requirements remain unimplemented.

### Token/session evidence boundary

The token-session auditor now caps transaction, token, and query parsing,
accepts only object JWT header/payload roots, keeps only algorithm, numeric
lifecycle-claim, and sensitive-claim-name indicators, and omits raw tokens and
arbitrary header/claim values. It also omits URL userinfo,
query values, fragments, and token-like path segments from finding
locations. `alg=none`, expired-claim, low-entropy, and post-logout reuse outputs
are explicitly unverified observations. A captured HTTP status does not prove
that a protected operation was authorized; no dual-account replay or live API
testing was performed. An opt-in local method verifies HS256/HS384/HS512 JWS
signatures only when the researcher supplies the key; it enforces minimum key
byte lengths but cannot infer entropy, find keys, verify asymmetric algorithms,
or prove that a server accepted the token. It does not persist or echo the key
and is not automatically run over captured transactions. The JWS signing input
and HMAC procedure follow [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html)
and [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html).

### Native ELF SBOM inventory boundary

The dependency scan now includes `.so` files with valid 32-/64-bit ELF headers
and `ET_DYN` type as generic components in its CycloneDX/SPDX inputs. This is
an inventory candidate classification, not proof a file is a shared library or
loaded by the app. It streams SHA-256 hashes and records a generic PURL derived
from the extracted relative path;
no vendor version, SONAME identity, dependency graph, or native advisory match
is inferred. Limits are 50,000 tree entries, 1,000 libraries, 128 MiB per
library, and 1 GiB total hashed data. Symlinks, non-ELF `.so` candidates,
oversized inputs, and I/O failures make native inventory status partial or
invalid rather than a clean complete result. This is not exhaustive supply-chain
inventory and does not establish that a library is loaded or used at runtime.

### RASP resilience inventory boundary

The Smali string inventory uses the shared no-symlink `SourceInventory` reader:
at most 5,000 tree entries, 2 MiB per Smali file, and 32 MiB total source bytes.
String-entropy samples are capped at 500 strings and 256 characters per sample.
Skipped files and limit conditions appear in the resilience API's `coverage`
object; a partial scan must not be interpreted as absence of indicators. This
inventory does not inspect native code, prove runtime control flow, or score
defense effectiveness.

```
Timeline & Execution Inventory [audited 2026-10-15; NOT COMPLETE]
├── Phase 1: Static Engine & Frameworks [PARTIAL; bounded analyzers exist]
├── Phase 2: Dynamic Engine & Frida [GENERATORS EXIST; runtime validation NOT DONE]
├── Phase 3: IPC Fuzzing & API [PROTOTYPES EXIST; confirmed exploitation NOT DONE]
├── Phase 4: RASP, SBOM & Automation [PARTIAL; measurement/format validation open]
└── Phase 5: Dashboard & Reporting [PARTIAL; tests pass, production gates open]
```

---

## Verification & Quality Assurance Gates

1. **Unit & regression suite**: On 2026-10-15, baseline commit `728a007` completed with 892 passed in 57.51 s; after OpenAPI changes the suite completed with 893 passed in 88.52 s. The pinned Python 3.14 environment completed with 895 passed after SBOM schema validation, 898 after token-session evidence hardening, 900 after exact Smali source/sink matching, and 902 after native ELF inventory (39.04 s; 1 synthetic duplicate-ZIP-entry warning). These results are not device/live-target validation.
2. **Synthetic regressions**: Tests exercise selected fixtures and mocks only. GitHub Actions run `38774618068` completed successfully on commit `7a85d3a`: 900 passed, 2 skipped, 1 warning. The workflow's pinned dependency installation, accuracy checks, reproducible wheel, asset verification, installed-wheel smoke, and synthetic browser suite passed. Browser checks used synthetic loopback services, no device, APK, or live target. Separately, the local pinned Python 3.14 environment reported 902 passed and 1 warning (39.04 s); CI skips two tests. No measured false-positive/false-negative rate or zero-leakage claim is established. SBOM regression tests use hash-pinned local CycloneDX 1.5 JSON/XSD, SPDX/JSF imported schema files, and SPDX 2.3 JSON schema fixtures. Provenance, upstream URLs, licenses, and expected digests are documented in `tests/fixtures/sbom_schemas/README.md`; the CycloneDX XSD import is resolver-mapped to a pinned local file with lxml network access disabled.
3. **Evidence semantics**: Several current workflows preserve candidate/observation distinctions, but no claim is made that every analyzer or stage has independently verified fail-closed behavior. See the release gates above.
4. **Scope boundary**: No APK, device, API origin, or researcher-controlled account was supplied for live validation in this task; no dynamic target testing was performed.

