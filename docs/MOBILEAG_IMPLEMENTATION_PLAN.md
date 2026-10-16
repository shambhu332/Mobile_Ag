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
| Static call graph and taint | `call_graph.py`, `symbol_resolver.py`, `taint_engine.py`; synthetic tests include `test_smali_call_graph.py` and `test_smali_register_flow_benchmark.py` | **Partial.** Heuristic bounded analysis; no claim of arbitrary cross-language, whole-program or lifecycle-complete tracing. Smali source/sink recognition matches exact owner + method names; WebView sinks include `loadUrl`, `loadData`, `loadDataWithBaseURL`, and `postUrl`. Local may-flow propagates taint through supported exact-signature invocation arguments into static/instance callee parameter registers (including wide parameter slots), with source/sink file and line evidence. Intent extra/data/metadata accessors (`getStringExtra()`/typed extras/`getExtras()`, `getData()`/`getDataString()`/`getScheme()`/`getAction()`/`getType()`/`getClipData()`), Bundle/Uri getters, Cursor value getters (`getString`, `getBlob`, and primitive value accessors), and bounded ClipData item/URI getters derive taint only when their receiver already carries taint, avoiding unconditional source treatment for arbitrary internal objects; `Uri.toString()` preserves the taint. External-content candidates now require a tainted URI passed to selected `ContentResolver` open methods or a tainted path passed through a bounded `File(String)`/`File.toPath()` conversion to selected file-stream constructors / `Files.readString` / `Files.readAllBytes` / `Files.newInputStream` / `Files.newBufferedReader` (with `Paths.get` preserving taint); taint propagates through a bounded set of stream/reader constructors and scalar/array `read`, `readLine`, `readAllBytes`, and selected Scanner methods. Synthetic regressions exercise URI → ContentResolver → reader → `readLine` and a char-array `read` → array load → StringBuilder → WebView sink. This models a candidate read from a selected path/URI input, not proof that the path resolves to content accessible to the app, that a URI is reachable or granted, that returned bytes are attacker-controlled, or that the source is authentic; platform API availability is also unresolved. Bounded array-element taint tracks `filled-new-array` elements and `aput`/`aget` through register aliases, but does not distinguish indexes or prove array/object identity. `fill-array-data` clears the destination register's tracked element-taint summary because its static payload replaces contents, but alias/object identity effects remain unresolved and register-flow coverage is marked partial. Primitive register moves, supported numeric conversions, and supported arithmetic operators (including `rsub-int/lit8`) preserve taint as a conservative may-flow; wide writes clear both destination words, and wide moves merge taint from either source word; untainted arithmetic and constant writes including `const-method-type`/`const-method-handle` clear stale register taint. Supported String transformations plus bounded StringBuilder/StringBuffer constructor, mutator, and toString operations preserve taint through local object-register aliases; builder identity across fields and calls is unresolved. Exact static-field reads/writes and bounded method-return summaries propagate tainted register values between exact methods, but not callee heap side effects; instance-field reads clear overwritten register taint and mark coverage partial to avoid stale-value false positives, and instance-field writes also mark partial coverage because field-value propagation and heap identity remain unmodeled. A limited set of exact Android callback signatures (`onNewIntent`, `onReceive`, `onStartCommand`, `onHandleIntent`, `onActivityResult`, `onBind`, and `onUnbind`) seeds the incoming `Intent` parameter for derived accessors only when the parsed superclass chain reaches the expected Android callback base; synthetic negative controls now verify a same-named callback on a non-Android class and a normal helper `Intent` parameter are not treated as lifecycle roots. This does not prove component registration, export state, caller privileges, or runtime reachability. Public `@JavascriptInterface` annotated method parameters are seeded as untrusted-source candidates, but annotation presence does not establish WebView bridge registration, enabled JavaScript, target API behavior, frame origin, loaded content, or reachability. This is not full interprocedural taint: instance fields and heap side effects, virtual dispatch/overrides, unsupported invoke forms such as `invoke-custom`/`invoke-polymorphic` (which mark coverage partial but do not propagate return taint), unrecognized destination-shaped register writes (which clear stale destination taint, mark coverage partial, and do not assume operand propagation), tainted arguments passed to calls without a local implementation or modeled summary mark coverage partial (their return/heap effects are not propagated), sanitizers, exception semantics, platform reachability and authorization are unresolved; budgets and skipped methods are exposed. The synthetic local-register evaluator now also covers a provider Cursor flow, NIO path reads, and hard-negative untainted URI/path controls; it still measures only public individual CWE/sink-line cases (including duplicate CWEs and conditional branches), not blind or independent accuracy, cross-file accuracy, APK recall, or field false-positive rates. Packed/sparse switch payload target resolution has synthetic positive coverage; malformed and over-limit payloads now have regressions confirming partial coverage is reported rather than silently accepted. Register-flow diagnostics retain at most 100 warning samples and expose total observed warning events plus whether samples were truncated; this improves visibility but is not comprehensive Smali opcode/syntax coverage. Independent corpora remain open. |
| IPC / FileProvider | `manifest_auditor.py`, `intent_redirection_auditor.py`, `pending_intent_auditor.py`, `fileprovider_auditor.py` | **Implemented as candidate analyzers.** Findings require component reachability, effective platform permission/grant behavior, and caller-controlled input validation; manifest patterns alone are not exploits. FileProvider XML scanning now uses bounded no-symlink inventory reads (5,000 entries, 2 MiB/file, 32 MiB total), filters to `res/xml*`, avoids duplicate recursive/direct matches, exposes coverage, reports parse/size/root-shape errors, and rejects DTD/entity declarations before XML parsing. Broad `external-media-path` roots (`.` or empty) are included as unverified configuration review candidates. Empty/`.` `files-path` and `cache-path` roots (including equivalent slash/dot spellings) are also recorded as INFO candidates because they map entire app-internal directories; no grant or external access is inferred. A literal `..` path segment now emits an INFO, unverified FileProvider configuration review candidate; it does not establish canonicalized root escape, a URI grant, or caller access. FileProvider analyzer descriptions require separate evidence of a served URI, effective grant, and caller reachability rather than implying unauthorized access from XML alone. Intent-redirection lexical scans now use the same file/entry/total bounds, skip symlinks, expose partial coverage, and reject forward-in-time extraction matches; method scope and component reachability remain unresolved, so findings are review candidates only. PendingIntent Java/Kotlin scans now use bounded no-symlink reads with coverage surfaced in the scan and receive the parsed target SDK. Missing mutability on target API 31+ is reported as an INFO compatibility lead (expected Android 12+ creation failure if executed), not a CWE-927 exploit claim; unknown/older targets retain a bounded mutability review candidate. Token distribution, receiver capability, and runtime path still require review. Task-affinity inventory now resolves an alias to exactly one parsed activity using canonicalized component names; it inherits affinity and launch mode from that target per Android's alias semantics and emits an INFO lead only for an exported alias with a literal non-default effective affinity. Missing/ambiguous targets withhold effective alias values and findings. This is not a StrandHogg exploit verdict or a blanket `singleTask` recommendation. Deep-link mutation generation now bounds input/query count, percent-encodes payloads while preserving other parameters, and the ADB launcher quotes each remote-shell argument; execution still requires an explicit serial and just-in-time scope guard. Launcher stdout/stderr are drained with a 4 KiB retained prefix per stream and are not persisted in results; observed byte count/truncation is exposed. The helper does not collect logcat/crash tombstones or establish exploitability, and generic activity-manager errors are not labeled crashes. Provider fuzz probes now require an explicit serial and per-command scope guard, validate authority/package/projection input, issue read-only SQL probe cases against both selection and projection fields, and quote remote shell arguments; they drain stdout/stderr concurrently while retaining at most 4 KiB per stream, expose observed byte counts/truncation, and omit raw provider output from result records. Neither these probes nor the other candidate analyzers establish runtime exploitability; FileProvider binary resources are not decoded. |
| Flutter / Hermes / IL2CPP | `flutter_engine.py`, `hermes_analyzer.py`, `il2cpp_auditor.py` | **Partial string/metadata probes, not decompilers.** Flutter binary reads now have both per-file and 32 MiB aggregate byte budgets; printable-string iteration is capped at 100,000 per binary and distinct endpoint/route/secret-marker output is capped, with explicit truncation errors. Flutter binary and asset discovery, and IL2CPP library discovery, use the bounded no-symlink `SourceInventory` instead of unbounded `os.walk` directory materialization; Flutter applies one shared tree-entry cap across library and asset inventory and rejects symlinked parent paths. Truncation, scan status, byte counts, and errors are exposed. Flutter still scans only bounded printable strings, not Dart snapshot structures. URLs from Flutter, Hermes, and IL2CPP are propagated as UNKNOWN-method embedded-string candidates; the orchestrator does not infer an HTTP method or callability from a URL string. Hermes bundle reads now use one bounded no-follow read, cap printable-string iteration and retained strings/endpoints, redact credential-like values in returned samples, and mark the scan partial with explicit errors when input or candidate output is truncated; `function_count` remains unknown rather than a misleading zero. The Hermes pass is still printable-string extraction, not a structured Hermes string-table parser or bytecode decompiler. IL2CPP now validates the version-29 global-metadata header ranges and bounded string-literal records (8-byte records, bounded literal sizes/count/UTF-8 reads), and extracts URL/secret-marker/class-name candidates from those parsed literals without retaining raw literal values. Unsupported metadata versions retain a bounded printable-string fallback; malformed v29 tables yield partial coverage. Tree and metadata reads, literal/candidate iteration, and endpoint/class outputs are bounded, and symlink paths are skipped. A bounded v29 type/member-table pass now resolves class namespaces/names, field names, method names, and parameter names/counts into review-only records. It does not resolve field/return/parameter types, generic constructs, native method bodies, or emit a complete `dump.cs`; names are metadata candidates, not source reconstruction. The orchestrator now retains bounded structured IL2CPP metadata summaries in scan state and API responses, with explicit static-candidate, non-exhaustive, runtime-not-tested, and not-proven labels; analysis errors are reflected as incomplete coverage. Other versions and format variants remain unsupported or unverified, and no independent corpus establishes format coverage. Credential-like matches emit redacted review markers rather than raw/candidate values. No Dart snapshot reconstruction or Hermes control-flow decompilation is implemented; the IL2CPP parser does not produce a complete C# symbol dump or method/type signatures. |
| iOS Mach-O / Swift | `macho_parser.py`, `ios_analyzer.py` | **Partial structural parser and bounded Swift name/field inventory.** The bounded thin 32/64-bit passes validate header/load-command and `LC_SEGMENT`/`LC_SEGMENT_64` section bounds, inventory dylib load commands and bounded `LC_SYMTAB` names, recognize Swift section names from actual section records, and extract capped printable strings only from parsed `__cstring` file ranges. A bounded `__swift5_types` pass resolves direct relative entries for class/struct/enum context descriptors and emits valid UTF-8 nominal type-name candidates. A bounded `__swift5_protos` pass now resolves direct protocol descriptor entries and emits protocol-name candidates; relative-indirectable entries remain partial and are not dereferenced. When direct field metadata is present, the parser validates the `__swift5_fieldmd` section/record bounds and returns UTF-8 field-name candidates grouped by type; it does not resolve field types or reconstruct declarations. Malformed ranges and unresolved names produce partial status. This is not full metadata/type/field/protocol reconstruction; protocol conformances from `__swift5_proto`, requirement signatures, and associated-type semantics remain unparsed. Parse status/errors and section/import/symbol/Swift type/field/protocol inventories are exposed with the iOS analysis summary; legacy whole-file Swift section-name, URL, and framework strings remain lexical candidates distinct from parsed section/import evidence. Fat/FAT64 architecture tables now receive bounded slice-count/range and table-vs-slice CPU agreement validation. Mach-O input is opened as a no-follow regular file and a truncated read forces partial status for thin and fat files; lexical URL enumeration and returned endpoint candidates are capped with explicit partial status. Complete `__TEXT`/cstring coverage above the 15 MiB input cap and robust independent malformed-corpus validation remain incomplete. Synthetic fixtures prove only these specific cases, not universal Mach-O compatibility.
| Frida stealth, TLS bypass, crypto harvesting | `dast/frida_stealth.py`, `unpinning_engine.py`, `crypto_harvester.py` | **Not accepted as a completed or safe feature.** Scripts are generators; no current-device validation is implied. Anti-detection/evasion and bypass behavior are outside this plan's completion criteria. Preserve explicit scope and do not treat modified-lab observations as ordinary-app proof. |
| IPC fuzzing / PoC synthesis | `deeplink_intent_fuzzer.py`, `provider_fuzzer.py`, `generators/poc_apk_synthesizer.py` | **Prototype / not proof-grade.** Provider probes now report read/query success and SQL errors as observations, not vulnerability verdicts. PoC generation now requires a CONFIRMED lifecycle state plus active structured analyst-attested evidence bound to the exact target package; this is not independent verification. Unverified, malformed, inactive, or cross-package evidence returns no PoC. Generated commands/source remain review artifacts with `execution_authorized=false`; no tool execution occurs. Full parameter validation, independent confirmation, and proof-grade generation remain open. The dashboard defers generation until the researcher opens that finding’s PoC tab; the read-only loopback navigator allows only the matching bounded GET route. Dynamic use requires exact authorization and human review. |
| API catalog / BOLA / token review | `api_cataloger.py`, `bola_fuzzer.py`, `token_session_auditor.py`, scoped capture/export endpoints | **Partial.** Catalog/schema inference and token heuristics do not establish server-side authorization flaws. Captured, redacted HTTP traffic can be exported as observed OpenAPI/HAR inventory; export routes are session-authenticated and separate from device-action middleware. The offline `/api/dast/traffic/audit` endpoint optionally compares supplied captured transactions with typed static endpoint declarations; it sends no requests and reports `not_requested` when declarations are absent. Traffic-audit findings normalize identifier-shaped paths and omit URL userinfo/query values rather than copying captured URLs into evidence. Shadow-API review normalizes numeric/UUID/email/token-shaped route IDs, supports method-specific declarations and canonical origin matching (including omission of default HTTP/HTTPS ports), and omits userinfo, query values, and raw ID-shaped path values; declarations supplied as path-only strings are origin/method wildcards. Static `APIMapper` blanks Java/Kotlin comments, Smali `#` comments, XML comments (preserving CDATA), and JS/Dart line/block comments while retaining string literals and line offsets; JS/Dart route-template interpolations are normalized to `{id}`, and unclosed XML comments/CDATA mark coverage partial, then extracts Retrofit verb/path declarations (including HEAD/OPTIONS and literal Retrofit `@HTTP` method/path pairs), route-literal endpoint candidates across Java/Kotlin as well as resource/bundle sources, and URL review leads with relative source-file and 1-based line evidence; route-only candidates retain `method=UNKNOWN`, and unknown/custom Retrofit method tokens are never guessed (their literal path may still appear as a route-only candidate); the general `@HTTP` annotation parser is quote-aware and capped at 4 KiB, with unsupported or oversized declarations reflected in partial-coverage diagnostics. Route output strips URL userinfo, drops query/fragment values, percent-encodes path controls, and templates obvious numeric, UUID, email, and opaque mixed path IDs; Empty/missing API-mapping roots return `not_analyzed` rather than resolving `Path("")` to the process working directory. Retrofit, route-literal, and URL matches are iterated lazily, endpoint de-duplication uses normalized redacted routes, and reaching the finding cap marks coverage partial. This best-effort redaction does not guarantee removal of arbitrary secrets. These remain unverified leads because static endpoint extraction may be incomplete. BOLA candidate extraction is offline-only and bounds URLs to 8,192 characters, query metadata to 100 fields, and candidate values to 256 characters; malformed authorities and over-limit query sets fail closed. TrafficAuditor caps sensitive-query parsing at 256 fields and emits an explicit incomplete-coverage lead rather than treating an over-limit URL as a clean CWE-598 review. The evaluator requires an explicit researcher-provided account-A marker; generic HTTP 200 is inconclusive. Result records omit raw resource IDs, credentials, and endpoint query/fragment data, template recognized identifier path segments, and retain only a digest rather than the response body; response hashing and canary comparison are capped at 1 MiB of text and explicitly mark truncated/invalid input. An offline dual-session observation comparator now requires the same supplied canary in successful A and B responses, but does not verify account identity, request equivalence, ownership, or server authorization. It remains an evaluator, not a replay system; no network requests are performed. JWT parsing is bounded and claim findings are explicitly unverified; output omits raw tokens and arbitrary header/claim values, retains only algorithm/lifecycle/claim-name indicators, and sanitizes endpoint URLs. An opt-in offline verifier now supports HS256/HS384/HS512 only with an explicitly supplied local key and constant-time comparison; asymmetric algorithms, key discovery, server acceptance, and key entropy/strength beyond JWA's minimum byte length are not assessed. The verifier is not automatically applied to captured traffic. Logout/reuse is only a same-token, status-sequence observation, not proof a protected resource was authorized. OpenAPI grouping preserves canonical per-origin servers, omits userinfo/default ports, and brackets IPv6 literals for valid server URLs. Static URL review recognizes bracketed IPv6 authorities, case-insensitive schemes, and escaped slash separators in serialized source strings, emitting only unverified literal-use candidates; it does not test network reachability or effective cleartext policy. Captured route paths replace numeric, canonical UUID, and email-shaped segments, long mixed alphanumeric token-shaped segments, and shorter (8-23 character) mixed-case alphanumeric segments with required string path parameters; percent-encoded ASCII is decoded only for this redaction decision. This privacy-first heuristic may parametrize route slugs, while short lowercase IDs, malformed encodings, or other encodings may remain unmodeled. JSON shape inference omits value-like object keys (UUIDs, long tokens/IDs, numeric IDs, and email-shaped keys) and marks that redaction; property values are never exported. Query-key signatures are deduplicated separately and merged as observed parameters, without exporting observed path/query values in the OpenAPI document. Generated documents are validated locally with pinned `openapi-spec-validator` 0.9.0. Malformed authorities/ports, overlong URLs, and unsupported schemes are excluded from OpenAPI endpoint modeling and counted under `invalidURLs`/`unmodeledRequests`; query metadata is parsed centrally and capped at 100 fields with 256-character names; traffic-catalog adapters do not expand query strings before the cap, and over-limit captures are counted as unmodeled instead of producing partial query signatures. Cataloger HAR retention is separately capped at 10,000 transactions, 2 MiB per transaction, and 16 MiB estimated aggregate; over-budget transactions are omitted while bounded endpoint modeling continues when inputs permit, and the capture estimates/omission counts are exposed. JSON shape inference also rejects bodies over a 1 Mi-character cap before decoding. Bounded HAR export still redacts captured values. HTTPS capture and dual-session replay remain open. |
| RASP / resilience | `rasp_resilience_auditor.py` | **Bounded Smali string/name inventory only.** The API inventories all discovered canonical `smali` / `smali_classesN` roots under a shared entry/file/byte budget and exposes root-discovery and analysis coverage; ambiguous roots, multiple extraction bases, symlinks, or truncated discovery fail closed. Aggregate and per-vector scores/pass states are withheld (`null`); control-flow assessment is explicitly unknown rather than inferred from obfuscation, and string entropy is not treated as proof of encryption. Candidate strings do not establish reachable/effective defenses. No MASVS conformance or runtime resistance is demonstrated. |
| Smart UI crawler | `smart_crawler.py`, `ui_crawler.py` | **Safety correction made in this revision.** No hard-coded credentials. Permission/consent prompts always stop at `WAIT`; researcher-supplied test credential entry, form submission, exploratory taps, and repeated-state `BACK` navigation each require explicit opt-in. Runtime UI observation now requires an explicit serial, validated package name, and just-in-time scope guard; the background DAST workflow propagates that guard. Legacy tap/text helpers are inert and issue no ADB commands; the observer only returns planned-action review data. Both crawler hierarchy parsers cap input at 2 Mi characters and reject more than 5,000 nodes; DTD/entity declarations are rejected, and over-limit/malformed input produces no partial action candidates. The separate Android automation snapshot parser caps encoded input at 1 MiB and now also rejects DTD/entity declarations before parsing. These are bounded parser behaviors, not assurances of safe or accurate UI interpretation. |
| SBOM / privacy | `sbom_generator.py`, `dependency_scanner.py`, `privacy_manifest_auditor.py` | **Partial.** Bounded Maven/npm inventory and opt-in OSV lookup are implemented in `dependency_scanner.py`; lookup is blocked in offline mode and results remain unverified. Dependency scans inventory bounded ELF `ET_DYN` `.so` candidates by path, SHA-256, class and machine; native release versions and vulnerability advisories are not inferred. Native-library tree discovery uses the shared bounded no-symlink inventory, so directory entries are capped before traversal results are sorted/materialized. iOS privacy-manifest candidates and Android Java/Kotlin/Smali source paths also use bounded no-symlink `SourceInventory` traversal; Android source reads retain per-file and aggregate byte caps, and coverage reports entry/file/read limits and skipped symlinks. Pinned CycloneDX 1.5 JSON/XSD (including its SPDX and JSF dependencies) and SPDX 2.3 JSON schemas validate populated synthetic JSON/XML output offline in regression tests. The normative XSD test exposed and fixed an XML element-order defect when component hashes/licenses were present. iOS privacy manifests are parsed across the app/framework tree, report parse/shape errors and per-manifest declarations, and avoid coercing malformed tracking values to true. Android Data Safety review is included in the orchestrator, reads the extracted manifest through a bounded no-follow regular-file read, rejects DTD/entity declarations, and parses actual permission XML elements (rather than substring matches). Its manifest/source coverage is retained in scan coverage even when no finding is emitted. A bounded main-executable symbol-to-app-manifest cross-check emits only informational, unverified candidates; embedded frameworks and Objective-C dispatch remain outside this pass. These are static indicators only: they do not prove API reachability, manifest completeness, SDK execution/data sharing, or any Play Console declaration or privacy compliance. HAR recognized credential fields are redacted before export. |
| Telemetry / graph / exports | `web/app.py`, `knowledge/neo4j_graph.py`, reporting modules | **Partial.** Session-authenticated `/ws/scans/{scan_id}/telemetry` is implemented with subscription isolation; `/ws/telemetry` remains the authenticated legacy aggregate stream. Graph writes now namespace component, finding, and endpoint uniqueness keys by scan and type while preserving display labels, preventing new writes from merging equal entities across scans under the existing global constraints. Finding CWE access now uses the model's actual `cwe_id` field. Synthetic tests verify distinct keys and display values with a mocked Neo4j session, not live database isolation. Existing graph records are not migrated; rebuild/cleanup is needed before assuming historical separation. HAR exports now redact recognized credential fields. Synthetic browser navigation verifies all eleven dashboard sections, explicit PoC retrieval, and axe checks at desktop/mobile viewports; test-plan legend contrast was corrected. This scoped browser check is not a complete WCAG claim. Neo4j vulnerability nodes now carry the original finding ID separately from their scan-scoped storage key, and graph clicks resolve through that identity to the finding evidence panel; a synthetic browser regression covers this cross-ID path. Neo4j and embedded graph vulnerability nodes now retain an allowlisted finding lifecycle status and proof label, surfaced in hover metadata; missing legacy node labels remain unknown until records are rewritten. New API inventory edges use `HAS_API_CANDIDATE` rather than `CALLS_API`; both new and legacy endpoint edges export as `endpoint_candidate`. Legacy endpoint records without a recognized evidence type fail closed to `method=UNKNOWN`, `evidence_type=legacy_endpoint_candidate`, and `proof_status=not_proven`; URL strings are not rendered as verified calls. Historical Neo4j relationship types are read as candidates, not migrated. The graph still does not demonstrate complete data flow, explicit URI-grant/network/data-flow edges, or validated vulnerable paths. The legacy attack-chain helper now returns no paths rather than treating app-level component/finding co-occurrence as a chain; production-scale telemetry, OpenAPI conformance, and release readiness also remain unestablished. |

Framework-detection missing-input behavior is also fail-explicit: an empty,
missing, or non-directory decompilation root returns `Unknown` with the shared
coverage schema (`not_analyzed`, `proof_status=not_proven`, non-exhaustive)
rather than omitting coverage. Synthetic tests cover these invalid-input cases;
they do not establish APK framework-detection completeness.

The decoded Android manifest ingestion path now reads only a no-follow regular
file, enforces an 8 MiB XML input cap, and rejects DTD/entity declarations
before ElementTree parsing. The APK extractor's separate package-name probe
now applies the same file type, size, and DTD/entity safeguards (returning
`unknown` on rejected input). Its referenced FileProvider XML inventory likewise
uses a bounded no-follow read (64 KiB) and rejects DTD/entities before parsing.
Synthetic tests cover DTD/entity, oversize, and final-symlink cases. This does
not harden every XML consumer or make extraction ancestor directories
race-proof.

The APK extractor's materialized Smali file-count and class-descriptor
comparisons now enumerate through the shared bounded no-symlink inventory
instead of `os.walk` directory lists. Entry-cap truncation and skipped paths
produce `capped` / `incomplete` outcomes, withholding descriptor sets rather
than claiming exact DEX-to-Smali correspondence. The provenance regressions
passed (**21 passed**); the full suite passed (**1,083 passed**, 40.65 s; one
expected synthetic duplicate-ZIP-member warning). `compileall` and
`git diff --check` passed. This does not prove decompiler completeness or
APK-wide class coverage.

The isolated-worker disk-budget monitor and evidence-publication symlink check
now share a bounded no-follow tree measurement rather than materializing
unbounded `os.walk` directory listings. Over-budget or incomplete publication
trees fail closed; worker-created symlinks are rejected before evidence is
moved into the scan output. Synthetic tests cover entry caps, regular-file byte
accounting, and linked evidence. This does not create a filesystem snapshot or
eliminate concurrent mutation races while a worker is still running. Focused
worker-tree/session tests passed (**5 passed**); the full suite passed
(**1,085 passed**, 41.07 s; one expected synthetic duplicate-ZIP-member
warning). `compileall` and `git diff --check` passed.

IPA extraction now scans the direct `Payload` entries under a fixed cap, rejects
symlink app bundles, and requires exactly one top-level `.app` instead of
materializing all matches and silently selecting the first. Synthetic tests
cover ambiguous app bundles and the entry cap. This makes bundle selection
deterministic but does not validate IPA signing or app runtime behavior. Focused
IPA tests passed (**3 passed**); the full suite passed (**1,086 passed**, 40.27
s; one expected synthetic duplicate-ZIP-member warning). `compileall` and
`git diff --check` passed.

Legacy dashboard snapshot import is now bounded by tree-entry, per-file, and
aggregate-byte budgets; it considers only direct scan-child `dashboard.json`
files, uses no-follow reads, and returns explicit partial coverage when files
are skipped or limits are reached. Synthetic tests cover a successful import,
a symlinked scan directory, and entry-budget truncation. Focused and full
tests passed (**4 passed** and **1,088 passed**, 40.92 s; one expected synthetic
duplicate-ZIP-member warning). `compileall` and `git diff --check` passed. This
legacy migration path is not a scan result completeness claim.

Network Security Configuration XML is also rejected when it contains DTD/entity
declarations, for both manifest-reference discovery and the configuration
audit; the existing no-follow, size-bounded file reader remains in force. A
synthetic DTD fixture verifies that the config is not interpreted and coverage
becomes partial. No Android platform behavior or live TLS policy was tested.

The report review-surface ledger now distinguishes configured analyzer paths
from paths absent in the scan record: absent mapped paths appear in
`missing_coverage_paths` and as explicit `coverage not recorded` gap reasons.
Synthetic coverage-ledger tests verify this for a partial WebView/deep-link
surface. Existing `analysis_state` still describes only observed analyzer
execution; it is not a completeness or security result. Both standard Markdown
and professional report output now render those per-path gap reasons instead
of showing only the broad surface limitation.

An `explicit_scan_root` normalizer now prevents `None`, empty, and whitespace
roots from becoming `Path("")` / the process working directory in the
CodeReviewer, TaintEngine, SecretScanner, NativeAnalyzer, DependencyScanner,
and FileProvider analyzer entry points. Missing inputs return empty/not-analyzed
coverage or pass `None` to bounded readers; the regression tests replace scan
functions with fail-on-call stubs. An explicit `"."` remains a caller-selected
root. This is not yet a guarantee that every analyzer API or caller handles
invalid roots identically.

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
`absent`, `parsed`, `partial`, or `invalid` plus bounded error codes. A bounded
review-only cross-check now compares up to 2,000 symbol names from the parsed
main executable against the app-root manifest's required-reason API categories;
missing declarations produce informational, unverified review candidates, not
compliance violations. This does not trace reachable calls, Objective-C message
dispatch, embedded framework use, runtime execution, or determine current Apple
submission requirements. Symbol absence is not evidence of API absence, and
symbol presence is not proof of API use.

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

### BOLA candidate extraction boundary

Offline BOLA resource-ID extraction now excludes query fields whose normalized
names contain credential indicators (`token`, `auth`, `password`, `secret`,
`session`, `cookie`, `bearer`, `credential`, or `key`) before selecting
identifier-like fields. This avoids misclassifying values such as
`user_token`/`accessToken` as object IDs. It does not establish ownership,
authorization behavior, or perform requests; path and query identifiers that
remain candidates still require authorized manual handling. Candidate values
with whitespace or ASCII/C1 control characters are rejected to prevent malformed
query data from entering identifier lists used by downstream tooling.

The researcher-canary response evaluator now never sets its legacy
`is_vulnerable` field true: observed canary matches are recorded separately as
`candidate_observed=true`, with `proof_status=not_proven`. A captured response
cannot verify account identity, request equivalence, object ownership, or
server-side authorization. Verified BOLA proof still requires a scoped replay
and independently attributable controls, neither of which is available here.

Its result fields now also bound input-derived reporting: methods are allowlist-
normalized, non-integer/out-of-range statuses become `0` with an invalid-input
reason, and researcher-supplied canary markers are limited to 256 characters.
Invalid account-A status values cannot establish the comparison control.

Input-field validation passed focused BOLA tests (**6 passed, 45 deselected**)
and full suite (**1,072 passed**, 39.49 s; one expected synthetic
duplicate-ZIP-member warning); `compileall` and `git diff --check` passed.

The credential-key filter passed focused BOLA tests (**5 passed, 45
deselected**) and the full suite (**1,071 passed**, 40.04 s; one expected
synthetic duplicate-ZIP-member warning); `compileall` and `git diff --check`
passed.

Query-ID control/whitespace filtering passed focused BOLA tests (**7 passed,
45 deselected**) and full suite (**1,073 passed**, 39.90 s; one expected
synthetic duplicate-ZIP-member warning); compilation and `git diff --check`
passed.

Fail-closed BOLA verdict-field tests also passed (**5 passed, 45 deselected**)
and full suite (**1,071 passed**, 40.00 s; one expected synthetic
duplicate-ZIP-member warning); compilation and `git diff --check` passed.

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

### Native JNI string-candidate evidence boundary

The JNI helper parses a bounded `.dynsym` table (up to 5,000 records) when
`pyelftools` is available, separating undefined `STT_FUNC` imports and defined
JNI export symbols from printable-string candidates. A 5 MiB input cap and
explicit invalid/partial/unsupported parser states prevent a truncated or
malformed file from being treated as a complete symbol inventory. Generated
INFO / `CWE-Unknown` leads explicitly withhold call reachability; a dynamic
symbol import is not proof of a call site, execution, attacker-controlled
arguments, or a vulnerability. `dangerous_calls_referenced` remains empty
because method-level native call graphs are not analyzed. Compiler-built
synthetic tests verify symbol import/export inventory only, not runtime
reachability or a real application.

Package-wide JNI library enumeration now uses the shared no-follow inventory
with limits of 5,000 entries, 5 MiB per library, 1,000 libraries, and 64 MiB
total source bytes. Its `package_coverage` reports skips/truncation separately
from individual library parse states; it does not imply that skipped libraries
had no indicators.

Package-inventory regressions passed native JNI focused tests (**7 passed, 7
deselected**) and full suite (**1,074 passed**, 40.50 s; one expected synthetic
duplicate-ZIP-member warning); compilation and `git diff --check` passed.

JNI long-name decoding now strips overload descriptors and decodes the JNI
escape forms for underscore, semicolon, array marker, and four-digit Unicode
characters. This improves symbol-name attribution but does not resolve native
declarations or connect exports to imported calls.

Top-level scan status is now `partial` when pyelftools is unavailable, the
input is truncated, symbol parsing fails/limits out, or `.dynsym` is absent;
the latter case is distinct from an empty dynamic import set. A compiler-built
relocatable-object regression verifies the missing-table state is not reported
as a clean import inventory.

Each emitted lead carries the scan/ELF parse status, bytes scanned, truncation
flag, and dynamic-symbol count in its metadata so a report consumer can see
whether its evidence came from a complete parse or a partial prefix.

Symbol-table names are de-duplicated, and the 5,000-entry limit and optional
parser-unavailable fallback have direct regressions. Missing pyelftools yields
partial ELF coverage while retaining only clearly labeled printable-string
candidates; repeated symbol entries do not inflate imported-name output.

Optional-parser, symbol-limit, and de-duplication tests passed (**6 passed, 7
deselected**) and full suite (**1,070 passed**, 39.96 s; one expected synthetic
duplicate-ZIP-member warning); `compileall` and `git diff --check` passed.

Finding-level coverage metadata passed focused native JNI tests (**4 passed,
7 deselected**) and the full suite (**1,068 passed**, 40.16 s; one expected
synthetic duplicate-ZIP-member warning); `compileall` and `git diff --check`
passed.

The scan-status regression passed the focused JNI tests (**4 passed, 2
deselected**) and full suite (**1,063 passed**, 40.18 s; one expected synthetic
duplicate-ZIP-member warning); `compileall` and `git diff --check` passed.

The JNI name-decoder change passed focused native JNI/name tests (**9 passed,
2 deselected**) and the full suite (**1,068 passed**, 39.97 s; one expected
synthetic duplicate-ZIP-member warning); `compileall` and `git diff --check`
passed. Escape decoding is covered by bounded synthetic names, not a broad
external ABI corpus.

The ELF symbol-table improvement passed focused JNI tests (**4 passed, 2
deselected**) and full suite (**1,063 passed**, 39.93 s; one expected synthetic
duplicate-ZIP-member warning); `compileall` and `git diff --check` passed.

### RASP resilience inventory boundary

The Smali string inventory uses the shared no-symlink `SourceInventory` reader:
at most 5,000 tree entries, 2 MiB per Smali file, and 32 MiB total source bytes.
Directory enumeration retains and sorts only the remaining entry-budget-sized
prefix (with at most one lookahead to detect truncation); it does not sort or
materialize an unbounded `scandir` result before applying the cap. When more
entries remain, coverage records `entry_budget` and the inventory is partial;
the selected prefix is deterministic only relative to the filesystem's
enumeration order, not a promise of globally lexicographically earliest files.
Synthetic tests exercise both path-only enumeration and bounded file reading
against a 10,000-entry iterator with a two-entry cap. This regression does not
establish bounded kernel/filesystem internals or exhaustive APK coverage.
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
   On 2026-10-16, commit `8c2b02a` was validated locally in the pinned Python 3.14 environment: **1,030 passed** (40.28 s; one expected synthetic duplicate-ZIP-entry warning). This adds bounded-`scandir` regression coverage; compilation and `git diff --check` also passed. GitHub Actions run `38834136167` was queued/in progress when recorded, so no remote CI result is claimed here. These are synthetic/local checks, not device or live-target validation.
   Commit `95da9c2` then passed the full suite with **1,031 passed** (40.23 s; same expected warning); its focused framework-capability tests passed (6). Compilation and `git diff --check` passed. This adds missing-input coverage reporting only and does not claim complete framework identification or device validation.
   The FileProvider XML DTD/entity rejection batch passed its focused tests (6) and full suite (**1,033 passed**, 39.80 s; one expected synthetic duplicate-ZIP-entry warning); compilation and `git diff --check` passed. This confirms only rejection behavior on the tested synthetic declarations, not general XML parser safety or Android runtime exposure.
   The decoded-manifest input hardening passed focused manifest/surface tests (58) and the full suite (**1,034 passed**, 39.87 s; same expected warning); compilation and `git diff --check` passed. Tests exercise DTD/entity, size-cap, and final-component symlink rejection on synthetic files only.
   Referenced FileProvider XML hardening then passed focused provider-path tests (4), manifest/surface tests (59), and the full suite (**1,035 passed**, 39.92 s; same expected warning); compilation and `git diff --check` passed. This verifies bounded no-follow read and DTD/entity rejection only for covered fixtures.
   The Android automation snapshot DTD/entity guard passed its focused test (1), the automation suite (23), and the full suite (**1,036 passed**, 40.30 s; same expected warning); compilation and `git diff --check` passed. No device actions were run.
   Network Security Configuration DTD/entity rejection passed its focused suite (4) and the full suite (**1,037 passed**, 39.66 s; same expected warning); compilation and `git diff --check` passed. Coverage is explicitly partial on rejected input; no platform TLS behavior was exercised.
   The APK extractor's package-name manifest probe passed artifact-provenance tests (20) and the full suite (**1,038 passed**, 39.98 s; same expected warning); compilation and `git diff --check` passed. Synthetic tests cover DTD, final symlink, and reduced-size-cap rejection; no untrusted APK was processed in this validation.
   The review-surface coverage ledger gap-reporting change passed `test_accuracy_foundations.py` (73 tests) and the full suite (**1,039 passed**, 40.51 s; same expected warning); compilation and `git diff --check` passed. It reports missing mapped coverage; it does not measure analyst or analyzer completeness.
   APIMapper lazy-match and coverage-cap regressions passed the focused APIMapper tests (8) and the full suite (**1,042 passed**, 40.40 s; same expected warning); compilation and `git diff --check` passed. This only measures synthetic bounded enumeration and redacted-route de-duplication.
   Missing-root APIMapper handling passed the focused APIMapper tests (11) and the full suite (**1,045 passed**, 40.00 s; same expected warning); compilation and `git diff --check` passed. The test blocks traversal for empty/whitespace/`None` roots; it does not cover all callers or path-race conditions.
   Rendering of missing coverage paths in standard and professional reports passed focused report tests (5) and the full suite (**1,046 passed**, 41.48 s; same expected warning); compilation and `git diff --check` passed. Synthetic report rendering only; no browser or exported PDF rendering validation is claimed.
   Missing-root guards for six initial static analyzers passed `tests/test_empty_scan_roots.py` (10 tests) and the full suite (**1,056 passed**, 41.08 s; same expected warning); compilation and `git diff --check` passed. A follow-up extends the guard to Flutter, Unity IL2CPP, Hermes, React Native, native ELF, iOS privacy manifests, and network-security-config root APIs. Its tests are recorded below after validation. These checks prevent absent/blank roots from becoming `Path('.')`; they do not cover every filesystem entry point or path races.
   Follow-up root validation passed `tests/test_empty_scan_roots.py` (**13 passed**) and the full suite (**1,059 passed**, 40.95 s; one expected synthetic duplicate-ZIP-member warning). `compileall` and `git diff --check` passed. This establishes only missing-root behavior for the named APIs with synthetic inputs and fail-on-call walk/read stubs; it does not establish analyzer accuracy or exhaustive path safety.
   A further guard now covers native JNI package-library and iOS Mach-O bundle entry points; JNI traversal also skips symlink directories and library candidates. Test results for this batch follow validation. No format parsing, library reachability, or iOS runtime behavior is established by these root checks.
   Native JNI/Mach-O root validation passed the focused root regression file (**13 passed**) and full suite (**1,059 passed**, 40.50 s; one expected synthetic duplicate-ZIP-member warning); compilation and `git diff --check` passed. The parameterized root test now also verifies those APIs do not walk the current directory for absent or blank roots.
   Remaining direct Smali entry points (`SmaliCallGraphEngine.build_graph`, `SymbolResolver.index_directory`, and the RASP string inventory) also now reject absent/blank roots instead of using the process directory or raising on `None`. Their focused/full results follow validation. This does not make analyzer coverage exhaustive.
   Direct Smali root validation passed the focused regressions (**84 passed**, including call-graph/register-flow coverage) and full suite (**1,059 passed**, 40.41 s; one expected synthetic duplicate-ZIP-member warning); `compileall` and `git diff --check` passed. These are test fixtures/stubs, not real APK recall or security validation.
   The Android Data Safety discrepancy auditor also now treats `None` as a missing source-tree root (rather than calling `Path(None)`); empty/blank/None roots produce no source-tree traversal. Focused and full test results follow validation. No privacy compliance conclusion follows from this input guard.
   Data Safety / privacy-root tests passed (**23 passed, 26 deselected**) and full suite (**1,059 passed**, 40.30 s; one expected synthetic duplicate-ZIP-member warning); compilation and `git diff --check` passed. This verifies bounded input handling only.
   The symbol registry used by interprocedural Smali/Java analysis previously used an unbounded `os.walk` and followed source-file symlinks when opening Java/Kotlin files. It now consumes the shared no-follow inventory (5,000 entries, 2 MiB/file, 64 MiB total), exposes that inventory coverage, and marks file-count truncation. Synthetic tests verify symlink/oversize skips; this bounds source acquisition but does not improve cross-language resolution completeness. Validation results follow.
   Symbol-inventory focused tests passed (**15 passed, 19 deselected**) and full suite (**1,060 passed**, 40.30 s; one expected synthetic duplicate-ZIP-member warning); compilation and `git diff --check` passed. No external APK corpus, inventory recall, or path-race guarantee is established.
   The direct native JNI library auditor now opens candidates with `O_NOFOLLOW|O_NONBLOCK`, accepts only regular files, and retains the existing 5 MiB read cap. A symlink regression verifies that synthetic target contents are not treated as library evidence. Focused/full results follow; this does not validate native binary parsing or real JNI call reachability.
   Native JNI no-follow validation passed its focused tests (**2 passed, 2 deselected**) and full suite (**1,061 passed**, 39.71 s; one expected synthetic duplicate-ZIP-member warning); compilation and `git diff --check` passed. This covers only direct symlink rejection and the existing synthetic ELF fixture.
   Native JNI results now distinguish invalid input, heuristic analysis, and a partial 5 MiB prefix, with bytes scanned and explicit read/size/header error codes. An oversized synthetic ELF verifies a candidate past the prefix is not silently treated as covered. Focused/full results follow; even a full-file heuristic scan is not structural ELF/JNI control-flow analysis.
   Native JNI coverage-state tests passed (**3 passed, 2 deselected**) and full suite (**1,062 passed**, 39.88 s; one expected synthetic duplicate-ZIP-member warning); compilation and `git diff --check` passed. This confirms output-state signaling on covered synthetic cases only.
The resilience API no longer performs an unbounded recursive `glob` or silently selects the first unexpected Smali directory. The initial bounded-root batch passed focused tests (**16 passed**) and the full suite (**1,076 passed**, 40.16 s; one expected synthetic duplicate-ZIP-member warning); `compileall` and `git diff --check` passed. This was a traversal-boundary improvement, not exhaustive Smali or RASP coverage.
The follow-up root-boundary check also rejects symlink components in the known apktool layout; a synthetic linked tree is not scanned. Its route tests passed (**3 passed**), and the full suite passed (**1,077 passed**, 40.50 s; one expected synthetic duplicate-ZIP-member warning); `compileall` and `git diff --check` passed. This avoids bypassing `SourceInventory`'s no-follow policy through the endpoint's fast path, but does not establish race-free filesystem access.
The multidex gap is now addressed: discovery includes all canonical sibling Smali roots under one shared bounded traversal budget, and analysis shares its file/entry/byte limits across roots. Synthetic route coverage verifies a candidate string present only in `smali_classes2` appears in the aggregate inventory; focused RASP tests passed (**6 passed**), and the full suite passed (**1,078 passed**, 40.56 s; one expected synthetic duplicate-ZIP-member warning). `compileall` and `git diff --check` passed. This does not establish APK-wide coverage when discovery or analysis limits are reached.
Flutter and IL2CPP recursive artifact discovery now use bounded no-symlink `SourceInventory` traversal rather than `os.walk` lists that were sorted/materialized before the entry cap. Flutter applies one shared entry budget across native libraries and assets, rejects symlinked asset-parent paths, and surfaces generic skipped-entry coverage; Unity library candidate discovery is likewise capped. Focused Flutter tests passed (**5**), focused IL2CPP tests passed (**4**), and the no-root regression suite passed (**14**); the full suite passed (**1,080 passed**, 40.26 s; one expected synthetic duplicate-ZIP-member warning). `compileall` and `git diff --check` passed. This does not alter the limited string/metadata semantics or establish framework-analysis completeness.
Native dependency-library discovery now uses the same bounded no-symlink source inventory rather than an `os.walk` result that could materialize an oversized directory before checking its 50,000-entry limit. A synthetic one-entry cap regression confirms partial status and no false “complete” library inventory. Focused native inventory tests passed (**3 passed**); the full suite passed (**1,081 passed**, 40.44 s; one expected synthetic duplicate-ZIP-member warning). `compileall` and `git diff --check` passed. Native hash bounds and versionless SBOM semantics are unchanged.
The iOS privacy-manifest candidate inventory and Android Data Safety Java/Kotlin/Smali source enumeration now also use bounded no-symlink traversal instead of sorting/materializing unbounded `os.walk` entries before applying limits. iOS manifest-count/tree caps and Android source-file/byte/tree coverage remain explicit; skipped symlinks are now reported as skipped rather than generic read failures. Focused privacy/Data Safety tests passed (**11 passed**); the full suite passed (**1,082 passed**, 41.12 s; one expected synthetic duplicate-ZIP-member warning). `compileall` and `git diff --check` passed. This does not establish privacy compliance or complete manifest/source coverage.
2. **Synthetic regressions**: Tests exercise selected fixtures and mocks only. GitHub Actions run `38774618068` completed successfully on commit `7a85d3a`: 900 passed, 2 skipped, 1 warning. The workflow's pinned dependency installation, accuracy checks, reproducible wheel, asset verification, installed-wheel smoke, and synthetic browser suite passed. Browser checks used synthetic loopback services, no device, APK, or live target. Separately, the local pinned Python 3.14 environment reported 902 passed and 1 warning (39.04 s); CI skips two tests. No measured false-positive/false-negative rate or zero-leakage claim is established. SBOM regression tests use hash-pinned local CycloneDX 1.5 JSON/XSD, SPDX/JSF imported schema files, and SPDX 2.3 JSON schema fixtures. Provenance, upstream URLs, licenses, and expected digests are documented in `tests/fixtures/sbom_schemas/README.md`; the CycloneDX XSD import is resolver-mapped to a pinned local file with lxml network access disabled.
3. **Evidence semantics**: Several current workflows preserve candidate/observation distinctions, but no claim is made that every analyzer or stage has independently verified fail-closed behavior. See the release gates above.
4. **Scope boundary**: No APK, device, API origin, or researcher-controlled account was supplied for live validation in this task; no dynamic target testing was performed.

