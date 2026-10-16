# MobileAg Master Technical Architecture & Implementation Blueprint

## Purpose and Scope
This document records an audited implementation plan for the **MobileAg** local-first mobile security assessment platform. It does not claim feature parity with commercial products, exhaustive coverage, or production readiness. Scope and completion claims are bounded by the evidence recorded below.

Depending on the section, this plan records implementation areas, evidence status,
coverage limits, and outstanding safety or external-validation gates.

---

```
MobileAg Master Blueprint Architecture
├── 1. Advanced Static Analysis & Taint Tracking
│   ├── Bounded Inter-Procedural Smali Call Graph and Taint Candidates
│   ├── Bounded Android Callback/Intent Flow Candidates
│   └── Android IPC Vulnerability Auditing (PendingIntent, FileProvider, Task Hijacking)
├── 2. Multi-Framework & Non-Dalvik Binary Analysis
│   ├── Flutter Snapshot String Candidates (Not a Dart Decompiler)
│   ├── React Native Hermes (.hbc) String Candidates (Not a Decompiler)
│   ├── Bounded Unity IL2CPP Metadata Candidates
│   └── Bounded iOS Mach-O & Swift Metadata Candidates
├── 3. Advanced Dynamic Instrumentation & Frida Harness
│   ├── Transparent, Explicitly Scoped Runtime Observation
│   ├── TLS Configuration Review (No Pinning Bypass)
│   ├── Cryptographic API Metadata Review (No Key/Plaintext Capture)
│   └── Non-Destructive Memory/Storage Exposure Review (No Secret Collection)
├── 4. Automated IPC Fuzzing & Exploit PoC Synthesis
│   ├── Dynamic Deep Link & Custom Scheme Mutation Fuzzer
│   ├── ContentProvider Traversal & Injection Fuzzer
│   └── Review-Only PoC Output (Never Execution Authorization)
├── 5. Mobile Backend API & Token Security Engine
│   ├── Automated API Cataloger & OpenAPI 3.0 / HAR Exporter
│   ├── Offline Dual-Session Observation Evaluator (Replay Not Implemented)
│   └── Mobile Token & Session Lifecycle Auditor
├── 6. Binary Hardening & RASP/Resilience Candidate Inventory
│   ├── Bounded RASP/Resilience Candidate Inventory (No Aggregate Score)
│   └── Static Anti-Tampering/Debugging Indicator Review
├── 7. Researcher-Guided UI Observation (Smart Crawler)
│   ├── Researcher-Guided Synthetic Form Handling
│   ├── Consent-Aware Permission/Prompt Handling (No Bypass)
│   └── UI State Hashing & Loop Prevention
├── 8. Mobile SBOM, Supply Chain & Privacy Manifests
│   ├── CycloneDX v1.5 & SPDX 2.3 Inventory Generators
│   ├── Opt-In OSV Advisory Lookup (Offline by Default; Unverified)
│   └── Apple Privacy Manifest (PrivacyInfo.xcprivacy) & Google Play Data Safety Auditor
└── 9. Dashboard, Bounded Telemetry & Reporting
    ├── WebSocket/SSE Real-Time Telemetry Stream
    ├── Interactive Attack Surface Graph Visualization (Vis.js / Neo4j)
    └── SARIF 2.1.0, PDF and Markdown Exports
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
2. **Bounded Inter-Procedural Call Linking**: When supported Smali invoke instructions resolve a method declared in the APK, propagate taint to mapped formal parameter registers, including receiver/wide-argument slots; bounded summaries also carry supported static-field and return-value taint. This is a may-flow candidate, not arbitrary Java/Kotlin/Smali cross-language resolution or full interprocedural control-flow analysis.
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

## 3. Transparent Dynamic Instrumentation & Runtime Validation

### 3.1 Authorized, visible instrumentation
* **Objective**: Support reproducible runtime observations only on an explicitly authorized package/build and researcher-selected device.
* **Safe scope**: Require an explicit device serial, package validation, just-in-time scope guard, operator approval, and preserved tool/build provenance. Report instrumentation state and failures honestly; do not conceal the agent, evade anti-debugging/anti-analysis controls, rename artifacts to avoid detection, or camouflage threads, sockets, or process memory.

### 3.2 TLS configuration review (no pinning bypass)
* **Objective**: Identify configured trust and certificate-pinning behavior without disabling it.
* **Safe scope**: Review Android Network Security Config and application/framework configuration statically. Network capture is allowed only for a researcher-controlled test build that explicitly trusts the lab CA. Do not hook or patch certificate-verification callbacks, change trust decisions, scan/patch Flutter binaries, or claim complete traffic visibility when pinning prevents capture. Missing traffic is an evidence gap, not a reason to bypass the control. Network Security Config discovery validates `@xml/` resource names, refuses unresolved resource references rather than substituting an unrelated default, and confines explicit manifest/config paths to nonsymlink files under the extraction root; rejected resolution is reported as partial coverage.

### 3.3 Cryptographic API metadata review (no key/plaintext harvesting)
* **Objective**: Record bounded cryptographic-use metadata for an authorized synthetic test case.
* **Safe scope**: If separately approved, record algorithm/mode, key-size metadata, call counts, and source-location context only. Never record raw keys, initialization vectors, decrypted/encrypted plaintext, database passwords, or user data. Prefer static API/configuration analysis; require output redaction and retention limits for any runtime metadata. This does not establish key entropy, data confidentiality, or cryptographic correctness.

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
* **Execution gate**: Direct `DeepLinkFuzzer` calls require an explicit callable just-in-time scope guard as well as an explicit serial; missing, false, or raising guards block before device access. Runtime observations remain `not_proven` and do not establish exploitability.

### 4.2 ContentProvider Fuzzer & Traversal Tester
* **Objective**: Test exported ContentProviders for directory traversal and SQL injection vulnerabilities.
* **Target Files**:
  - `mobileag/dast/provider_fuzzer.py` (New)
  - `mobileag/dast/provider_auditor.py` (Enhancement)
* **Technical Implementation**:
  1. Identify all ContentProviders with `android:exported="true"`.
  2. Probe only researcher-owned test builds containing synthetic data. Path traversal payloads target fixed `mobileag_synthetic_canary` fixture filenames; never request app databases, preferences, `/etc/hosts`, or other user/OS data. Projection/selection SQLi queries require explicit `synthetic_data_confirmed=true` in addition to the selected serial and scope guard.
  3. Record bounded access/query observations without retaining returned rows; assess disclosure only against the documented test-fixture canary and controls.
* **Observation handling**: Explicit `SecurityException` / `Permission Denial` output takes precedence over SQL-parser wording; a denied query is not classified as an observed SQL error or a vulnerability. Missing synthetic-data confirmation returns `BLOCKED_SYNTHETIC_SCOPE` without starting ADB.

### 4.3 Review-Only PoC Output (Not Execution Authorization)
* **Objective**: Provide bounded review material for eligible, analyst-attested findings without claiming independent proof or authorizing execution.
* **Target Files**:
  - `mobileag/generators/poc_apk_synthesizer.py` (New)
  - `mobileag/generators/templates/poc/` (Templates)
* **Boundary**: Current generator output is a review artifact. Generation requires active structured analyst attestation bound to the exact package; it is not independently verified. No executable ADB launch/read/query command is emitted. Templates use synthetic canary markers, avoid outputting provider/file contents, omit PendingIntent dispatch, and keep the task-affinity example inert. Deep-link custom URIs are still operator-supplied review data and must be checked before use. Template-interpolated identifiers and URI values are constrained by field-specific allowlists (including Kotlin `$` rejection), and malformed values fail closed; this is not a general-purpose escaping layer. Orchestrator persistence accepts only bounded unique Markdown filenames and writes at most 500 guides, each capped at 1 MiB, using private atomic replacement. These constraints do not make generated Kotlin independently safe to compile/run or establish vulnerability impact. Independent verification and proof-grade generation remain incomplete.

---

## 5. Mobile Backend API & Token Security Engine

### 5.1 Observed API Catalog & OpenAPI 3.0 Exporter
* **Objective**: Produce a bounded, redacted inventory of observed or statically declared API candidates; this is not the entire backend contract.
* **Current boundary**: OpenAPI generation is locally schema-validated and output is bounded; persistence uses a private-mode temporary file and atomic replacement. HAR export is capped at 64 MiB and uses private-mode atomic replacement. Retained HAR requests are owned snapshots, so caller mutation after ingestion cannot bypass the recorded retention budget or rewrite later exports. JSON-object shape inference visits at most 100 properties without first materializing the full item sequence. Raw capture values remain in bounded process memory by design and are redacted on export. This does not establish hosted ingestion or a complete backend contract.
* **Target Files**:
  - `mobileag/dast/api_cataloger.py` (New)
  - `mobileag/dast/traffic_auditor.py` (Enhancement)
* **Technical Implementation**:
  1. Retain only bounded traffic actually observed by supported capture paths. HTTPS interception is not implemented; use only an explicitly configured researcher-controlled test build where appropriate.
  2. Deduplicate requests by method, host, path template, and query parameter signatures.
  3. Infer request/response JSON schemas and auto-generate an **OpenAPI 3.0 specification (`openapi.json`)**.
  4. Flag "Shadow APIs" (undocumented endpoints seen in traffic that are not declared in mobile code).

### 5.2 Offline BOLA / IDOR Dual-Session Observation Evaluator
* **Objective**: Compare researcher-supplied observations for a synthetic canary; automated request replay and server-side authorization verification are not implemented.
* **Target Files**:
  - `mobileag/dast/bola_fuzzer.py` (New)
  - `mobileag/dast/api_security_tester.py` (Enhancement)
* **Boundary**: Offline extraction returns identifier candidates only; query candidates require normalized ID/account/user/order-style key tokens rather than substring coincidence. The evaluator compares already-supplied account-A/account-B responses and requires a synthetic canary in both successful controls before labeling an observation as a candidate. It never accepts or replays session tokens, stores raw response bodies, or emits a verified BOLA verdict. Report endpoints omit userinfo, query/fragment values, recognized identifiers, and path values following common credential markers; this is heuristic redaction and can hide legitimate route slugs or miss unknown encodings. Any live replay requires separate target authorization, researcher-controlled accounts/data, scope review, and independent evidence.

### 5.3 Mobile Token & Session Lifecycle Auditor
* **Objective**: Audit mobile authentication tokens, JWT lifecycle claims, cleartext transmission, and session revocation.
* **Target Files**:
  - `mobileag/dast/token_session_auditor.py` (New)
  - `mobileag/dast/api_security_tester.py` (Enhancement)
* **Technical Implementation**:
  1. Parse bounded JWT header and payload indicators, including an observed `alg=none`; reject duplicate JSON object members rather than choosing an ambiguous claim/header value. Do not infer server acceptance or estimate key entropy/strength from token bytes.
  2. Inspect expiration claims (`exp`, `iat`) to detect missing expiration, expired tokens in use, or excessive lifetimes (CWE-613).
  3. Flag cleartext HTTP transmission of authorization tokens (CWE-319) and tokens passed in URL query strings (CWE-598).
  4. Detect session token reuse after logout or de-authentication requests (CWE-613).
  5. Calculate Shannon entropy to identify predictable, low-entropy session IDs (CWE-330).
  6. Opt-in offline HS256/HS384/HS512 verification using an explicitly researcher-supplied key; report only comparison status, enforce JWA minimum key byte length, and never infer server acceptance or key entropy from length.

---

## 6. Binary Hardening & RASP/Resilience Candidate Inventory

### 6.1 Bounded Static Resilience Indicator Review (No Aggregate Score)
* **Objective**: Inventory bounded Smali names/strings as manual-review leads. No MASVS conformance, protection effectiveness, or product-parity score is produced.
* **Target Files**:
  - `mobileag/analysis/rasp_resilience_auditor.py` (New)
  - `mobileag/analysis/binary_protection_auditor.py` (Enhancement)
* **Current boundary**: The analyzer inventories bounded Smali strings/names and reports coverage; it withholds aggregate/per-vector scores and control-flow conclusions. The ambiguous bare `su` substring is excluded because it matches ordinary directives such as `.super`; candidate indicators do not prove that controls are reachable, effective, or resistant to an attacker.

---

## 7. Researcher-Guided UI Observation (Smart Crawler)

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
     - Compute a truncated SHA-256 state key over the activity and sorted resource IDs (or short visible labels for elements without IDs); raw labels are not persisted by the state counter or copied into action explanations.
     - Track visited state counts with a finite per-crawler state budget; when exhausted, stop and return `WAIT`. Repeated-state `BACK` navigation, exploratory taps, and form submission are separate opt-ins; defaults return `WAIT`.

---

## 8. Mobile SBOM, Supply Chain Inventory & Privacy Declaration Review

### 8.1 Standardized CycloneDX v1.5 & SPDX 2.3 Exporter
* **Objective**: Generate bounded, interoperable SBOM inventory documents; schema validity and coverage limits do not establish complete dependency inventory or supply-chain assurance.
* **Current boundary**: CycloneDX JSON/XML and SPDX JSON writers enforce a 16 MiB serialized output cap and use private-mode temporary files with atomic replacement. A destination symlink is replaced rather than followed. The generator rejects additions beyond 10,000 components, 5,000 vulnerabilities, 64 licenses per component, or 100 CWEs per vulnerability. This is bounded local artifact handling; it does not establish complete package inventory or supply-chain assurance.
* **Target Files**:
  - `mobileag/analysis/sbom_generator.py` (New)
  - `mobileag/analysis/dependency_scanner.py` (Enhancement)
* **Technical Implementation**:
  1. Catalog all Maven/Gradle libraries, embedded JNI native libraries (`.so`), and npm dependencies.
  2. Generate standard Package URLs (PURL): `pkg:maven/com.squareup.okhttp3/okhttp@4.9.3`.
  3. Export valid CycloneDX v1.5 JSON/XML and SPDX 2.3 manifests.
  4. Query the Open Source Vulnerabilities (OSV) database to attach known CVEs to inventoried components.

### 8.2 Privacy Manifest & Google Play Data Safety Auditor
* **Objective**: Compare bounded static declaration evidence with selected manifest/source indicators for manual privacy review; do not claim legal or platform-policy compliance.
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

### 9.1 Session-Scoped WebSocket Telemetry
* **Objective**: Deliver authenticated scan-scoped telemetry already emitted by supported workflows; this is not a complete event bus for every tool.
* **Target Files**:
  - `mobileag/web/app.py` (Enhancement)
  - `mobileag/web/static/telemetry.js` (Enhancement)
* **Current boundary**: `/ws/scans/{scan_id}/telemetry` and an authenticated legacy aggregate stream exist. Per-scan subscription isolation is covered synthetically. A pending subscriber slot remains reserved during awaited scan validation and transfers to the active set without an intervening await, preserving the 32-connection cap during concurrent setup. Frida hook events, captured request bodies, screenshots, production-scale delivery, and loss/replay guarantees are not established and must not be claimed.

### 9.2 Interactive Attack Surface Graph (Vis.js / Neo4j)
* **Objective**: Visualize currently modeled component/finding/API-candidate associations; do not label co-occurrence as data flow or an exploit chain.
* **Target Files**:
  - `mobileag/knowledge/neo4j_graph.py` (Enhancement)
  - `mobileag/web/static/interface.js` (Enhancement)
* **Current boundary**: Graph nodes and edges reflect available stored associations. Explicit Intent, URI-grant, network-call, source/sink, and validated vulnerable-path edges are not implemented. Click-through finding evidence is available for modeled findings; no path should be colored or described as vulnerable without independent path evidence.

Graph exports now allowlist legacy vulnerability lifecycle/proof labels before
placing them in Vis.js node tooltip text; missing or unexpected values render as
`unknown`. A synthetic regression exercises markup-like and non-string legacy
values. This is output hardening, not live Neo4j isolation or graph-completeness
evidence.

### 9.3 Evidence-limited JSON, Markdown, and PDF report artifacts
* **Objective**: Persist researcher-readable reports without converting unverified candidates into confirmed impact.
* **Current boundary**: Orchestrator scan IDs are constrained to bounded path-safe names, and the per-scan output directory must not be a symlink or resolve outside the selected root. `ReportEngine` writes JSON, Markdown, and PDF under the caller-selected output directory. PDF content is generated from escaped prepared report fields with inline CSS only; all resource fetches are rejected. Artifact names require a bounded path-safe scan ID, and files are written through private-mode temporary files followed by atomic replacement so an existing report symlink is not followed. The PDF HTML and output byte sizes are capped; oversized reports fail explicitly rather than silently truncating findings. `ProfessionalReportExporter` also uses capped private atomic replacement for its Markdown output. CLI-generated JSON/Markdown reports use heuristic redaction and bounded private atomic writes. Pentest checklist planning state is capped, loaded from no-follow regular files, and saved atomically; malformed records do not partially mutate state. The feedback training-data export is capped by rows/pages/bytes, redacts payloads, and publishes via private atomic replacement; failed exports preserve the previous destination. Other legacy export writers require separate review. PDF generation/validation is local and does not establish report completeness or PDF-reader compatibility across platforms.

---

## Comprehensive Implementation Schedule & Status

> **Audit correction (refreshed 2026-10-16 at `6b9093e`): this blueprint is not 100% complete.** The
> `[COMPLETED]` labels and the old “zero false-positive / fail-closed” claims
> below were not supported by the existence of files or unit tests. At baseline commit `728a007`, `python -m pytest -q` reported **892 passed**
> (57.51 s). The current checkout's full suite reports **1,240 passed**
> (61.24 s) in the pinned Python 3.14 validation environment; `compileall`
> and `git diff --check` also passed. These are primarily mocked/synthetic
> regressions and do not establish actual APK/device coverage,
> exploitability, completeness, or production readiness. The implementation
> names below indicate bounded prototypes unless the capability is separately
> demonstrated and measured. Do not use the original status tree as a release
> gate or claim of feature parity.

### Verified implementation status

| Blueprint area | Checkout evidence | Status / remaining work |
|---|---|---|
| Static call graph and taint | `call_graph.py`, `symbol_resolver.py`, `taint_engine.py`; synthetic tests include `test_smali_call_graph.py` and `test_smali_register_flow_benchmark.py` | **Partial.** Heuristic bounded analysis; no claim of arbitrary cross-language, whole-program or lifecycle-complete tracing. Smali source/sink recognition matches exact owner + method names; WebView sinks include `loadUrl`, `loadData`, `loadDataWithBaseURL`, and `postUrl`. Local may-flow propagates taint through supported exact-signature invocation arguments into static/instance callee parameter registers (including wide parameter slots), with source/sink file and line evidence. Intent extra/data/metadata accessors (`getStringExtra()`/typed extras/`getExtras()`, `getData()`/`getDataString()`/`getScheme()`/`getAction()`/`getType()`/`getClipData()`), Bundle/Uri getters, Cursor value getters (`getString`, `getBlob`, and primitive value accessors), and bounded ClipData item/URI getters derive taint only when their receiver already carries taint, avoiding unconditional source treatment for arbitrary internal objects; `Uri.toString()` preserves the taint. External-content candidates now require a tainted URI passed to selected `ContentResolver` open methods or a tainted path passed through a bounded `File(String)`/`File.toPath()` conversion to selected file-stream constructors / `Files.readString` / `Files.readAllBytes` / `Files.newInputStream` / `Files.newBufferedReader` (with `Paths.get` preserving taint); taint propagates through a bounded set of stream/reader constructors and scalar/array `read`, `readLine`, `readAllBytes`, and selected Scanner methods. Synthetic regressions exercise URI → ContentResolver → reader → `readLine` and a char-array `read` → array load → StringBuilder → WebView sink. This models a candidate read from a selected path/URI input, not proof that the path resolves to content accessible to the app, that a URI is reachable or granted, that returned bytes are attacker-controlled, or that the source is authentic; platform API availability is also unresolved. Bounded array-element taint tracks `filled-new-array` elements and `aput`/`aget` through register aliases, but does not distinguish indexes or prove array/object identity. `fill-array-data` clears the destination register's tracked element-taint summary because its static payload replaces contents, but alias/object identity effects remain unresolved and register-flow coverage is marked partial. Primitive register moves, supported numeric conversions, and supported arithmetic operators (including `rsub-int/lit8`) preserve taint as a conservative may-flow; wide writes clear both destination words, and wide moves merge taint from either source word; untainted arithmetic and constant writes including `const-method-type`/`const-method-handle` clear stale register taint. Supported String transformations plus bounded StringBuilder/StringBuffer constructor, mutator, and toString operations preserve taint through local object-register aliases; builder identity across fields and calls is unresolved. Exact static-field reads/writes and bounded method-return summaries propagate tainted register values between exact methods, but not callee heap side effects; instance-field reads clear overwritten register taint and mark coverage partial to avoid stale-value false positives, and instance-field writes also mark partial coverage because field-value propagation and heap identity remain unmodeled. A limited set of exact Android callback signatures (`onNewIntent`, `onReceive`, `onStartCommand`, `onHandleIntent`, `onActivityResult`, `onBind`, and `onUnbind`) seeds the incoming `Intent` parameter for derived accessors only when the parsed superclass chain reaches the expected Android callback base; synthetic negative controls now verify a same-named callback on a non-Android class and a normal helper `Intent` parameter are not treated as lifecycle roots. This does not prove component registration, export state, caller privileges, or runtime reachability. Public `@JavascriptInterface` annotated method parameters are seeded as untrusted-source candidates, but annotation presence does not establish WebView bridge registration, enabled JavaScript, target API behavior, frame origin, loaded content, or reachability. This is not full interprocedural taint: instance fields and heap side effects, virtual dispatch/overrides, unsupported invoke forms such as `invoke-custom`/`invoke-polymorphic` (which mark coverage partial but do not propagate return taint), unrecognized destination-shaped register writes (which clear stale destination taint, mark coverage partial, and do not assume operand propagation), tainted arguments passed to calls without a local implementation or modeled summary mark coverage partial (their return/heap effects are not propagated), sanitizers, exception semantics, platform reachability and authorization are unresolved; budgets and skipped methods are exposed. The synthetic local-register evaluator now also covers a provider Cursor flow, NIO path reads, and hard-negative untainted URI/path controls; it still measures only public individual CWE/sink-line cases (including duplicate CWEs and conditional branches), not blind or independent accuracy, cross-file accuracy, APK recall, or field false-positive rates. Packed/sparse switch payload target resolution has synthetic positive coverage; malformed and over-limit payloads now have regressions confirming partial coverage is reported rather than silently accepted. Register-flow diagnostics retain at most 100 warning samples and expose total observed warning events plus whether samples were truncated; this improves visibility but is not comprehensive Smali opcode/syntax coverage. Independent corpora remain open. |
| IPC / FileProvider | `manifest_auditor.py`, `intent_redirection_auditor.py`, `pending_intent_auditor.py`, `fileprovider_auditor.py` | **Implemented as candidate analyzers.** Findings require component reachability, effective platform permission/grant behavior, and caller-controlled input validation; manifest patterns alone are not exploits. FileProvider XML scanning now uses bounded no-symlink inventory reads (5,000 entries, 2 MiB/file, 32 MiB total), filters to `res/xml*`, avoids duplicate recursive/direct matches, exposes coverage, reports parse/size/root-shape errors, and rejects DTD/entity declarations before XML parsing. Direct FileProvider XML parsing uses a 4 KiB-chunked pull parser with depth capped at 64, clears completed child subtrees, caps modeled path entries at 5,000 and each retained `name`/`path` attribute at 256 characters, and clears accumulated candidates if malformed trailing XML is found. Entry/attribute overflow yields `partial` coverage (`xml_path_entry_limit` or `xml_path_attribute_limit`) rather than silently treating omitted configuration as clean; the complete input string is still bounded at 1 Mi characters. Broad `external-media-path` roots (`.` or empty) are included as unverified configuration review candidates. Empty/`.` `files-path` and `cache-path` roots (including equivalent slash/dot spellings) are also recorded as INFO candidates because they map entire app-internal directories; no grant or external access is inferred. A literal `..` path segment now emits an INFO, unverified FileProvider configuration review candidate; it does not establish canonicalized root escape, a URI grant, or caller access. FileProvider analyzer descriptions require separate evidence of a served URI, effective grant, and caller reachability rather than implying unauthorized access from XML alone. Intent-redirection lexical scans now use the same file/entry/total bounds, skip symlinks, expose partial coverage, and reject forward-in-time extraction matches; method scope and component reachability remain unresolved, so findings are review candidates only. PendingIntent Java/Kotlin scans now use bounded no-symlink reads with coverage surfaced in the scan and receive the parsed target SDK. Missing mutability on target API 31+ is reported as an INFO compatibility lead (expected Android 12+ creation failure if executed), not a CWE-927 exploit claim; unknown/older targets retain a bounded mutability review candidate. Token distribution, receiver capability, and runtime path still require review. Task-affinity inventory now resolves an alias to exactly one parsed activity using canonicalized component names; it inherits affinity and launch mode from that target per Android's alias semantics and emits an INFO lead only for an exported alias with a literal non-default effective affinity. Missing/ambiguous targets withhold effective alias values and findings. This is not a StrandHogg exploit verdict or a blanket `singleTask` recommendation. Deep-link mutation generation now bounds input/query count, percent-encodes payloads while preserving other parameters, and the ADB launcher quotes each remote-shell argument; execution still requires an explicit serial and just-in-time scope guard. Launcher stdout/stderr are drained with a 4 KiB retained prefix per stream and are not persisted in results; observed byte count/truncation is exposed. The helper does not collect logcat/crash tombstones or establish exploitability, and generic activity-manager errors are not labeled crashes. Provider fuzz probes now require an explicit serial and per-command scope guard; an explicit boolean `False` or guard exception blocks the command (normal return values including `None` retain exception-based guard compatibility). The separate approved-fixture `ProviderAuditor` also honors boolean denial before and after its shell query, so post-action revocation withholds findings. They validate authority/package/projection input, issue read-only SQL probe cases against both selection and projection fields, and quote remote shell arguments; they drain stdout/stderr concurrently while retaining at most 4 KiB per stream, expose observed byte counts/truncation, and omit raw provider output from result records. Neither these probes nor the other candidate analyzers establish runtime exploitability; FileProvider binary resources are not decoded. |
| Flutter / Hermes / IL2CPP | `flutter_engine.py`, `hermes_analyzer.py`, `il2cpp_auditor.py` | **Partial string/metadata probes, not decompilers.** Flutter binary reads now have both per-file and 32 MiB aggregate byte budgets; printable-string iteration is capped at 100,000 per binary and distinct endpoint/route/secret-marker output is capped, with explicit truncation errors. Flutter binary and asset discovery, and IL2CPP library discovery, use the bounded no-symlink `SourceInventory` instead of unbounded `os.walk` directory materialization; Flutter applies one shared tree-entry cap across library and asset inventory and rejects symlinked parent paths. Truncation, scan status, byte counts, and errors are exposed. Flutter still scans only bounded printable strings, not Dart snapshot structures. URLs from Flutter, Hermes, and IL2CPP are propagated as UNKNOWN-method embedded-string candidates; the orchestrator does not infer an HTTP method or callability from a URL string. Hermes bundle reads now use one bounded no-follow read, cap printable-string iteration and retained strings/endpoints, redact credential-like values in returned samples, and mark the scan partial with explicit errors when input or candidate output is truncated; `function_count` remains unknown rather than a misleading zero. The Hermes pass is still printable-string extraction, not a structured Hermes string-table parser or bytecode decompiler. IL2CPP now validates the version-29 global-metadata header ranges and bounded string-literal records (8-byte records, bounded literal sizes/count/UTF-8 reads), and extracts URL/secret-marker/class-name candidates from those parsed literals without retaining raw literal values. Unsupported metadata versions retain a bounded printable-string fallback and explicitly report `scan_status=partial` with `unsupported_metadata_version`; this does not decode those versions or establish coverage beyond lexical candidates. Malformed v29 tables yield partial coverage. Tree and metadata reads, literal/candidate iteration, and endpoint/class outputs are bounded, and symlink paths are skipped. A bounded v29 type/member-table pass now resolves class namespaces/names, field names, method names, and parameter names/counts into review-only records. It does not resolve field/return/parameter types, generic constructs, native method bodies, or emit a complete `dump.cs`; names are metadata candidates, not source reconstruction. The orchestrator now retains bounded structured IL2CPP metadata summaries in scan state and API responses, with explicit static-candidate, non-exhaustive, runtime-not-tested, and not-proven labels; analysis errors are reflected as incomplete coverage. Flutter/Hermes results now also populate the scan-state coverage ledger, including candidate counts, truncation/errors, explicit heuristic/non-exhaustive boundaries, and incomplete status on engine failure; an empty Hermes bundle inventory is reported as not applicable, not as a completed decompilation. Other versions and format variants remain unsupported or unverified, and no independent corpus establishes format coverage. Credential-like matches emit redacted review markers rather than raw/candidate values. No Dart snapshot reconstruction or Hermes control-flow decompilation is implemented; the IL2CPP parser does not produce a complete C# symbol dump or method/type signatures. |
| iOS Mach-O / Swift | `macho_parser.py`, `ios_analyzer.py` | **Partial structural parser and bounded Swift name/field inventory.** The bounded thin 32/64-bit passes validate header/load-command and `LC_SEGMENT`/`LC_SEGMENT_64` section bounds, inventory dylib load commands and bounded `LC_SYMTAB` names, recognize Swift section names from actual section records, and extract capped printable strings only from parsed `__cstring` file ranges. A bounded `__swift5_types` pass resolves direct relative entries for class/struct/enum context descriptors and emits valid UTF-8 nominal type-name candidates. A bounded `__swift5_protos` pass now resolves direct protocol descriptor entries and emits protocol-name candidates; relative-indirectable entries remain partial and are not dereferenced. When direct field metadata is present, the parser validates the `__swift5_fieldmd` section/record bounds and returns UTF-8 field-name candidates grouped by type; it does not resolve field types or reconstruct declarations. Malformed ranges and unresolved names produce partial status. This is not full metadata/type/field/protocol reconstruction; protocol conformances from `__swift5_proto`, requirement signatures, and associated-type semantics remain unparsed. Parse status/errors and section/import/symbol/Swift type/field/protocol inventories are exposed with the iOS analysis summary; legacy whole-file Swift section-name, URL, and framework strings remain lexical candidates distinct from parsed section/import evidence. Fat/FAT64 architecture tables now receive bounded slice-count/range and table-vs-slice CPU agreement validation. Mach-O input is opened as a no-follow regular file and a truncated read forces partial status for thin and fat files; lexical URL enumeration and returned endpoint candidates are capped with explicit partial status. Complete `__TEXT`/cstring coverage above the 15 MiB input cap and robust independent malformed-corpus validation remain incomplete. Synthetic fixtures prove only these specific cases, not universal Mach-O compatibility.
| Frida stealth, TLS bypass, crypto harvesting | `dast/frida_stealth.py`, `unpinning_engine.py`, `crypto_harvester.py`, `generators/frida_generator.py` | **Retired in the safe profile.** Hook/template generators and their ready-to-run payloads are removed; compatibility entry points refuse generation. The scan orchestrator no longer generates or writes Frida scripts. Crypto fixture parsing retains only bounded operation/algorithm labels and discards key, IV, plaintext, and payload fields. This does not implement authorized visible runtime instrumentation; that remains a separately reviewed external/device gate. |
| IPC / dynamic verification / PoC synthesis | `deeplink_intent_fuzzer.py`, `provider_fuzzer.py`, `verification_loop.py`, `generators/poc_apk_synthesizer.py` | **Prototype / not proof-grade.** Provider probes report read/query success and SQL errors as observations, not vulnerability verdicts. PoC generation requires a CONFIRMED lifecycle state plus active structured analyst-attested evidence bound to the exact target package; this is not independent verification. Unverified, malformed, inactive, cross-package, and unsupported interpolated component/authority/affinity/URI/finding-ID values fail closed. Generated commands/source remain review artifacts with `execution_authorized=false`; no generated PoC is executed. The former free-form `adb shell` path has been replaced by one deep-link-only dispatch observation requiring a CWE-601 candidate, explicit serial, just-in-time exact package/serial guard returning `True`, operator approval, synthetic-data confirmation, and bounded custom-scheme URI/timeout. The output is only an Activity Manager dispatch observation (`verified=false`); it cannot change finding status or establish impact. Other probe types remain disabled. Target package type/length and Kotlin-interpolated component syntax now fail closed; independent confirmation and proof-grade generation remain open. The dashboard defers generation until the researcher opens that finding’s PoC tab; the read-only loopback navigator allows only the matching bounded GET route. |
| API catalog / BOLA / token review | `api_cataloger.py`, `bola_fuzzer.py`, `token_session_auditor.py`, scoped capture/export endpoints | **Partial.** Catalog/schema inference and token heuristics do not establish server-side authorization flaws. Captured, redacted HTTP traffic can be exported as observed OpenAPI/HAR inventory; export routes are session-authenticated and separate from device-action middleware. The offline `/api/dast/traffic/audit` endpoint optionally compares supplied captured transactions with typed static endpoint declarations; it sends no requests and reports `not_requested` when declarations are absent. Traffic-audit findings normalize identifier-shaped paths and omit URL userinfo/query values rather than copying captured URLs into evidence. Shadow-API review normalizes numeric/UUID/email/token-shaped route IDs, supports method-specific declarations and canonical origin matching (including omission of default HTTP/HTTPS ports), and omits userinfo, query values, and raw ID-shaped path values; declarations supplied as path-only strings are origin/method wildcards. Static `APIMapper` blanks Java/Kotlin comments, Smali `#` comments, XML comments (preserving CDATA), and JS/Dart line/block comments while retaining string literals and line offsets; JS/Dart route-template interpolations are normalized to `{id}`, and unclosed XML comments/CDATA mark coverage partial, then extracts Retrofit verb/path declarations (including HEAD/OPTIONS and literal Retrofit `@HTTP` method/path pairs), route-literal endpoint candidates across Java/Kotlin as well as resource/bundle sources, and URL review leads with relative source-file and 1-based line evidence; route-only candidates retain `method=UNKNOWN`, and unknown/custom Retrofit method tokens are never guessed (their literal path may still appear as a route-only candidate); the general `@HTTP` annotation parser is quote-aware and capped at 4 KiB, with unsupported or oversized declarations reflected in partial-coverage diagnostics. Route output strips URL userinfo, drops query/fragment values, percent-encodes path controls, and templates obvious numeric, UUID, email, opaque mixed, and recognized digit-bearing typed-prefix path IDs; Empty/missing API-mapping roots return `not_analyzed` rather than resolving `Path("")` to the process working directory. Retrofit, route-literal, and URL matches are iterated lazily, endpoint de-duplication uses normalized redacted routes, and reaching the finding cap marks coverage partial. This best-effort redaction does not guarantee removal of arbitrary secrets. These remain unverified leads because static endpoint extraction may be incomplete. BOLA candidate extraction is offline-only and bounds URLs to 8,192 characters, query metadata to 100 fields, and candidate values to 256 characters; malformed authorities and over-limit query sets fail closed. TrafficAuditor caps sensitive-query parsing at 256 fields and emits an explicit incomplete-coverage lead rather than treating an over-limit URL as a clean CWE-598 review. The evaluator requires an explicit researcher-provided account-A marker; generic HTTP 200 is inconclusive. Result records omit raw resource IDs, credentials, and endpoint query/fragment data, template recognized identifier path segments, and retain only a digest rather than the response body; response hashing and canary comparison are capped at 1 MiB of text and explicitly mark truncated/invalid input. An offline dual-session observation comparator now requires the same supplied canary in successful A and B responses, but does not verify account identity, request equivalence, ownership, or server authorization. It remains an evaluator, not a replay system; no network requests are performed. JWT parsing is bounded and claim findings are explicitly unverified; `exp`/`iat` are exposed only for exact int/float values that are finite and within the supported epoch range (booleans, NaN/infinities, and out-of-range numbers are omitted while claim presence remains distinct). Per-transaction request headers are capped at 100 entries; malformed, over-limit, oversized Authorization values, or duplicate case-insensitive Authorization fields mark coverage partial, and raw header values are not copied into coverage. The auditor inspects at most the first bounded authorization value when duplicates exist, so the status remains partial rather than implying all credentials were reviewed. Output omits raw tokens and arbitrary header/claim values, retains only algorithm/lifecycle/claim-name indicators, and sanitizes endpoint URLs. An opt-in offline verifier now supports HS256/HS384/HS512 only with an explicitly supplied local key and constant-time comparison; asymmetric algorithms, key discovery, server acceptance, and key entropy/strength beyond JWA's minimum byte length are not assessed. The verifier is not automatically applied to captured traffic. Logout/reuse is only a same-token, status-sequence observation, not proof a protected resource was authorized. OpenAPI grouping preserves canonical per-origin servers, omits userinfo/default ports, and brackets IPv6 literals for valid server URLs. Static URL review recognizes bracketed IPv6 authorities, case-insensitive schemes, and escaped slash separators in serialized source strings, emitting only unverified literal-use candidates; it does not test network reachability or effective cleartext policy. Captured route paths replace numeric, canonical UUID, and email-shaped segments, long mixed alphanumeric token-shaped segments, shorter (8-23 character) mixed-case alphanumeric segments, and recognized typed prefixes (such as `usr_`, `order_`, or `id-`) followed by a digit-bearing identifier with required string path parameters; percent-encoded ASCII is decoded only for this redaction decision. This bounded privacy-first heuristic may parametrize legitimate route slugs, while unrecognized prefixes, short lowercase IDs, malformed encodings, or other encodings may remain unmodeled; it is not a guarantee that arbitrary secrets are removed. JSON shape inference omits value-like object keys (UUIDs, long tokens/IDs, numeric IDs, and email-shaped keys) and marks that redaction; property values are never exported. Query-key signatures are deduplicated separately and merged as observed parameters, without exporting observed path/query values in the OpenAPI document. Generated documents are validated locally with pinned `openapi-spec-validator` 0.9.0. Malformed authorities/ports, overlong URLs, and unsupported schemes are excluded from OpenAPI endpoint modeling and counted under `invalidURLs`/`unmodeledRequests`; query metadata is parsed centrally and capped at 100 fields with 256-character names; traffic-catalog adapters do not expand query strings before the cap, and over-limit captures are counted as unmodeled instead of producing partial query signatures. Cataloger HAR retention is separately capped at 10,000 transactions, 2 MiB per transaction, and 16 MiB estimated aggregate; over-budget transactions are omitted while bounded endpoint modeling continues when inputs permit, and the capture estimates/omission counts are exposed. JSON shape inference also rejects bodies over a 1 Mi-character cap before decoding. Bounded HAR export still redacts captured values. HTTPS capture and dual-session replay remain open. |
| RASP / resilience | `rasp_resilience_auditor.py` | **Bounded Smali string/name inventory only.** The API inventories all discovered canonical `smali` / `smali_classesN` roots under a shared entry/file/byte budget and exposes root-discovery and analysis coverage; ambiguous roots, multiple extraction bases, symlinks, or truncated discovery fail closed. Aggregate and per-vector scores/pass states are withheld (`null`); control-flow assessment is explicitly unknown rather than inferred from obfuscation, and string entropy is not treated as proof of encryption. Candidate strings do not establish reachable/effective defenses. No MASVS conformance or runtime resistance is demonstrated. |
| Smart UI crawler | `smart_crawler.py`, `ui_crawler.py` | **Safety correction made in this revision.** No hard-coded credentials. Permission/consent prompts always stop at `WAIT`; researcher-supplied test credential entry, form submission, exploratory taps, and repeated-state `BACK` navigation each require explicit opt-in. Runtime UI observation now requires an explicit serial, validated package name, and just-in-time scope guard; the background DAST workflow propagates that guard. Legacy tap/text helpers are inert and issue no ADB commands; the observer only returns planned-action review data. Both crawler hierarchy parsers cap input at 2 Mi characters and reject more than 5,000 nodes; DTD/entity declarations are rejected, and over-limit/malformed input produces no partial action candidates. The separate Android automation snapshot parser caps encoded input at 1 MiB and now also rejects DTD/entity declarations before parsing. These are bounded parser behaviors, not assurances of safe or accurate UI interpretation. |
| SBOM / privacy | `sbom_generator.py`, `dependency_scanner.py`, `privacy_manifest_auditor.py` | **Partial.** Bounded Maven/npm inventory and opt-in OSV lookup are implemented in `dependency_scanner.py`; lookup is blocked in offline mode and results remain unverified. Dependency scans inventory bounded ELF `ET_DYN` `.so` candidates by path, SHA-256, class and machine; native release versions and vulnerability advisories are not inferred. Native-library tree discovery uses the shared bounded no-symlink inventory, so directory entries are capped before traversal results are sorted/materialized. iOS privacy-manifest candidates and Android Java/Kotlin/Smali source paths also use bounded no-symlink `SourceInventory` traversal; Android source reads retain per-file and aggregate byte caps, and coverage reports entry/file/read limits and skipped symlinks. Pinned CycloneDX 1.5 JSON/XSD (including its SPDX and JSF dependencies) and SPDX 2.3 JSON schemas validate populated synthetic JSON/XML output offline in regression tests. The normative XSD test exposed and fixed an XML element-order defect when component hashes/licenses were present. iOS privacy manifests are parsed across the app/framework tree, report parse/shape errors and per-manifest declarations, and avoid coercing malformed tracking values to true. Android Data Safety review is included in the orchestrator, reads the extracted manifest through a bounded no-follow regular-file read, rejects DTD/entity declarations, and parses actual permission XML elements (rather than substring matches). Its manifest/source coverage is retained in scan coverage even when no finding is emitted. Bounded symbol-to-manifest cross-checks cover the main executable and up to 32 direct `Frameworks/*.framework/<FrameworkName>` executables (15 MiB each, 64 MiB aggregate) under a 50,000-entry traversal budget; each framework is compared only with manifests in its own bundle, and findings remain informational, unverified candidates. Framework traversal/parse/manifest limits are surfaced in separate coverage. Objective-C message dispatch, versioned/nonstandard framework binary layouts, and binaries outside the recognized direct framework layout remain outside this pass. These are static indicators only: they do not prove API reachability, manifest completeness, SDK execution/data sharing, or any Play Console declaration or privacy compliance. HAR recognized credential fields are redacted before export. |
| Telemetry / graph / exports | `web/app.py`, `knowledge/neo4j_graph.py`, reporting modules | **Partial.** Session-authenticated `/ws/scans/{scan_id}/telemetry` is implemented with subscription isolation; `/ws/telemetry` remains the authenticated legacy aggregate stream. Graph writes now namespace component, finding, and endpoint uniqueness keys by scan and type while preserving display labels, preventing new writes from merging equal entities across scans under the existing global constraints. Finding CWE access now uses the model's actual `cwe_id` field. Synthetic tests verify distinct keys and display values with a mocked Neo4j session, not live database isolation. Existing graph records are not migrated; rebuild/cleanup is needed before assuming historical separation. HAR exports redact recognized credential fields in request/response headers, URL, query, and bodies; namespaced fields ending in credential suffixes such as `_session_id`, `_refresh_token`, and `_client_secret` are redacted while lookalikes such as `tokenizer` remain visible. Synthetic regressions cover both response-header export and hard negatives; arbitrary secrets in fields not recognized by the heuristic remain a privacy limitation. Captured response headers are retained through the in-memory capture-to-HAR path and included after redaction; synthetic regressions verify both retained benign metadata and omitted Set-Cookie values. This does not preserve every raw capture field or establish production export behavior. Synthetic browser navigation verifies all eleven dashboard sections, explicit PoC retrieval, and axe checks at desktop/mobile viewports; test-plan legend contrast was corrected. This scoped browser check is not a complete WCAG claim. Neo4j vulnerability nodes now carry the original finding ID separately from their scan-scoped storage key, and graph clicks resolve through that identity to the finding evidence panel; a synthetic browser regression covers this cross-ID path. Neo4j and embedded graph vulnerability nodes now retain an allowlisted finding lifecycle status and proof label, surfaced in hover metadata; missing legacy node labels remain unknown until records are rewritten. New API inventory edges use `HAS_API_CANDIDATE` rather than `CALLS_API`; both new and legacy endpoint edges export as `endpoint_candidate`. Legacy endpoint records without a recognized evidence type fail closed to `method=UNKNOWN`, `evidence_type=legacy_endpoint_candidate`, and `proof_status=not_proven`; URL strings are not rendered as verified calls. Historical Neo4j relationship types are read as candidates, not migrated. ReportEngine now writes JSON, Markdown, and PDF report artifacts with path-safe scan IDs and private atomic replacement; escaped PDF text and a deny-all resource fetcher prevent report fields from becoming active HTML or triggering network/file fetches. Bounded oversized PDF generation fails explicitly rather than implying a complete report. The graph still does not demonstrate complete data flow, explicit URI-grant/network/data-flow edges, or validated vulnerable paths. The legacy attack-chain helper now returns no paths rather than treating app-level component/finding co-occurrence as a chain; production-scale telemetry, OpenAPI conformance, and release readiness also remain unestablished. |

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

Per-manifest output now has separate caps for tracking domains, declared API
categories, and API reason-code pairs, in addition to package-wide caps. This
prevents repeated declarations across up to 128 manifests from multiplying the
retained output beyond the intended inventory bounds. Synthetic regressions
cover per-manifest truncation and explicit partial status (**8 focused privacy
tests**); the related privacy/IPA suites passed (**58 passed**); full pytest
passed (**1,251 passed**, 60.25 s); compileall and `git diff --check` passed.

The offline API query-string indicator now shares normalized credential-key
recognition with the token-session auditor (including namespaced suffixes),
caps URL/query parsing, validates malformed authorities, and labels rejected or
over-limit inputs `incomplete_input` instead of silently treating them as a
clean review. Findings still omit query values and remain unverified CWE-598
review leads. The focused workflow boundary suite passed (**20 passed**); full
pytest passed (**1,253 passed**, 60.60 s); compileall and `git diff --check`
passed. This does not establish that a query value is a credential or that any
server uses it.

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

Query-token review now normalizes parameter-name separators/casing and detects
common aliases/suffixed names such as `refresh-token`, `id_token`,
`client_secret`, `secret_key`, `cookie`, and `X-Amz-Security-Token`; it flags the key even when the
value is short, never copies the value into evidence, and deliberately avoids
substring matches such as `tokenizer`. This remains name-based heuristic
coverage and cannot discover arbitrary credential parameter names.
The same token audit emits an unverified CWE-522 review lead when captured
HTTP(S) URLs contain userinfo syntax; the username/password values are omitted
from finding text and the sanitized location. This pattern does not prove that
the credentials were valid or accepted.
Transaction-level token findings also have a 20,000-result ceiling; the auditor
reports received/analyzed/omitted transactions and marks the output partial
when transaction or finding limits truncate processing, query parsing exceeds
its field cap, or malformed/oversized URLs are unmodeled. The token audit API
exposes this coverage rather than silently presenting a bounded result as
complete.
Recognized credential-like query keys remain CWE-598 review candidates, but a CWE-319 cleartext transport lead requires a non-empty credential-like query value, URL userinfo, or an Authorization credential observed over HTTP. Blank token-shaped query parameters do not by themselves imply credential transmission; findings remain unverified and do not establish server acceptance.

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

SBOM component hashes are normalized to supported CycloneDX digest identifiers
and validated for hexadecimal syntax and algorithm-specific digest length before
emission. Unsupported algorithms, malformed/truncated digests, and ambiguous
duplicate aliases fail closed instead of yielding syntactically plausible but
invalid hash metadata. This validates supplied digest shape, not artifact
integrity or provenance.

CycloneDX advisory metadata now validates bounded identifiers, basic PURL
scheme/length, XML-safe descriptions, exact positive `CWE-n` values, and severity
labels (mapping OSV `moderate` to CycloneDX `medium`) before JSON/XML emission.
Malformed fields are rejected rather than partially coerced; attached advisory
data still does not establish that a dependency is present or exploitable.
Application/component metadata is also bounded and typed, component categories
are allowlisted, and synthesized fallback PURL segments are percent-encoded;
this is basic shape checking rather than full Package URL standard validation.

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
Timeline & Execution Inventory [audited 2026-10-16; NOT COMPLETE]
├── Phase 1: Static Engine & Frameworks [PARTIAL; bounded analyzers exist]
├── Phase 2: Dynamic Engine & Frida [SAFE PROFILE DISABLES HOOK EXECUTION; authorized runtime validation NOT DONE]
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

   On 2026-10-16, commit `5c26f4e` carried captured response headers through
   the bounded API-capture catalog into HAR output, with redaction and capture
   size accounting; synthetic tests cover benign-header retention and
   `Set-Cookie` value omission. Commit `7fd1d41` extended the authenticated
   capture-export route regression to verify the same redaction boundary.
   Focused tests passed (3 catalog tests; 1 route test), and the pinned Python
   3.14 full suite passed (**1,136 passed**, 94.94 s after `5c26f4e`; **1,136
   passed**, 117.04 s after `7fd1d41`). `git diff --check` passed before each
   commit. The suite emitted existing pytest-asyncio deprecation warnings and
   async resource warnings. This validates synthetic export behavior only;
   neither live capture nor target/device testing was performed.

   IL2CPP coverage-state regression: unsupported metadata versions continue to
   use the bounded printable-string fallback but now explicitly report
   `scan_status=partial` and `unsupported_metadata_version`. Focused IL2CPP
   regressions passed (**7 passed**, 37 deselected); the pinned Python 3.14
   full suite passed (**1,137 passed**, 153.49 s). `git diff --check` is run
   before commit. This verifies only synthetic unsupported-version status
   signaling; metadata decoding for other versions remains unimplemented.

   JWT time-claim validation was restored after review found its finite/range
   check unreachable. The auditor now omits boolean, non-finite, and
   out-of-range `exp`/`iat` values while preserving a separate `has_exp_claim`
   indicator. Focused token-auditor regressions passed (**3 passed**, 68
   deselected); the pinned Python 3.14 full suite passed (**1,138 passed**,
   118.75 s). Findings remain unverified and no server acceptance is inferred.

   Token audit request-header parsing now reads at most 100 header entries per
   transaction. Duplicate case-insensitive Authorization names, malformed
   entries, and over-limit maps are represented as partial coverage; tests
   confirm omitted/ambiguous values are not copied into coverage. Focused
   coverage tests passed (**4 passed**, 68 deselected); the pinned Python 3.14
   full suite passed (**1,139 passed**, 116.07 s). This is synthetic parser
   behavior only, not traffic capture or server-side token verification.

   Oversized Authorization header values now also mark header coverage partial
   before the value is discarded. The regression uses a synthetic value above
   the configured 64 KiB token bound and asserts it is absent from coverage;
   the focused header test passed (1), and the full suite passed (**1,139
   passed**, 103.96 s). This checks the local bounded parser only.


   Cleartext token findings now require a non-empty sensitive query value (or
   another credential source such as Authorization/userinfo); an empty or
   whitespace-only token-shaped query parameter retains its CWE-598 candidate
   but does not imply credential transmission. Focused regressions passed
   (**3 passed**, 70 deselected), and the full suite passed (**1,140 passed**,
   91.07 s). Results remain unverified traffic indicators.

   Privacy redaction now recognizes namespaced credential-field suffixes such
   as `_session_id`, `_refresh_token`, `_client_secret`, and `_private_key`,
   while hard negatives retain `tokenizer`, `secretariat`, and request-trace
   metadata. HAR regression confirms a namespaced session response header is
   redacted. Focused privacy/export tests passed (**15 passed**, 85 deselected);
   the full suite passed (**1,145 passed**, 89.14 s). This remains
   best-effort field-name redaction and does not detect arbitrary secrets in
   arbitrary fields.

   Provider fuzzer scope checks now honor an explicit `False` return as denial;
   regression mocks verify traversal and selection/projection probes do not
   launch ADB when denied. Existing exception-based guards and `None` returns
   remain compatible. Focused provider tests passed (**4 passed**, 70
   deselected); the full suite passed (**1,146 passed**, 78.35 s). No device
   commands were run in this validation.

   The approved-fixture `ProviderAuditor` now honors boolean scope denial
   before launching ADB and rechecks after the command, withholding findings
   when scope is revoked. Focused provider tests passed (**3 passed**, 13
   deselected) plus the existing arbitrary-authority denial regression (**1
   passed**, 18 deselected); the full suite passed (**1,148 passed**, 68.47 s).
   These are synthetic shell mocks; no device command was run.

   `StorageAuditor` now honors explicit boolean scope denial at each shell
   boundary. A denial before execution prevents ADB; a denial after `su`
   prevents the direct-shell fallback. Focused storage tests passed (**5
   passed**, 13 deselected), and the full suite passed (**1,150 passed**,
   70.18 s). All device access was mocked; no rooted or physical device was
   used. Existing deprecation/resource warnings remain.

   The memory-forensics path now transfers and persists only six fixed
   category labels, never matching memory strings or `/proc/<pid>/environ`
   values. Explicit `False` or exception-based scope denial is enforced before
   and after process lookup and the root-shell scan; invalid serial/PID/output
   bounds are rejected, and unrecognized command output is discarded. Any
   resulting marker is INFO/UNVERIFIED with `ordinary_app_access` explicitly
   not established. Focused memory regressions passed (**4 passed**, 78
   deselected); the full suite passed (**1,152 passed**, 72.20 s), and
   `compileall` plus `git diff --check` passed. All ADB behavior was mocked;
   the `su`/`strings`/AWK pipeline, Android utility compatibility, memory-scan
   resource cost, and live-device behavior remain unvalidated. Legacy callers
   that omit a guard remain supported, so callers must still supply an
   explicit scope guard for authorized device use. Existing pytest-asyncio
   deprecation and async-resource warnings remain.

   `DeepLinkFuzzer` now treats an explicit `False` scope-guard result as a
   denial at every existing pre/post ADB checkpoint; exceptions continue to
   fail closed, while guard omission remains compatible for legacy callers.
   Synthetic tests prove denial prevents baseline collection or link launch
   after baseline capture. Focused runtime/deep-link regressions passed (**7
   passed**, 85 deselected); the full suite passed (**1,154 passed**, 72.29
   s), with `compileall` and `git diff --check` passing. All ADB behavior was
   mocked; no device was used, and this does not prove deep-link exploitability
   or Android runtime behavior. Existing pytest-asyncio and async-resource
   warnings remain.

   `UICrawler` now fails closed on an explicit boolean scope denial before or
   between UIAutomator dump/read operations, and it skips cleanup once the
   guard denies further commands. Synthetic regressions verify pre-command
   denial and revocation after the uniquely named dump command; revocation may
   leave that temporary file on-device because cleanup is intentionally not
   attempted out of scope. Focused UI/runtime regressions passed (**9 passed**,
   86 deselected); the full suite passed (**1,157 passed**, 72.39 s), with
   `compileall` and `git diff --check` passing. All ADB actions were mocked;
   no Android device or UI behavior was tested. Existing pytest-asyncio and
   async-resource warnings remain.

   `IntentFuzzer.exercise_component` now treats an explicit `False` guard
   result as denial, matching its existing exception-denial behavior. Synthetic
   tests verify denial before baseline capture and after baseline capture but
   before the component launch. Focused intent-scope regressions passed (**3
   passed**, 18 deselected); the full suite passed (**1,159 passed**, 70.52 s),
   and compilation plus `git diff --check` passed. ADB was mocked; no Android
   device was used, and this validates only scope-boundary behavior, not IPC
   impact or runtime exploitability. Existing test-environment warnings remain.

   `DeepLinkIntentFuzzer.execute_fuzz_case` now reports `BLOCKED_SCOPE` when
   its required guard explicitly returns `False`; the subprocess mock confirms
   no ADB process starts on this denial path. The existing exception-denial
   behavior remains. Its focused regression passed (**1 passed**, 24
   deselected); the full suite passed (**1,159 passed**, 74.85 s), with
   `compileall` and `git diff --check` passing. This is mock-only scope-gate
   evidence, not device execution or proof of a deep-link vulnerability.

   The outbound `LLMBroker` now treats an explicit `False` scope-guard result
   as a denial before contacting a provider, between requests, and after a
   response before any approved fallback. Synthetic tests verify that initial
   denial sends no request and post-response revocation prevents the secondary
   request. Focused LLM fallback tests passed (**34 passed**); the full suite
   passed (**1,161 passed**, 79.01 s), with `compileall` and `git diff --check`
   passing. Provider transports were mocked; no credentials or real network
   requests were used. Existing pytest-asyncio and async-resource warnings
   remain.

   `/api/dast/launch` now rechecks the authenticated session, configured
   device allowlist, and exact launch action/package policy immediately before
   and after dispatch, in addition to the central middleware gate. A synthetic
   route regression revokes the launch action during the mocked dispatch and
   confirms the response is denied. Focused route/session regressions passed
   (**3 passed**, 34 deselected); the full suite passed (**1,162 passed**,
   73.14 s), with `compileall` and `git diff --check` passing. Dispatch was
   mocked; no device was used. A revocation during dispatch cannot undo a
   command already sent, but the result is not accepted after the scope check
   fails. Existing test-environment warnings remain.

   `/api/dast/execute_adb` now rechecks the authenticated session, configured
   device allowlist, and explicit `execute_adb` policy at dispatch and after
   command completion; command input is limited to 1–4,096 characters. Mocked
   tests verify a revoked device-wide shell action suppresses the response and
   an over-limit request is rejected. Focused route tests passed (**3 passed**,
   22 deselected); the full suite passed (**1,164 passed**, 75.93 s), with
   `compileall` and `git diff --check` passing. No command was run on a device.
   The policy intentionally remains device-wide and the endpoint accepts
   arbitrary command semantics; enabling it is not ordinary-app authority and
   must be explicitly scoped/approved. It is unsuitable for unattended or
   destructive testing.

   `/api/dast/logcat` now rechecks authenticated session, configured device,
   and exact package/action policy before PID lookup and around each
   PID-filtered log read. A synthetic test revokes logcat permission during a
   mocked read and verifies the route returns 403 without returning the log
   line. Focused logcat route tests passed (**3 passed**, 23 deselected); the
   full suite passed (**1,165 passed**, 71.52 s), with `compileall` and
   `git diff --check` passing. Logcat and PID access were mocked; no device was
   used. Existing warnings remain.

   `/api/dast/install` now rechecks the authenticated session, configured
   device allowlist, and explicit install action immediately before and after
   archive validation and installation. A synthetic uploaded fixture revokes
   install scope during validation and confirms no installer call occurs.
   Permission grants remain opt-in and default to false. Focused install-route
   regression passed (**1 passed**, 26 deselected); the full suite passed
   (**1,166 passed**, 70.28 s), with `compileall` and `git diff --check`
   passing. Archive validation and installation were mocked; no APK was
   installed on a device. Existing test-environment warnings remain.

   The `/api/dast/root` route now rechecks authenticated session, configured
   device allowlist, and explicit `root` action policy around the root request
   and its follow-up identity observation. A mock revokes policy after the
   `adb root` command and verifies the follow-up `id` probe is not issued. Root
   remains a device-level privilege transition, not ordinary-app evidence or
   exploit proof. Focused root-route tests passed (**2 passed**) plus the
   existing out-of-scope-device denial (**1 passed**); the full suite passed
   (**1,167 passed**, 69.35 s), with `compileall` and `git diff --check`
   passing. No root command ran on a device.

   `/api/dast/connect` now rechecks the authenticated session, exact configured
   host:port allowlist, and explicit `connect` action both before and after
   `adb connect`. A synthetic route test revokes the action during the mocked
   connection and confirms the result is denied. Focused connect-route tests
   passed (**2 passed**, 27 deselected); the full suite passed (**1,168
   passed**, 55.38 s), with `compileall` and `git diff --check` passing. No
   device connection was attempted. Existing test-environment warnings remain.

   Destructive device-wide logcat clearing is now retired: the dashboard
   control and policy choice were removed, and the API handler returns 410
   without invoking `clear_logcat` (the middleware also rejects the retired
   action). Synthetic tests cover the handler, endpoint denial, and UI control
   removal. Focused logcat/retirement tests passed (**4 passed**, 26
   deselected); the full suite passed (**1,169 passed**, 55.74 s), with
   `compileall` and `git diff --check` passing. No device log buffer was
   touched. This preserves evidence; the old endpoint is intentionally
   incompatible and its helper remains unused for legacy callers only.

   Screenshot capture now rechecks authenticated session, configured device,
   and explicit `screenshot` action immediately before and after acquisition.
   A mocked regression revokes scope during capture and confirms no image is
   returned. Focused screenshot-route test passed (**1 passed**, 30 deselected);
   the full suite passed (**1,170 passed**, 56.44 s), with `compileall` and
   `git diff --check` passing. Capture was mocked; no device screen was read.
   Existing test-environment warnings remain.

   Frida runtime execution, daemon startup, elevated `FridaRunner` process
   probing, and preset script delivery are disabled. The policy no longer authorizes a
   `frida` execution action; legacy execution endpoints reject requests, and
   the dashboard retains only read-only Frida process observation under its
   separately scoped `frida_status` action. Hook, TLS-bypass, root-bypass, and
   crypto/key-harvesting controls and generated-script delivery were removed
   from the UI. Focused synthetic regressions passed (**23 passed**, 178
   deselected); `git diff --check` passed. No device was used and no Frida
   process was attached. Script-generator code remains in the source tree but
   is not delivered or executed through the application; its safety and
   completeness are not claimed. This intentionally retires those actions,
   rather than treating security-bypass tooling as completed functionality.

   A follow-up source-level hardening removed dormant Frida bypass, root-evasion,
   stealth-daemon, and crypto/key/plaintext-harvesting payloads, including the
   LLM/template generator and four ready-to-run templates. The orchestrator
   now omits script generation and file publication; compatibility generator
   methods fail closed. Crypto event parsing keeps only bounded operation and
   algorithm labels and rejects payload-preview events. The Copilot quick
   action and stale scan-modal bypass fields were removed; static TLS review
   remains the supported path. Focused regression tests passed (**297 passed**),
   including refusal to generate scripts and removal of
   sensitive event fields. Full pytest passed (**1,169 passed**, 65.47 s),
   with `compileall` and `git diff --check` passing. The isolated Playwright
   run passed with no page errors or off-loopback requests; process/device and
   provider adapters were synthetic/mocked. No device or provider was used.

   Legacy `Finding.frida_script` data remains parseable for old stored records
   but is now excluded from all standard and report dictionary exports. The
   focused serialization/privacy regressions passed (**39 passed**); this
   preserves migration compatibility without re-publishing hook payloads.

   A follow-up Playwright run loaded local axe-core **4.10.3** and checked all
   ten workspace sections at desktop and 320 px mobile widths against WCAG
   2.0 A/AA and WCAG 2.1 AA rules; no violations were reported. The first run
   hit a timing-sensitive immediate visibility assertion after graph-click
   navigation; the harness now waits for the view's visible state, and the
   repeat run passed. The report explicitly distinguishes `a11y_status=passed`
   from `not_run` (rather than rendering an empty object as if it were tested).
   This is a bounded automated check, not a complete WCAG conformance claim.

   SBOM PURL handling now uses pinned `packageurl-python==0.17.6` rather than
   accepting any string prefixed with `pkg:`. Component and advisory references
   are parsed, validated, and canonicalized; malformed percent escapes,
   duplicate qualifier names, invalid coordinates, and non-`pkg` schemes are
   rejected. Maven/npm PURLs are built from structured coordinates, while app
   fallback identities use `generic` instead of confusing Android app records
   with package-manager `apk` packages. This follows the upstream
   [PURL core specification](https://github.com/package-url/purl-spec) and its
   [Python parser](https://github.com/package-url/packageurl-python); it does
   not prove that package coordinates or vulnerability matches are authentic.
   Focused SBOM/API tests passed (**149 passed across the focused runs**); full
   pytest passed (**1,171 passed**, 66.22 s), with compilation and
   `git diff --check` passing. The full suite is synthetic/mocked and not an
   inventory recall claim. `pip check` also reports unrelated conflicts in
   optional preinstalled tools in the shared environment, so that auxiliary
   environment check is not clean.

   HAR export now stores only supported HTTP methods; unsupported methods are
   counted as unmodeled/omitted before request bodies or headers enter the
   retained capture list. Content-Type header values are restricted to a small
   explicit media-type allowlist, with parameters and unknown values replaced
   by `application/octet-stream` in both request/response headers and HAR MIME
   fields. Synthetic regressions verify that boundary/secret-like values and
   unsupported methods are not serialized. Focused HAR/catalog regressions
   passed (**22 passed**); the full suite passed (**1,173 passed**, 68.25 s),
   with compile and diff checks passing. This hardens bounded exports only; it
   does not prove arbitrary-secret redaction or real capture coverage.

   PoC synthesis input handling was tightened: target packages must be strings
   within the Android package-name length bound, and interpolated component
   names reject Kotlin `$` template syntax rather than allowing it into generated
   source. Synthetic regressions cover non-string/oversized package values and
   interpolation-shaped component names. Focused PoC tests passed (**3 passed**);
   full pytest passed (**1,173 passed**, 67.23 s), and compile/diff checks passed.
   This closes only the reviewed identifier-interpolation cases: analyst
   attestation is not independent verification, generated PoCs remain
   review-only, and the generator is still not proof-grade.

   A follow-up regression expansion exercises malformed component, authority,
   task-affinity, URI, affected-component, and finding-ID values, including
   quote/newline and Kotlin-interpolation shapes. Focused PoC regressions passed
   (**3 passed**); full pytest passed (**1,173 passed**, 67.23 s), with compile
   and diff checks passing. This confirms the tested validation paths only; it
   does not substitute for context-aware escaping or independent verification.

   PoC templates were then bounded to synthetic-canary review material: no ADB
   launch/read/query command is generated; FileProvider reads at most 64 bytes
   from a fixture canary and prints only a boolean; provider output is a canary
   boolean rather than rows; PendingIntent dispatch is omitted; task-affinity
   source contains no overlay or credential collection; and the default deep
   link uses the reserved `.invalid` host. A synthetic regression checks all
   six categories and rejects raw-content/privileged-action strings. Focused
   PoC tests passed (**3 passed**); full pytest passed (**1,174 passed**, 65.64
   s), with compile and diff checks passing. Generated Kotlin is not built or
   executed by these tests, custom URI metadata remains review data, and this
   safety hardening does not establish vulnerable behavior or proof-grade
   coverage.

   Full pytest passed (**1,170 passed**, 59.32 s); the isolated Playwright
   regression passed with synthetic fixtures and mocked device/model adapters.
   It confirmed no page errors, no XSS marker execution, no external requests,
   no real ADB/Frida calls, and no Frida deployment controls. The browser
   report's former `masvs_kpi_present: false` probe checked a nonexistent
   optional KPI, although the MASVS coverage chart is present. The browser
   probe now checks the actual chart and summary instead; no coverage score is
   inferred from chart presence. Chromium
   reported expected synthetic 401/404/503 responses and CSP-blocked inline
   handler control. Browser artifacts were written under `/tmp`, not into the
   repository. No device or commercial model was contacted.

   JWT header/payload decoding now rejects duplicate JSON object member names,
   preventing the offline parser from silently selecting one of conflicting
   `alg`/claim values. Synthetic regressions cover duplicate header and payload
   members; the HMAC helper now classifies such an ambiguous compact token as
   invalid input. Focused token tests passed (**4 passed**); full pytest passed
   (**1,174 passed**, 67.10 s), with compile and diff checks passing. This does
   not verify token acceptance, server policy, token provenance, or live
   session behavior.

   RASP indicator review removed the bare `su` substring, which matched common
   Smali such as `.super` and generated false root-detection leads. A synthetic
   negative control covers `.super`, `result`, and `subscription` text while
   preserving context-bearing root path matches. Focused RASP/root-boundary
   tests passed (**6 passed**); full pytest passed (**1,175 passed**, 66.64 s),
   with compile and diff checks passing. This improves one lexical heuristic;
   the inventory remains incomplete and does not establish effective root
   detection or absence of root checks.

   Smart UI crawler decisions no longer copy hierarchy text/content descriptions
   into permission, submit, or exploratory-click explanations; the loop counter
   continues to retain only truncated state digests. Synthetic negative controls
   place a synthetic email and account-recovery label in UI text and confirm
   they are absent from returned explanations/state keys. Focused crawler tests
   passed (**5 passed**); full pytest passed (**1,176 passed**, 64.82 s), with
   compile and diff checks passing. Parsed hierarchy objects remain transiently
   available to classifier logic, and no device-side crawler run was performed.

   The UI crawler now caps each instance at 10,000 distinct state hashes and
   returns `WAIT` without another action when the cap is reached. A regression
   uses a one-state test budget to verify the state map remains capped and the
   truncation is observable. Focused crawler tests passed (**6 passed**); full
   pytest passed (**1,177 passed**, 63.19 s), with compile and diff checks
   passing. This guards state-tracking memory only; it does not limit total
   session duration or demonstrate behavior on a real device.

   ContentProvider SQL probe classification now gives explicit permission
   denial precedence over coincident SQLite/syntax-error wording, since a
   denied call cannot establish that the query reached provider SQL handling.
   A mocked regression covers mixed `SecurityException` plus SQL-error output
   and confirms no raw output is retained. Focused provider tests passed
   (**5 passed**); full pytest passed (**1,178 passed**, 64.34 s), with compile
   and diff checks passing. This remains observation classification only; it
   does not prove provider authorization, data sensitivity, or SQL injection.

   Provider fuzzing now requires `synthetic_data_confirmed=True` as well as its
   explicit serial and scope guard before either traversal or SQLi probes can
   start. Traversal payloads target only fixed synthetic-canary filenames; app
   databases, shared preferences, and OS files were removed. Synthetic tests
   verify missing confirmation returns `BLOCKED_SYNTHETIC_SCOPE` without ADB,
   and that only canary paths are formed. Focused provider tests passed (**6
   passed**); full pytest passed (**1,178 passed**, 74.48 s), with compile and
   diff checks passing. The boolean is an operator assertion, not verification
   that a device actually contains synthetic-only data; live testing remains
   subject to scope and fixture review.

   The lower-level deep-link launch helper now rejects a missing/non-callable
   just-in-time scope guard before logcat or ADB access. Existing synthetic
   dynamic-matrix tests now supply the guard explicitly, and a negative control
   confirms an unguarded call reaches neither device adapter. Focused runtime
   tests passed (**8 passed**); full pytest passed (**1,179 passed**, 55.99 s),
   with compile and diff checks passing. This enforces a caller-provided scope
   decision, not the correctness of that caller's authorization or live-device
   exploitability.

   BOLA observation endpoint sanitization now redacts the first path value after
   common credential markers (including percent-encoded marker spellings), in
   addition to userinfo, query/fragment values, and recognized IDs. A synthetic
   endpoint regression verifies that short path credentials do not survive in
   serialized results. Focused BOLA tests passed (**7 passed**); full pytest
   passed (**1,180 passed**, 56.13 s), with compile and diff checks passing.
   This is heuristic redaction: it may hide legitimate route slugs and cannot
   guarantee removal of arbitrary or unrecognized secret encodings.

   BOLA query candidate extraction now tokenizes normalized query-key names and
   requires an identifier-related token (`id`, `account`, `user`, `order`, or
   supported resource names), rather than accepting any key containing those
   character sequences. A hard-negative confirms `grid=blue` is ignored while
   `valid_id` and `orderId` remain candidates. Focused BOLA tests passed (**7
   passed**); full pytest passed (**1,181 passed**, 56.21 s), with compile and
   diff checks passing. Candidate extraction remains heuristic and does not
   establish object ownership or authorization.


   OpenAPI route templating now also recognizes a bounded set of typed, digit-bearing resource-ID prefixes (for example, `usr_98472` and `order_123`), including percent-encoded ASCII for the redaction decision. Regression coverage verifies those values are absent from exported paths and confirms ordinary `/users/me` and `/orders/recent` route segments remain literal. Focused OpenAPI tests passed (**4 passed**); full pytest passed (**1,182 passed**, 55.76 s), with compile and diff checks passing. This remains a heuristic and can redact legitimate prefixed slugs or miss unrecognized identifier formats.


   Static API endpoint sanitization now applies the same bounded typed-prefix ID heuristic as captured-route export, including percent-encoded ASCII, while preserving ordinary route words. Focused API-mapper tests passed (**4 passed**) and the captured-route regression passed (**1 passed**); full pytest passed (**1,183 passed**, 55.68 s), with compile and diff checks passing. An initial full-suite run exposed a false positive for `item-00005-slug`; the ambiguous `item` prefix was removed from both sanitizers and a hard-negative regression now preserves that route. The duplicated sanitizers remain separate implementations, so future heuristic changes must keep both paths covered.


   Direct FileProvider XML parsing now bounds retained output to 5,000 path entries and 256 characters per `name`/`path` attribute. Entry overflow and skipped oversized attributes are explicitly `partial`, with distinct error codes; synthetic regressions verify the cap and that oversized values do not enter entries/findings. Focused FileProvider parser tests passed (**5 passed**); full pytest passed (**1,185 passed**, 56.15 s), with compile and diff checks passing. The parser still receives a fully materialized string bounded at 1 Mi characters; chunking, depth, entry, and attribute limits bound additional parsed-tree/output retention, not source-string allocation or Android runtime exposure.


   FileProvider parsing now uses `XMLPullParser` over 4 KiB chunks and drops completed child subtrees, so the existing 5,000-entry cap stops further parsing instead of first materializing a full ElementTree. If malformed trailing XML is encountered after earlier candidates, accumulated entries/findings are cleared and the result is invalid; wrong roots and non-string input are also rejected explicitly. Focused FileProvider tests passed (**20 passed**); full-suite result is recorded after validation. This bounds parsed-tree retention, while the original XML string remains capped at 1 Mi characters.


   The streaming FileProvider parser also rejects excessive nesting at depth 64 with explicit partial status (`xml_depth_limit`); a synthetic deeply nested document verifies the bounded exit. Focused FileProvider tests passed (**21 passed**); full pytest passed (**1,188 passed**, 56.70 s), with compile and diff checks passing. The limit does not establish XML-parser safety for every implementation or runtime exposure.


   iOS privacy API review now scans bounded embedded framework executables in addition to the app binary, recognizing only direct `Frameworks/*.framework/<FrameworkName>` binary layouts and up to 32 candidates under a 64 MiB aggregate size / 50,000-entry traversal budget. Each framework symbol candidate is checked against its own bundle manifests (not the app manifest), uses a unique finding identifier, and remains `UNVERIFIED`; Objective-C dispatch and nonstandard/versioned layouts remain unsupported. Synthetic IPA and cap regressions verify framework-specific declaration comparison, that app declarations do not mask framework candidates, unique framework finding IDs, and explicit partial coverage when candidate limits are reached. Focused privacy-symbol tests passed (**5 passed**); full pytest passed (**1,190 passed**, 55.78 s), with compile and diff checks passing.


   ReportEngine now produces a PDF alongside its JSON and Markdown outputs. The HTML is constructed from escaped prepared fields and inline CSS only, with resource fetching denied; PDF HTML/output caps fail explicitly. Scan IDs are validated before path construction, and report files are replaced atomically using private-mode temporary files to avoid following planted artifact symlinks. Tests cover real PDF signature generation, unsafe scan-ID rejection, symlink replacement, and markup escaping. Focused report-export tests passed (**4 passed**); full pytest passed (**1,193 passed**, 58.79 s), with compile and diff checks passing. Rendering and signatures do not prove cross-platform PDF compatibility or report completeness.


   Network Security Config resolution now rejects traversal-shaped `@xml/` resource names, unresolved resource IDs, explicit manifest paths outside the extraction root, and direct candidate paths with symlink components. A missing manifest-referenced custom config no longer falls back to an unrelated default; each rejection reports partial coverage. Synthetic tests cover traversal, symlink, external manifest path, and unrelated-default controls. Focused Network Security Config tests passed (**8 passed**); full pytest passed (**1,197 passed**, 59.60 s), with compile and diff checks passing. This is offline path handling only; no Android platform TLS policy or live traffic behavior was exercised.

   SARIF export now validates generated documents against the bundled OASIS
   2.1.0 schema and the importer's shared run/rule/result/object-size bounds;
   file output is capped and atomically replaces symlink destinations using a
   private temporary file. Focused exporter/importer validation passed (**12
   passed**). This validates format and local file-write behavior only; no
   GitHub/GitLab ingestion or hosted CI integration is established.

   OpenAPI file export now applies a 16 MiB serialized-output cap and uses
   private-mode atomic replacement, so a pre-existing destination symlink is
   not followed. Synthetic tests cover replacement, file mode, and cap failure.
   Focused catalog/OpenAPI validation passed (**17 passed**); full-suite and
   compile results follow. This is local artifact handling only, not live
   capture, backend-contract completeness, or hosted validator integration.

   API capture retention now snapshots request fields after bounded validation
   instead of storing caller-owned mutable objects. Regression coverage mutates
   the original request and its maps after ingestion, then verifies the stored
   HAR/model remains the bounded original. Focused capture tests passed (**19
   passed**); full-suite and compile results follow. Raw observed values remain
   in process memory until object disposal and still require controlled data
   handling; the snapshot does not establish confidentiality or live capture.

   JSON request/response schema inference now iterates at most its 100-property
   sample directly instead of first allocating a list of every object member.
   A 10,000-property synthetic mapping verifies the visit cap and explicit
   truncation marker. Focused validation follows; this reduces intermediate
   allocation but does not establish complete schema inference.

   WebSocket setup now holds its pending-capacity reservation through awaited
   scan validation and transfers that slot to the active subscriber list
   without yielding, closing a concurrent-handshake over-admission race. A
   synthetic async interleaving with 31 occupied slots verifies the second
   handshake is rejected and the first activates at the cap. Focused WebSocket
   tests passed (**3 passed**); full-suite and compile results follow. This is
   local concurrency regression evidence, not production load testing.

   CycloneDX JSON/XML and SPDX JSON output now share a 16 MiB cap and private
   atomic replacement helper. Synthetic tests cover symlink replacement,
   private file permissions, and fail-before-write behavior for all three
   formats. Focused normative-schema and writer tests passed (**11 passed**);
   full-suite and compile results follow. The schema fixtures remain offline
   validation evidence for synthetic documents, not assurance of SBOM
   completeness or third-party tool interoperability.

   SBOM in-memory inventories are now explicitly capped at 10,000 components,
   5,000 vulnerability records, 64 licenses per component, and 100 CWEs per
   vulnerability. Exceeding a cap raises rather than silently dropping
   inventory. Focused normative SBOM tests passed (**9 passed**); full-suite
   and compile results follow. These item budgets do not establish that
   upstream scanners inventory every dependency.

   The legacy `ProfessionalReportExporter` Markdown path now enforces a 16 MiB
   output cap and uses private-mode atomic replacement rather than following a
   pre-existing symlink. Synthetic tests cover both conditions. Focused report
   writer tests passed (**2 passed**); full-suite and compile results follow.
   Other legacy file writers remain subject to separate review.

   Pentest checklist state persistence now uses a 1 MiB cap, private atomic
   replacement on save, and no-follow regular-file reads on load. Parsed rows
   are validated before any checklist item is mutated, preventing partial
   state application on malformed later entries. Focused checklist tests
   passed (**4 passed**); full-suite and compile results follow. This covers
   local planning-state persistence only; the checklist remains a planning
   reference and does not authorize or execute tests.

   HAR persistence now caps serialized output at 64 MiB and uses private-mode
   atomic replacement instead of writing through an existing destination
   symlink. Synthetic tests cover successful redacted serialization, symlink
   replacement, file mode, and fail-before-write size rejection. Focused HAR
   tests passed (**11 passed**); full-suite and compile results follow. This
   validates local export handling only, not completeness of captured traffic.

   The Orchestrator now validates caller-supplied scan IDs before path
   construction and refuses a per-scan directory that is a symlink or resolves
   outside the selected output root. Synthetic tests cover safe creation,
   traversal-shaped IDs, and a planted directory symlink without touching its
   target. Focused path tests passed; full-suite and compile results follow.
   This narrows path escape risk but does not make concurrent directory changes
   race-free.

   Scan `state.json` and generated review-only PoC guides now use private,
   atomic, bounded writes. Guide output is limited to 500 entries / 1 MiB each;
   filenames must be unique and match a path-safe Markdown pattern. Tests cover
   symlink replacement, mode, oversize rejection, traversal names, and duplicate
   names. Focused Orchestrator artifact regressions passed (**5 passed**); full
   suite and compile results follow. This hardens persistence only; generated
   guides remain unverified review plans and are never executed here.

   CLI JSON/Markdown output paths now use a shared 32 MiB private atomic writer;
   CLI finding exports apply the existing heuristic redactor before serialization.
   Unit regressions cover symlink replacement, private mode, oversize failure,
   byte payloads, and an end-to-end synthetic taint CLI export with a redacted
   credential. Focused tests passed (**4 passed**); full-suite and compile
   results follow. Heuristic redaction can miss unrecognized secrets, and this
   does not establish report completeness.

   Feedback training-data export now redacts each Qdrant payload, caps traversal
   at 100 pages / 10,000 labeled rows and 16 MiB, and writes through a private
   temporary file before atomic replacement. Synthetic async tests verify
   credential redaction, destination-symlink replacement, row/page-cap failure
   preservation, and temporary-file cleanup. Focused tests passed (**3
   passed**); full-suite and compile results follow. This does not establish
   training-data suitability or remove secrets missed by heuristic redaction.

   Flutter and Hermes analyzer outputs now reach the Orchestrator coverage
   ledger instead of being omitted. The ledger records bounded candidate
   counts, scan statuses, truncation/errors, and explicit non-exhaustive,
   runtime-not-tested, not-proven limitations; analyzer exceptions become
   incomplete coverage. Synthetic integration tests cover candidate
   propagation and truncated output (**3 focused tests passed**). Full pytest
   passed (**1,231 passed**, 62.37 s); compileall and `git diff --check` passed.
   This repairs coverage reporting only: neither probe is a framework
   decompiler, and the tests do not establish APK recall or runtime behavior.

Native JNI analyzer coverage is now copied into the orchestrator ledger with
inventory limits/skips, per-library statuses, candidate counts, and explicit
non-reachability/runtime-proof limitations. Analyzer exceptions become
incomplete coverage; no native library in a valid extraction is not applicable.
Synthetic propagation checks pass (**3 focused tests passed**). Full suite and
compile results follow; this adds reporting only, not Java-to-native call-flow
analysis.

Validation for the native-JNI coverage-ledger change: full pytest passed
(**1,231 passed**, 59.84 s); compileall and `git diff --check` passed. Results
are synthetic regression evidence, not native exploit or APK-wide coverage proof.

A follow-up failure-path regression forces the native-JNI worker to raise and
verifies the orchestrator records `static_status=incomplete` while preserving
`proof_status=not_proven`. Focused coverage tests passed (**2 passed**); full
pytest passed (**1,231 passed**, 61.51 s); compileall and `git diff --check`
passed. The injected exception is synthetic; no real native scan failure was
induced.

The Orchestrator engine summary now mirrors the Smali call-graph analyzer's
reported `static_status` instead of unconditionally labeling any non-throwing
run `completed_heuristically`. A synthetic partial-coverage integration case
passed with `tests/test_android_surface_coverage.py` (**34 passed**); full pytest
passed (**1,231 passed**, 61.16 s); compileall and `git diff --check` passed.
This makes the summary agree with analyzer coverage, not a claim of complete
call-graph or taint coverage.

The Orchestrator now synchronizes each successful analyzer's engine summary
with that analyzer's `static_status` when present (Android surface retains its
category-level WebView summary). This prevents partial scans from appearing
fully completed and distinguishes an offline-blocked OSV lookup from the local
dependency inventory: engine status reflects inventory coverage while
`lookup_status` remains `skipped_offline`. Synthetic tests cover partial
Dependency and Network Security Config statuses. Focused tests passed (**34
passed**); full pytest passed (**1,231 passed**, 60.15 s); compileall and
`git diff --check` passed. This validates summary consistency on fixtures, not
real APK coverage.

Expanded the engine-summary regression to cover partial API mapping, native
inventory, binary-protection, React Native, intent-redirection, PendingIntent,
FileProvider, dependency, and Network Security Config statuses. The focused
Orchestrator coverage file passed (**34 passed**); full pytest passed
(**1,231 passed**, 60.20 s); compileall and `git diff --check` passed. These
are controlled analyzer fixtures and do not establish real APK recall.

Flutter/Hermes empty-result coverage now distinguishes a valid resource tree
with no matching framework artifacts (`not_applicable`) from an invalid or
missing scan root (`incomplete`). The orchestrator passes root validity into
coverage aggregation, and synthetic regressions cover both outcomes. Focused
coverage tests passed (**3 passed**); full pytest passed (**1,232 passed**,
60.73 s); compileall and `git diff --check` passed. This fixes empty-result
status reporting only; it does not add framework format detection or analysis.

The per-scan API inventory endpoint now reports every returned route as an
unverified candidate instead of counting only records with a `VULNERABLE`
label (which could yield zero for a non-empty inventory). Non-list persisted
values fail closed to an empty inventory. Synthetic route coverage passed
(**2 focused tests**); full pytest passed (**1,233 passed**, 61.07 s);
compileall and `git diff --check` passed. `vulnerable_count` remains zero because
this inventory endpoint does not establish backend authorization proof.

IL2CPP coverage now distinguishes a complete scan with no Unity IL2CPP artifacts
(`not_applicable`) from an analyzed IL2CPP candidate (`analyzed_heuristically`),
invalid roots (`incomplete`), and truncation/errors (`partial`). The Orchestrator
also retains the bounded candidate count and scan errors. Synthetic status
regressions passed; full pytest passed (**1,234 passed**, 60.05 s); compileall
and `git diff --check` passed. This remains a version-limited metadata/string
probe, not C# decompilation or APK-wide coverage.

Static API mapping now records bounded GraphQL `query`/`mutation`/`subscription`
operation-name candidates with source path and line, separately from URL/route
candidates. It does not invent an HTTP path or treat an operation name as a
server endpoint. Comments are excluded; a 1,000-item cap marks coverage partial.
Synthetic positive, comment-negative, location, and cap regressions passed
(**2 focused tests**); full pytest passed (**1,236 passed**, 61.42 s); compileall
and `git diff --check` passed. This lexical inventory does not establish an
operation's execution, server schema, or authorization behavior.

GraphQL operation inventory now also reads bounded standalone `.graphql` and
`.gql` files. Their comments and quoted values are blanked before operation
matching while preserving line locations; unterminated strings mark static
coverage partial. Synthetic tests cover named operations, comment/description
negative controls, no fabricated HTTP endpoints, and malformed-input status.
Focused GraphQL tests passed (**4 passed**); full pytest passed (**1,238
passed**, 60.69 s); compileall and `git diff --check` passed. This remains a
bounded lexical candidate pass, not a GraphQL parser or server schema analysis.

The authenticated per-scan API inventory response now exposes the bounded static
GraphQL operation candidates and their count alongside route candidates, so
these lexical findings are accessible without mislabeling them as URLs. The
route inventory regression verifies this response shape (**2 focused tests**);
full pytest passed (**1,238 passed**, 61.30 s); compileall and
`git diff --check` passed. The response remains an unverified inventory, not a
server contract or authorization verdict.

Observed API capture now extracts bounded GraphQL operation type/name candidates
from JSON `query` bodies and publishes only those names in an OpenAPI vendor
extension; query/variable values are not copied into this metadata. Duplicate
JSON members, malformed strings, and query/operation caps produce explicit
coverage-gap counters. A shared lexical helper keeps standalone static GraphQL
scanning and observed-operation extraction consistent. Synthetic export tests
cover comment/description decoys, secret-value omission, duplicate-key rejection,
and OpenAPI validation. Focused dynamic tests passed (**2 passed**) and focused
static GraphQL tests passed (**4 passed**); full pytest passed (**1,240 passed**,
61.84 s); compileall and `git diff --check` passed. These are operation-name
observations only, not a GraphQL schema, server contract, or authorization result.

Direct `MobileApiCataloger.export_openapi_json()` output now carries a root
`x-mobileag-proof-state: not_proven` marker and explanatory text that captured
routes are not a complete backend contract or authorization proof; this boundary
no longer depends on using only the HTTP export route. Focused catalog tests
passed (**3 passed**); full pytest passed (**1,240 passed**, 61.24 s); compileall
and `git diff --check` passed. This is evidence labeling, not server validation.

Observed GraphQL operation extraction now also handles GET requests whose URL
query has a single `query` parameter. Repeated query parameters are treated as
ambiguous and mark a coverage gap; decoded query documents and variable values
are not copied into OpenAPI metadata. Synthetic tests verify operation-name
export, raw-query omission, and duplicate-query rejection (**2 focused tests**);
full pytest passed (**1,242 passed**, 62.06 s); compileall and
`git diff --check` passed. This is capture-derived operation-name evidence only.

GraphQL dynamic capture regressions now verify over-size documents set a
coverage-gap counter and global candidate-cap overflow increments the omitted
candidate count while keeping exports bounded. Focused GraphQL tests passed
(**6 passed**); full pytest passed (**1,244 passed**, 60.55 s); compileall and
`git diff --check` passed. These tests validate bounded candidate handling, not
exhaustive GraphQL parsing or server-side behavior.

The shared GraphQL lexical inventory now accepts operation declarations only
at document brace-depth zero, avoiding false operation candidates from fields
named `query`, `mutation`, or `subscription` inside a selection set. Focused
static/dynamic GraphQL tests passed (**11 passed**); full pytest passed
(**1,245 passed**, 61.00 s); compileall and `git diff --check` passed. The
scanner remains lexical and does not validate the complete GraphQL grammar.

Opt-in OSV batch processing now counts unexpected task-level exceptions as
failed advisory lookups before deriving `lookup_status`; `gather()` continues
to isolate peer requests, but those failures can no longer leave coverage
incorrectly marked `completed`. A synthetic task-failure regression and the OSV
suite passed (**8 passed**); full pytest passed (**1,246 passed**, 62.26 s);
compileall and `git diff --check` passed. This validates reporting for the
injected failure path, not OSV availability, advisory freshness, or package
inventory completeness.

Best-effort URL export redaction now removes userinfo even when the URL has a
username but no password (a case not caught by the prior credential-pattern
fallback), while retaining a valid userinfo-free IPv6 authority. Synthetic
privacy-export tests passed (**28 passed**); full pytest passed (**1,247
passed**, 61.72 s); compileall and `git diff --check` passed. This is a targeted
redaction improvement, not a guarantee against arbitrary secrets embedded in
unknown URL components or non-URL text.

Static API route normalization now recognizes percent-encoded sensitive path
markers (for example, `%74oken`) before redacting the following path value.
This closes an encoding variant that previously bypassed the path-marker
comparison. The focused API-mapper/depth regressions passed (**77 passed**);
full pytest passed (**1,247 passed**, 61.61 s); compileall and
`git diff --check` passed. Route normalization remains heuristic and does not
guarantee detection of every secret-bearing path convention.

The bounded route sanitizer is now shared by the static API mapper and Flutter,
Hermes, and IL2CPP embedded-URL candidate inventories. In addition to removing
queries/userinfo and redacting opaque values, it preserves chained sensitive
markers (such as `/auth/token/`) until the following value is redacted; this
prevents a marker itself from being replaced while accidentally exposing the
credential segment after it. Synthetic framework/API regressions passed (**137
passed**); full pytest passed (**1,247 passed**, 60.92 s); compileall and
`git diff --check` passed. These remain printable-string/route candidates, not
framework decompilation, endpoint reachability, or proof of credential use.

The same shared route sanitizer now covers iOS Mach-O embedded URL candidates,
so route/query/userinfo minimization applies consistently across the analyzed
Flutter, Hermes, IL2CPP, Mach-O, and static-source candidates. A synthetic Mach-O
fixture verifies that a chained `/auth/token/<value>` path retains only the
route markers and redacts the following value. Focused Mach-O tests passed (**15
passed**); full pytest passed (**1,247 passed**, 60.12 s); compileall and
`git diff --check` passed. This remains a bounded binary string candidate, not
proof of an iOS network request or Swift control flow.

Retained Hermes printable-string samples and Mach-O `__cstring` samples now
pass through shared candidate-text minimization: embedded URLs lose query,
fragment, userinfo, and recognized sensitive/opaque path values, and known
credential patterns are redacted before storage in the result object. Synthetic
Hermes/Mach-O fixtures verify that values in both token paths and URL queries do
not survive in retained samples. The roadmap module suite passed (**46
passed**); full pytest passed (**1,247 passed**, 60.31 s); compileall and
`git diff --check` passed. This minimizes known candidates but cannot guarantee
redaction of arbitrary application secrets in binary strings.

Token-session finding context URLs now use the same shared route sanitizer as
static and framework endpoint candidates. This aligns handling of encoded and
chained credential path markers and removes URL userinfo before endpoint
context is retained. Focused token/JWT tests passed (**17 passed**); full pytest
passed (**1,247 passed**, 60.52 s); compileall and `git diff --check` passed.
This is evidence minimization only; token parsing and server-side session
acceptance remain separate, bounded review tasks.

iOS `PrivacyInfo.xcprivacy` inventory now enforces a 16 MiB aggregate read
budget in addition to the per-file/tree caps, and bounds retained tracking
domains, API categories, and distinct error codes. Over-limit or malformed list
entries are recorded as partial coverage instead of being silently exposed as
complete declarations. Synthetic tests cover aggregate-byte truncation, output
caps, invalid oversized values, and normal manifest parsing. The full privacy /
road-map module file passed (**48 passed**); full pytest passed (**1,249
passed**, 60.56 s); compileall and `git diff --check` passed. This is bounded
declaration inventory, not Apple compliance or runtime API-use proof.

The iOS manifest parser now also retains bounded
`NSPrivacyAccessedAPITypeReasons` codes per declared API category and exposes
them in the IPA report, while flagging malformed/oversized entries as partial.
It records the supplied values only; it does not validate them against Apple's
current allowed-reason catalog or infer compliance. Focused privacy-manifest
tests passed (**7 passed**) and the IPA propagation test passed (**1 passed**);
full pytest passed (**1,250 passed**, 60.54 s); compileall and
`git diff --check` passed.

Static API URL inventory now caps processing at 1,000 endpoint records and reports
received, analyzed, omitted, invalid-record, and incomplete-URL counts. Empty
input is explicitly `not_analyzed`; malformed or over-limit input is `partial`,
not a clean result. Synthetic boundary tests passed (**21 passed** in
`test_workflow_draft_boundaries.py`). This is bounded URL-structure triage only;
it does not test API authorization, authentication, or rate limiting.
