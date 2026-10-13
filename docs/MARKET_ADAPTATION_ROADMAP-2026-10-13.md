# Mobile security market adaptation roadmap (2026-10-13)

## Purpose and decision

This translates the public market review into a realistic MobileAg product plan.
It is not a promise to reproduce every commercial feature, nor a claim that
MobileAg currently matches a commercial MAST platform. MobileAg's defensible
position is a local-first, scope-aware research workbench with unusually clear
evidence and coverage boundaries. Keep that trust property as a release gate.

Market references informing the plan: [OWASP MASTG](https://mas.owasp.org/MASTG/),
[NowSecure MAST](https://www.nowsecure.com/solutions/by-need/mobile-app-security-testing/),
[Appknox](https://www.appknox.com/), [Ostorlab](https://ostorlab.co/),
[Guardsquare AppSweep](https://www.guardsquare.com/appsweep-mobile-application-security-testing),
[MobSF](https://mobsf.org/), [Bishop Fox mobile assessments](https://bishopfox.com/services/penetration-testing-services/mobile-application-assessment),
[Appdome](https://www.appdome.com/mobile-app-security/), and
[Approov](https://docs.approov.io/introduction/overview/). These links describe
vendor-stated capabilities; they are not independent efficacy ratings.

## Baseline already present in this checkout

Do not rebuild existing capabilities under new labels. README.md and the
contributor roadmap already describe offline APK/IPA triage, evidence-bearing
unverified candidates, reports, explicit device/origin/stage approval,
bounded API replay, local sandboxing, scoped triage, readiness checks, and
synthetic benchmarks. The project also explicitly documents decompiler,
coverage, root/shell, and runtime-proof limitations. Current gaps are chiefly
measured breadth, assurance, evidence ergonomics, and operational product
quality—not a missing “AI pentest” button.

## Implementation status

- **P0.1 implemented for generated reports/exports:** confirmation is now
  fail-closed on scan-authoritative artifact hash, package, and version binding;
  unattached confirmations downgrade to UNVERIFIED. JSON, Markdown, SARIF, and
  professional Markdown expose evidence basis and binding status. Structured
  evidence is rendered only for bound analyst attestations, with default
  redaction. The synthetic loopback browser check renders the finding evidence
  panel and asserts that independent exploit verification is not established;
  it also checks text-only injection resistance. No report implies independent
  verification.
- **P0.2 core implemented; still partial:** the evaluator matches CWE plus
  normalized safe relative source/sink paths, sink line and, where labeled,
  source line per case; optional method matching supports simple names plus
  lexical owner/signatures when the bounded parser can derive them; counts
  distinct instances and duplicate outputs; treats unsafe explicit detector paths as execution
  failures rather than silently falling back to fixture paths; records case
  execution failures, Java parser-unavailable, syntax-error and parser-exception
  fallback counts, corpus/analyzer hashes, backend and tool versions. Committed
  fixtures are regression-only, not blind validation. Tree-sitter Java
  identities use parsed owner/signatures; Kotlin and fallback identities use
  bounded lexical parsing. Java AST traces now additionally carry a distinct
  package/import-qualified method label for unambiguous non-generic types. A
  bounded same-source top-level declared-type index now canonicalizes a simple
  signature type even when an unrelated wildcard import is present; duplicate
  top-level names, nested types, unresolved wildcard types, and capped indexes
  remain unqualified. The evaluator compares these labels only when explicitly
  supplied in expected instances. AST duplicates now enrich an existing lexical result
  with the AST trace while retaining the original lexical trace. The schema-v5
  evaluator tests an import-qualified flow and its patched negative control;
  the regression corpus and AST unit tests also cover a same-source declared
  type amid a wildcard import, with duplicate-name and lexical-fallback
  negative controls.
  Optional identity labels can make expected locations overlap; matching now
  uses deterministic maximum bipartite assignment rather than greedy tuple
  order, preventing a broad expectation from consuming the only observation
  available to a narrower expectation.
  Same-file tainted-parameter-to-sink summaries retain lexical method owner and
  arity, allowing same-named helpers in different classes to be distinguished.
  Direct identifier parameter forwarding can be composed across a bounded
  helper chain (at most 32 summary rounds and 5,000 summaries per source file);
  same-owner/same-arity overloads
  are withheld because argument-type dispatch is unresolved. Synthetic
  positive-chain, transformed-argument negative, and ambiguous-overload tests
  cover this bounded improvement; it is not cross-file or general call-graph
  analysis, and calls through other receivers remain unresolved. Bounded direct,
  transitive, round-limit, and summary-budget counts are available in taint
  coverage and the report capability inventory; limits mark the scan partial.
  These remain analyzer instrumentation, not recall.
  This is syntactic name canonicalization only: it does
  not resolve symbols, wildcard/generic types, overload dispatch, or cross-file receivers;
  the existing lexical identity is retained, and ambiguous types withhold the
  qualified label. Corpus input accounting now distinguishes submitted,
  completed, failed and skipped cases. Output schema v5 is published and tested
  against evaluator output; it accepts optional,
  bounded per-case unsupported-construct labels and counts them without
  upgrading the global unsupported-construct state: automatic unsupported
  constructs remain `not_measured`, and APK extraction omissions remain
  `not_in_scope`. APK ingestion now counts bounded ZIP/DEX/native-library inputs,
  compares root DEX members with expected Apktool smali directories, and records
  bounded Apktool/JADX stdout/stderr marker counts without retaining raw logs.
  These are heuristic messages, not skipped-file or unsupported-construct
  counts. Apktool's regular `.smali` output files are now counted per expected
  DEX directory with symlink-safe bounded traversal; this is output inventory,
  not decoded-class completeness or analyzer-consumption proof. Directory
  comparison detects missing expected output directories, not incomplete
  decoding inside them. A bounded DEX header/table reader now compares class
  descriptor sets against Apktool `.class` directives where the ASCII-only
  descriptor subset, canonical one-to-one DEX-directory mapping, and size
  budgets permit: it reports exact missing/extra descriptor counts for those
  extracted outputs, not general decompiler completeness or analyzer
  consumption. Bounded Modified UTF-8 decoding now supports BMP and surrogate-
  pair descriptors and compares them with UTF-8 Apktool Smali names; malformed
  MUTF-8, unsupported DEX data, ambiguous mappings, and budget limits fail
  closed to `incomplete`. Synthetic non-ASCII positives and invalid four-byte
  UTF-8 negatives cover this boundary. Checksums,
  bytecode decoding, JADX coverage and unsupported constructs remain
  `not_measured`. A descriptor mismatch is an ingestion discrepancy, not a
  vulnerability or proof of exploitability. The capability inventory exposes
  aggregate and per-DEX missing/extra counts without descriptor strings, and
  ambiguous directory mapping is explicitly marked incomplete. Per-DEX
  file-count deltas remain only a discrepancy signal, not an exact omission total.
  Bounded source analyzers now also report exact counts for encountered skipped
  inputs and stopping conditions by fixed reason code (for example symlink,
  oversized file, traversal error, entry/byte budget, or analyzer result cap),
  without retaining paths. Capability inventory JSON and Markdown summaries
  carry those counters where the bounded analyzer coverage path exposes them.
  This describes the local inventory reader and
  analyzer caps only; it does not identify decompiler-omitted classes or
  language constructs the analyzers fail to recognize.
  Tree-sitter Java syntax-error fallbacks now additionally count observed
  `ERROR`/missing AST nodes under a 100,000-node per-file visit budget and
  separately count files whose node count hit that budget. This measures
  parser-reported syntax-error nodes, not unsupported language features,
  semantic errors, or decompiler omissions; the latter remain `not_measured`.
  Missing counts are not represented as zero. Both AST-enabled and lexical tests now score two
  distinct real same-file flows and a patched second-flow negative control.
  No field accuracy or APK-wide recall claim is made.
- **P0.3 implemented as a fail-closed review ledger:** JSON, Markdown,
  professional Markdown, and SARIF now include a conservative review-surface
  ledger with mapped analyzer status, runtime
  state, evidence state, and explicit unmapped surfaces. It only crosswalks
  existing coverage metadata; it does not claim that the surface was tested
  end to end. Evidence states follow the fail-closed taxonomy, and every row
  retains `proof_status=not_proven` and `independently_verified=false`. Parsed
  manifest component inventory is now recorded separately;
  serialization/logging/preference-storage have bounded lexical review mappings, with the
  ObjectInputStream flow count mapped separately, and FileProvider
  declarations have a static inventory mapping. Backup/logging coverage does
  not inherit unrelated generic manifest candidate counts; the backup-rule
  inventory and logging analyzer are crosswalked independently. Effective runtime
  authorization, dataflow, URI-grant issuance/access, and comprehensive
  storage/backup/logging behavior remain untested or unproven. Each ledger row
  also emits specific gap reasons for unrecorded/partial analyzer states,
  recorded skipped-source counts, and named bounded-limit counters, alongside
  mapped coverage-path pointers and its surface-specific limitation. These
  describe coverage metadata only and do not upgrade evidence or proof states.
- **P0.4 implemented for available evidence:** JSON, Markdown, professional
  Markdown, and SARIF now carry source/sink trace metadata where recorded,
  structured evidence for artifact-bound attestations, and explicit limits.
  Report-bound evidence is redacted by default. Reachability prerequisites,
  controls, and reproduction data are shown only when present in the evidence;
  absent data remains a gap, not an inferred proof.
- **P1 manifest inventory slice:** the pipeline now records whether the
  parsed-manifest auditor completed, plus bounded component/exported-component
  and candidate counts, and exposes those counts through the ledger. Component
  permission inventory now records explicit versus application-inherited
  `android:permission`, provider read/write overrides, and explicit per-path
  permission scopes; exported-provider review checks each declared direction
  rather than only the generic permission.
  Exported use of an in-manifest custom permission whose base protection is
  `normal` or `dangerous` yields an INFO/UNVERIFIED review candidate, including
  compound protection flags and provider-wide/per-path read/write use sites.
  This is not merged-manifest validation, permission protection/signature
  verification, URI-grant enforcement, or effective caller-authorization testing.
  Requested permission inventory now includes both `uses-permission` and
  `uses-permission-sdk-23` declarations, retaining `maxSdkVersion` and
  `usesPermissionFlags` context; request declarations are not interpreted as
  actual grants or effective device behavior.
  Permission references resolve only when they name one bounded plain string
  literal from Apktool `res/values*` with no conflicting qualifier variant;
  XML aliases, non-plain values, binary resource tables, merged-manifest
  effects, and dynamic references remain unresolved. Exported components with
  unresolved `@...`/`?...` permission references retain an INFO-only manual
  review lead rather than being treated as proof of either authorization or
  unrestricted access. Resource values themselves are not copied into the
  inventory summary.
- **P1 provider-path configuration slice:** the manifest parser resolves only
  simple symbolic FileProvider `@xml/name` resources beneath the extracted
  `res/xml` directory, records grant/path-permission declarations, and flags
  broad configured roots as INFO/UNVERIFIED review candidates. Missing, unsafe,
  overlarge, or malformed resources are incomplete. This does not prove a URI
  grant was issued, caller access, or sensitive-file exposure.
- **P1.6 implemented as bounded configuration review only:** manifest parsing
  and provider-path review now cover symbolic FileProvider resources,
  component/exported-component inventory, URI grant declarations and broad
  configured roots. A lexical PendingIntent factory check emits INFO-only
  manual-review candidates when literal mutability flags are absent and a
  separate lead when the final flags argument contains literal
  `FLAG_MUTABLE`; unrelated earlier arguments cannot trigger or suppress the
  review. It resolves only unique bounded Java `final int` and Kotlin `const val Int` aliases initialized with flag-only expressions; helpers, reassigned/local aliases, duplicate declarations, and unsupported expressions remain unresolved, and it does not prove unsafe fill-in behavior. Effective
  full permission resolution and runtime WebView bridge/origin review remain
  incomplete. A same-method INFO-only WebView lead now requires literal
  JavaScript enablement plus a content-load or bridge-registration call;
  co-occurrence still does not establish attacker control, origin, registration
  effectiveness, or reachability. Storage/log review is not comprehensive.
  Java URI-query/component AST
  flow candidates can now be joined to an exported manifest URI-route class
  only by an exact package/import and same-source lexical-qualified owner identity; the route
  context is attached to findings and coverage, but same-class association does
  not prove that the route invokes the method or that the flow is reachable,
  unguarded, or exploitable. Component, route, and finding inventories are
  capped at 5,000/5,000/10,000 respectively; truncation is explicit and marks
  correlation `partial` rather than implying complete inventory. Cross-file dispatch, wildcard/type resolution,
  runtime WebView bridge/origin, and storage/log review remain incomplete.
  A bounded sensitive-identifier heuristic also emits INFO/UNVERIFIED review
  leads for preference-like writes (for example an identifier named
  `accessToken` passed to `putString`); comments and string literals are
  excluded. It does not establish storage API semantics, value sensitivity,
  encryption, backup inclusion, accessibility, or dataflow. The storage surface
  ledger maps this instrumentation without upgrading evidence. A separate
  INFO-only lead recognizes literal `MODE_WORLD_READABLE`/
  `MODE_WORLD_WRITEABLE` only in the mode argument of `openFileOutput` or
  `getSharedPreferences`; other arguments, comments, and literals do not
  trigger it. Deprecated mode detection does not establish target/API behavior
  or cross-app accessibility. A bounded Java
  source-to-sink path now follows recognized untrusted input,
  including an `Intent.getData()` URI opened by a declared `ContentResolver`
  through `openInputStream`, `openAssetFileDescriptor`, `openFileDescriptor`,
  or `openTypedAssetFileDescriptor`, through simple local assignments into
  `ObjectInputStream.readObject()` and emits only an INFO/CWE-502 UNVERIFIED
  candidate. Intent-byte-array and URI-stream positives, plus local/static
  byte/URI negative controls, are covered. This does not establish provider
  control, URI-grant entitlement, returned content trust, custom serializers,
  object filters, guards, cross-file flow, or actual reachability. Same-method lexical proximity
  checks still surface INFO-only leads for external-input/WebView-bridge
  interactions; a separate bounded CWE-79 INFO candidate traces attacker input
  only through the `loadDataWithBaseURL` base/data arguments (not history or
  unrelated arguments). WebView taint counts are recorded separately in the
  review ledger; effective origin, bridge exposure, guards, and runtime flow
  remain unproven. WebView source-site inventory records bounded
  `@JavascriptInterface` methods and same-file registrations; a direct
  unqualified `new Type()`/`Type()` registration is associated with annotated methods only
  when exactly one lexical class declaration matches. Variable aliases,
  duplicate class names, and other expressions remain unresolved. This does
  not prove effective registration, a reachable WebView, origin, invocation,
  or authorization. Java
  parameters and bounded Kotlin `name: Type` parameters on lexically `@JavascriptInterface`
  annotated methods (including annotations on the declaration line) can also
  act as candidate taint sources into that sink; annotation adjacency is
  checked, but registration beyond that direct same-file association, WebView settings,
  SDK behavior, caller origin, and execution are not resolved. Kotlin parameter
  extraction and a synthetic bridge-parameter-to-HTML-sink path are covered,
  along with unannotated-method negative controls. Identifier-based log statements also surface INFO-only
  review candidates; bounded `Timber` calls (including `Timber.tag(...).d(...)`)
  are also inventoried when sensitive-looking identifiers occur in arguments.
  This remains identifier-based review only, not sensitive-value flow proof.
  Manifest coverage now
  inventories bounded `fullBackupContent` and `dataExtractionRules` resource
  references and summarizes matching decoded XML include/exclude counts and
  domains. Rule paths are omitted from report coverage; unresolved/unsafe/
  overlarge/malformed resources remain incomplete. It does not infer sensitive
  data inclusion, effective cloud/device-transfer backup behavior, or impact.
  None of these checks establishes value flow or runtime accessibility.
- **P1.7 partial:** bounded native byte-string plus ELF class/machine, SONAME,
  GNU build ID, per-library SHA-256, `DT_NEEDED`, and undefined dynamic
  function-symbol inventory with bounded deterministic per-library name samples
  (with a synthetic compiler fixture proving import classification only; no
  callsite, disassembly, argument, or dataflow proof)
  and Maven/Gradle dependency parsing exist, including literal Gradle strings,
  common single-line Groovy map notations, Gradle lockfiles, literal Gradle
  version catalogs only when their bounded aliases are referenced by supported
  dependency declarations (unused catalog entries no longer count as resolved
  packages); line and block comments are excluded from literal Gradle coordinate
  parsing to avoid sending commented-out dependencies to OSV. Embedded
  `pom.properties` are also inventoried. A DTD/entity-rejecting bounded POM
  reader inventories only root-level direct dependencies with literal coordinates
  or bounded whole-value properties declared in that same POM; parent/effective
  model, built-in/parent property, profile, dependency-management, and imported-BOM entries stay
  unresolved, and embedded `META-INF/maven` library POMs are not treated as
  application dependency proof. Effective Maven models and transitive
  resolution remain unsupported. Unresolved/dynamic
  declarations are counted rather than evaluated, and malformed catalogs make
  coverage partial. When present in the analyzed tree, bounded npm
  `package-lock.json` v1/v2/v3 package coordinates
  with exact semver versions are also inventoried and may be queried as npm
  when advisory lookup is separately authorized. V1's nested tree is walked
  iteratively under a 10,000-entry limit; v2/v3's `packages` map uses the same
  cap. Yarn v1 `yarn.lock` selector records are also inventoried under the same
  10,000-selector bound when the v1 format marker is present; Yarn Berry and
  dynamic/resolution-alias records remain unsupported and partial. Unsupported lockfile versions,
  dynamic/workspace entries, malformed records, and inventory limits downgrade
  coverage rather than being treated as resolved dependencies. APKs often do
  not package build-time lockfiles; their absence is not evidence of no
  third-party dependencies. Dependency coordinates are inventoried even
  offline; OSV lookups require explicit per-invocation `--lookup-advisories`
  authorization; offline mode is a hard egress prohibition and cannot be
  overridden by per-invocation consent. Tests assert zero client construction
  when consent is supplied alongside offline settings. Authorized online OSV
  lookups now stream responses under a 1 MiB per-body limit, cap accepted
  vulnerabilities at 100 per package and findings at 500 per scan, bound
  advisory text/metadata, and report truncation or malformed result counts as
  partial coverage. Freshness is `not_retrieved` if no valid response arrives;
  OSV results remain unverified. The body cap is enforced during streaming,
  not after buffering the full response. ELF hash/build ID identify exact bytes, not the
  source or release version; package coordinate accuracy and advisory freshness
  remain unvalidated. These are not full binary/dependency analyses.
- **P1.5 inventory implemented; measurement remains partial:** JSON, Markdown,
  and professional reports now enumerate Java/Kotlin, Smali, native/JNI,
  React Native, WebView hybrid,
  Flutter, Xamarin, Cordova, Unity, split APK/AAB, multi-DEX, and obfuscation.
  Each row separates bounded implemented support from per-scan execution and
  states limitations; partial/fallback execution is distinct from skipped or
  incomplete execution. Framework signature detection now preserves all
  matching framework hints instead of overwriting earlier matches, and the
  capability matrix separately labels each signature as detected, not
  detected only after a complete bounded traversal, incomplete, or not
  recorded; detection never changes the analysis execution or proof state.
  Synthetic multi-signature, complete-empty, truncated, and unknown-state tests
  cover this distinction. A separate offline `inventory-aab` command now
  validates bounded bundle ZIP structure and inventories top-level module/asset-
  pack manifests, DEX-header class-count, and native-library member counts with input SHA-256;
  it writes a versioned standalone JSON schema and never extracts, decodes
  protobuf manifests, synthesizes APKs, or runs analyzers. Synthetic complete,
  partial, unsafe-archive, and no-overwrite cases are covered. The matrix is
  not validated recall; split delivery and framework corpus measurements
  remain absent. APK DEX member counts, expected
  Apktool output directories, per-DEX declared class-definition/output-file
  count deltas, and bounded descriptor-set comparison against Apktool output
  are measured, but bytecode decode completeness, malformed-input
  behavior across decompilers,
  exact skipped/unsupported class counts, and multi-DEX semantic coverage are
  not. Bounded per-category Apktool/JADX log marker counts now flow into scan coverage;
  observed error/unsupported/skip markers or truncated log classification
  downgrade decompiler review coverage and preserve per-tool counts without
  retaining log text. Categories may overlap, and counts are not deduplicated
  across tool logs. These are diagnostic marker-line counts only: exact
  omitted-file and unsupported-construct counts remain null, and absence of a
  marker is not completeness proof. A decoded single-APK manifest's optional `split` attribute is recorded
  as a narrow indicator; absence does not establish a base/complete install.
  AAB module inventory does not measure delivered split-set completeness or
  device-specific selection.
- **P1.8 partial:** runtime evidence components exist, but current unrooted
  device outcomes are not established. No live device test was in scope or
  performed.
- **P2.9 partially implemented:** documented offline JSON scan command and
  JSON/SARIF/Markdown output exist; JSON now carries a schema version with a
  published v1 schema and SARIF carries run tool/artifact identity. Synthetic
  CLI contract tests verify offline mode, success `0` for completed scans even
  with candidates, and nonzero for incomplete scans. Scan JSON is not
  byte-for-byte reproducible: timestamps and scan identifiers are intentionally
  per-run values. A local CI gate now builds the wheel twice from isolated
  identical source snapshots with fixed `SOURCE_DATE_EPOCH`; matching hashes
  establish packaging reproducibility only within that build environment. A local rerun on 2026-10-13 produced identical wheel SHA-256 `e431fcbdeaef59c1b9191ff85e387d0b8076cb14c5aa7e0a696e073fdab526e7`; this does not establish hosted-runner or supply-chain reproducibility. CI pins Python 3.14.7, exact PEP 517
  setuptools/wheel versions, and runtime/test constraints; the hosted Ubuntu
  image, package supply chain, and APK decompiler extraction are not hermetic or
  proven reproducible. CI
  installation against the remote package index has not been exercised here.
- **P2.10 partial:** scan-scoped revision-aware triage and evidence history
  remain. A new read-only `GET /api/scans/{current}/comparison/{baseline}`
  comparison requires completed scans for the same package, binds both scan
  IDs and artifact hashes, matches exact rule/CWE/file/sink-line identities,
  preferring explicit finding/metadata rule or check IDs and using detector plus
  sink operation only as a fallback. A synthetic control proves distinct check
  IDs from one analyzer do not collapse into a false persistence match. It
  reports unmatchable counts. A missing current candidate is explicitly
  `not_proof_of_fix`; `fixed_count` stays null. The read-only response now also
  reports whether recorded tool-version and coverage objects are equal, different,
  or unknown. Equality is explicitly not treated as analyzer/coverage equivalence.
  A saved test plan now freezes its same-package baseline scan ID, artifact SHA-256, and version; `GET /api/scans/{scan_id}/planned-comparison` rechecks the baseline scan ID, package, artifact hash, and recorded app version and fails closed if the referenced binding changed. The editor now uses that route and blocks comparisons while plan edits are unsaved. A Chromium regression, `tests/browser_test_plan_comparison.py`, is now part of the Project validation CI browser job; it verifies the saved-plan route, artifact-binding status, `not_proof_of_fix` behavior, and dirty-draft block against an isolated loopback server with synthetic scans. Comparison output remains read-only. A separate `relocation_leads` list now offers only a unique possible file-move hint when rule/CWE, qualified method identity, and sink operation agree; exact-location absence remains `not_proof_of_fix` and ambiguous or unqualified cases receive no lead. This is not a finding match, semantic moved-code analysis, or fix verdict; richer moved-code matching and fuller retest workflow UX still need product/design review.
- **P2.12 API/storage slice implemented:** authenticated per-scan GET/PUT
  test-plan records are revisioned in local SQLite, bound to the completed
  scan's package and artifact SHA-256, and deleted with that scan's evidence.
  The bounded schema captures roles, flow descriptions, test-account aliases,
  surface coverage, manual evidence notes tied to flows/findings, and optional
  same-package baseline scan linkage. Credentials, arbitrary scope/action fields,
  unknown surface names, stale revisions, and invalid finding/flow references
  are rejected; secret-like note text is redacted. This records operator
  planning/attestation only and cannot authorize or execute target testing.
  A collapsible in-dashboard editor now provides bounded multi-entry controls
  for roles, flows, aliases, coverage, and evidence notes; scan changes preserve
  dirty drafts until explicit reload, and save stays disabled while plan loading
  fails. Plan deletion is shown in the explicit scan purge preview. This remains
  record-only, not approval/execution; a deeper retest-aware evidence lifecycle
  still needs product/design review.
- **P2.11 SARIF implemented; MobSF subset import implemented:** `mobileag.cli import-sarif`
  offers a local offline importer for bounded SARIF 2.1.0, validating the
  vendored OASIS draft-07 schema before projecting an intentionally limited
  subset, with size/run/result limits. It rejects
  unsafe artifact URIs, deduplicates rule/location results, records input
  SHA-256 and tool provenance, redacts output, ignores producer evidence, and
  always labels results UNVERIFIED. It writes a separate
  new file and never changes scan history. The full upstream schema is pinned
  by source/hash and has no runtime external references. A separate
  `mobileag.cli import-mobsf-json` command now accepts only the recognized
  Android `code_analysis.findings` and `manifest_analysis.manifest_findings`
  shapes, under a 5 MiB, 5,000-candidate, and 20,000 source-location-entry
  bound. Its MobileAg projection schema
  is versioned, unsafe source paths are omitted, output is redacted, duplicate
  rule/location rows are removed, and imported findings stay UNVERIFIED with
  zero confidence and `proof_status=not_proven`. It writes a new file only and
  does not mutate scan history, bind an artifact, import producer evidence, or
  support dynamic reports. Synthetic tests model the observed shape, not a
  producer-generated compatibility corpus; MobSF-version compatibility and
  interoperability remain partial pending authorized real report fixtures.
- **P3.13–15 intentionally not implemented:** shielding/RASP/MTD, cloud AI as
  a dependency, and multi-tenant hosting need explicit product, privacy,
  authorization, and architecture decisions; they are not implied by this
  implementation request.

**Completion boundary:** the local evidence/reporting safeguards, initial
instance evaluator, capability inventory, several INFO-only Android review
checks, offline dependency inventory, CLI JSON contract, bounded SARIF
projection with full schema validation, ELF import inventory, and bounded
root-DEX-to-Smali directory, declared-class-count and bounded descriptor-set accounting have
implemented/tested slices. The roadmap is not complete:
remaining substantial work includes semantic symbol/type-resolved flow-instance
attribution beyond package/import and unique same-source top-level type name
canonicalization, decompiler-level
skipped-file and unsupported-construct measurement,
broader Android/native/framework analyzer coverage, and hosted-runner/build-supply-chain
reproducibility validation.
Authorized current-device
validation and independent blind corpora need external assets/approval;
immutable retest comparison and full interoperability need design review; P3
items are separate product decisions. Synthetic tests do not prove field
efficacy or production exploitability.

## Prioritized implementation plan

Priority means sequencing, not severity. Each item needs an issue/design review
before broad implementation. No target access, provider egress, or device use is
authorized by this roadmap.

### P0 — Trustworthy evidence and test quality (next)

1. **Evidence contract audit.** Inventory every finding/report/UI/export path.
   Require stable artifact identity (hash, package/version where available),
   analyzer/tool/backend versions, source location, evidence state, and explicit
   gaps. Keep static candidate, runtime observation, analyst attestation, and
   independent verification distinct. Ensure missing evidence never becomes a
   clean verdict.
2. **Finding instance matching.** Extend benchmark evaluation beyond
   CWE-per-case to normalized source/sink locations and individual flow
   instances. Retain positive and hard-negative fixtures; publish parser
   failures, skipped files, and unsupported constructs. Do not publish a single
   accuracy score without corpus size, provenance, and limitations.
3. **Coverage ledger.** Create one coherent per-surface ledger for manifest/IPC,
   serialization, files/URI grants, storage/logging, WebView/deep links,
   network/API/authentication, crypto/native code, and runtime. States must be
   fail-closed (`not_tested`, `candidate`, `observed`, `attested`,
   `independently_verified`, or justified `not_applicable`) with an evidence
   pointer and gap reason. Reuse existing stage and scan coverage instead of
   duplicating or inferring execution from configuration.
4. **Report review UX.** Make a report easy to validate: source → guard → sink,
   reachability prerequisites, observed impact, artifact/build identity,
   reproduction notes, remediation, and a negative control. Redact secrets by
   default; preserve raw evidence separately only with explicit operator action.

**Acceptance:** synthetic fixtures and negative controls; JSON/Markdown/SARIF
round trips; parser/decompiler failures; tests proving no unsupported result is
reported as a pass. Full tests and focused browser regression. No real app,
account, device, or external service is needed.

### P1 — Mobile analysis depth (after P0)

5. **Framework and binary coverage inventory.** Measure Java/Kotlin, native/JNI,
   Flutter, React Native, hybrid WebView, split APK/AAB, multi-DEX, obfuscation,
   and malformed inputs. For each, record supported behaviors and honest
   unsupported/partial status. Add only bounded analyzers with test fixtures.
6. **Android surface analyzers.** Prioritize effective exported-component and
   permission reasoning, app links/deep links, content-provider roots/grants,
   PendingIntent mutability, WebView origin/bridge flows, backup/log exposure,
   and untrusted deserialization—always linking a controllable entrypoint to a
   sensitive sink before raising confidence. A manifest declaration alone is
   not proof of runtime reachability or exploitability.
7. **Native and dependency inventory.** Add bounded native-library and
   dependency inventory with provenance, parser limitations, and advisory
   freshness. Network advisory lookup must remain an explicit separately
   authorized operation; offline analysis stays offline.
8. **Runtime evidence improvements.** Add safe, read-only, reproducible evidence
   collection only for explicitly approved devices and packages. Preserve
   package/PID attribution and OS/build/ABI identity. Root, shell, hooks, or
   older OS results remain labeled modified-lab observations, not ordinary-app
   proof.

**Acceptance:** separate synthetic or authorized, independently reviewed
corpora; exact positive/negative cases; versioned device/tool provenance;
current unrooted-device tests only when specifically approved. Do not claim
whole-app recall from a focused detector benchmark.

### P2 — Workflow and integrations (only after design review)

9. **Reproducible local CI mode.** Provide a documented, deterministic local
   command/JSON contract suitable for CI, preserving offline defaults, stable
   exit semantics, artifact hashes, tool versions, and coverage gaps.
10. **Finding lifecycle and retest.** Add revision-bound triage, fix state, and
    explicit retest linkage to immutable scan identity. Avoid a “fixed” state
    inferred from a later scan unless the same rule/location and relevant
    evidence are compared.
11. **Optional import/export interop.** Consider MobSF/SARIF imports only after
    defining source provenance, schema validation, size/resource limits,
    secret redaction, deduplication, and trust labels. Imported tool results
    must not become MobileAg-verified findings.
12. **Human-assisted testing workflow.** Add a structured test-plan and
    evidence-capture workflow (roles, flows, test accounts, coverage, findings,
    retest), not automated arbitrary tapping or unbounded fuzzing. Scope and
    approval remain explicit.

**Acceptance:** local synthetic integration; exact schemas and migration tests;
negative tests for scope expansion, unsafe imports, stale revisions, and
secret persistence. No vendor API credentials or customer APKs in tests.

### P3 — Optional protection and enterprise features (separate product decision)

13. **Do not build app shielding/RASP or MTD into MobileAg by default.** Those
    are separate product categories with signing, compatibility, SDK, runtime,
    privacy, threat telemetry, and operational-response obligations. If ever
    pursued, first produce a threat model, customer need, platform design,
    privacy review, supply-chain review, and dedicated release/test plan.
14. **Do not add cloud AI as a default scanner dependency.** Existing consented
    aggregate-metadata review must remain optional and isolated. Any new provider
    needs explicit egress/retention review, data minimization, cancellation,
    and fail-closed behavior.
15. **No multi-tenant/remote-hosting claim yet.** The current documented
    single-operator local model is not a SaaS authorization boundary. Remote
    deployment requires a separate architecture for tenant isolation, RBAC,
    secrets, quotas, auditability, upload isolation, and threat modeling.

## Explicit non-goals

- Do not copy claims such as “detects every bug,” vendor accuracy percentages,
  “certified secure,” or a generic vulnerability-count leaderboard.
- Do not equate shielding, pinning, app attestation, obfuscation, or rooted-lab
  behavior with secure backend authorization.
- Do not add automatic target discovery, unapproved live API testing, implicit
  device selection, credential collection, root/SSL bypass, destructive tests,
  or hidden provider/network calls.
- Do not treat MASVS mapping as certification or exhaustive coverage.

## Release scorecard

Every release candidate should report: tests run; benchmark corpus and
partition; TP/FP/FN by detector and backend; instance/location matching status;
parser/decompiler failures; unsupported formats; coverage gaps; tool/build
versions; and any device/browser acceptance performed. Unit tests, synthetic
benchmarks, browser tests, and real-device validation are separate evidence
classes. Passing one does not imply the others ran.

## Suggested sequence

Start with P0.1–P0.3 as separate reviewable changes; they improve trust across
all existing analyzers and reports. Then implement one P1 analyzer at a time,
selected by a labeled corpus and user value. P2 integrations and P3 product
categories need explicit design approval because they materially expand data,
authorization, or operational boundaries.
