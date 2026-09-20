# MobileAg Architecture & Component Map

## Overview
MobileAg is a modular mobile application security analysis framework designed to perform static code analysis, structural manifest auditing, and false-positive filtering using multi-model consensus and historical pattern matching.

```mermaid
flowchart TD
    subgraph Ingestion ["1. Ingestion Phase"]
        A[APK Extractor] --> B[Manifest Parser]
        A --> C[Framework Detector]
        A --> D[Packer Detector]
        A --> E[Obfuscation Analyzer]
    end

    subgraph Analysis ["2. Analysis Phase"]
        B & E --> F[Manifest Auditor]
        A --> G[Secret Scanner]
        A --> H[Code Reviewer]
        A --> I[API Mapper]
        A --> J[Native Analyzer]
        A --> K[Dependency Scanner]
    end

    subgraph Filtering ["3. Filtering Phase"]
        F & G & H & I & J & K --> L[Reachability Filter]
        L --> M[Sanitizer Filter]
        M --> N[Consensus Filter]
        N --> O[Historical Match Filter]
        O --> P[Confidence Scorer]
    end

    subgraph Output ["4. Generation & Reporting Phase"]
        P --> Q[Frida Template Engine]
        P --> R[PoC Guide Engine]
        Q & R --> S[Report Engine]
        S --> T[Markdown / JSON Reports]
    end
```

---

## Directory Structure

```
Mobile_Ag/
├── config/                  # Configuration & LLM Provider Routing
│   ├── llm_config.py
│   └── settings.py
├── data/                    # CWE, MASVS & Signature Reference Databases
│   ├── cwe_database.json
│   ├── known_packers.json
│   └── masvs_mapping.json
├── mobileag/
│   ├── analysis/            # Security Analysis Modules
│   │   ├── api_mapper.py
│   │   ├── code_reviewer.py
│   │   ├── dependency_scanner.py
│   │   ├── manifest_auditor.py
│   │   ├── native_analyzer.py
│   │   └── secret_scanner.py
│   ├── core/                # Pipeline Orchestration & State Management
│   │   ├── orchestrator.py
│   │   └── state.py
│   ├── diffing/             # APK Version Differential Analysis
│   │   └── version_diff.py
│   ├── filters/             # 5-Layer False-Positive Elimination Pipeline
│   │   ├── confidence.py
│   │   ├── consensus_vote.py
│   │   ├── historical_match.py
│   │   ├── pipeline.py
│   │   ├── reachability.py
│   │   └── sanitizer_check.py
│   ├── generators/          # Script & Guide Templating Engines
│   │   ├── frida_generator.py
│   │   ├── poc_generator.py
│   │   └── templates/
│   ├── ingestion/           # Extraction & Decompilation Parsers
│   │   ├── apk_extractor.py
│   │   ├── framework_detector.py
│   │   ├── manifest_parser.py
│   │   ├── obfuscation.py
│   │   └── packer_detector.py
│   ├── knowledge/           # Graph & Vector Database Integration
│   │   ├── feedback.py
│   │   ├── neo4j_graph.py
│   │   ├── qdrant_store.py
│   │   └── schemas.py
│   ├── llm/                 # Multi-LLM Provider Adaptors
│   │   ├── consensus.py
│   │   ├── fallback.py
│   │   ├── router.py
│   │   └── providers/
│   └── reporting/           # Report Compilation & Formatting
│       ├── cvss.py
│       ├── finding.py
│       ├── masvs.py
│       └── report_engine.py
├── tests/                   # Test Suite
├── docker-compose.yml       # Neo4j & Qdrant Services setup
├── pyproject.toml           # Project Dependencies
└── README.md                # Project Overview & Setup Instructions
```

---

## Phase Breakdown

| Phase | Component | Responsibilities |
|---|---|---|
| **Phase 1** | Configuration & Router | Multi-provider routing (Gemini, GPT, Claude, DeepSeek, Grok), state initialization, CVSS 3.1 calculation. |
| **Phase 2** | Ingestion & Analysis | Decompilation, manifest auditing, hardcoded key scanning, code review, API mapping, native `.so` inspection, dependency scanning. |
| **Phase 3** | Filtering & Knowledge | 5-layer false positive elimination (Reachability, Sanitizer, Consensus, Vector similarity, Scorer), Neo4j attack graph, Qdrant vector memory. |
| **Phase 4** | Orchestration & Output | Central state machine orchestrator, version diffing (`v1` vs `v2`), Markdown/JSON report engine, CLI interface. |
