# MobileAg

Autonomous multi-agent mobile application security testing framework powered by LLMs.

## Features

- **Multi-LLM Consensus Engine**: Uses Gemini, OpenAI, Claude, DeepSeek, and Grok to analyze code, voting on vulnerabilities to minimize false positives.
- **5-Layer False Positive Filter**: Verifies reachability, input sanitization, historical patterns (via Qdrant), and LLM consensus before confirming a finding.
- **Frida Script Generation**: Automatically writes app-specific Frida hooks to verify findings at runtime.
- **PoC Guide Generation**: Creates step-by-step markdown guides to reproduce the vulnerabilities.
- **Version Diffing**: Compares two APKs and highlights new attack surfaces (e.g., newly exported components, removed permission guards).

## Prerequisites

- Python 3.11+
- `apktool` and `jadx` installed and in PATH
- Optional: Ghidra for native analysis (`/opt/ghidra`)
- API Keys for one or more LLMs (Gemini, OpenAI, Claude, DeepSeek, Grok)

## Setup

1. Install dependencies via poetry or pip:
```bash
pip install -e .
```

2. Copy `.env.example` to `.env` and add your API keys:
```bash
cp .env.example .env
```

## Usage

### Scan an APK
```bash
mobileag scan --apk target.apk --output ./results
```

### Compare APK Versions
```bash
mobileag diff --old v1.apk --new v2.apk --output ./diff_results
```
