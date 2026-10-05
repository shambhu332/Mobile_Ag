# MobileAg Project Rules & Guardrails

## Tool Discovery & Executable Paths
- Never hardcode absolute executable paths (e.g. `/usr/local/bin/jadx` or `/usr/local/bin/apktool`).
- Always use `shutil.which("<tool>")` with fallback checks against `/usr/bin/jadx` and `/var/lib/snapd/snap/bin/apktool`.
- Verify ADB availability via `shutil.which("adb")` or `/usr/bin/adb`.

## JADX Decompilation Guidelines
- Always pass multi-threading flags (`-j 4` or `-j 8`) and `--show-bad-code` to prevent decompilation stalls on complex/obfuscated bytecode.
- Always wrap subprocess execution in an `asyncio.wait_for(..., timeout=90.0)` guard. If decompilation times out, log a warning and proceed gracefully with extracted sources and full Smali disassembly rather than crashing or blocking indefinitely.

## Web Telemetry & Scan State Invariants
- Whenever creating a scan record in `ACTIVE_SCANS[scan_id]`, ensure all expected keys are initialized: `findings`, `stats`, `agent_telemetry`, `api_endpoints`, `components`, `deep_links`, and `attack_surface_graph`.
- In telemetry workers, use `ACTIVE_SCANS[scan_id].setdefault(...)` when appending findings or telemetry items to prevent `KeyError`s during asynchronous streaming.

## Reporting & SARIF Export
- In `SARIFExporter`, always guard against `line_number` being `None` before casting to `int`: use `line_val = max(1, int(f_line)) if f_line is not None else 1`.
