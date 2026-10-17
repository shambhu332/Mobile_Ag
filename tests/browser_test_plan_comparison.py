"""Opt-in isolated Chromium check for the scan-bound manual retest workflow.

Run with the repository's cached Chromium path. Only synthetic SQLite scan
records and loopback requests are used; no APK, device, provider, or target is
accessed.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mobileag.web.repository import ScanRepository


def wait(page, selector: str, predicate, timeout: int = 10) -> None:
    import time
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = page.locator(selector).inner_text()
        if predicate(value):
            return
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {selector}; last text={page.locator(selector).inner_text()!r}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", default=str(Path.home() / ".cache/ms-playwright/chromium-1247/chrome-linux64/chrome"))
    args = parser.parse_args()
    if not Path(args.chromium).is_file():
        raise SystemExit(f"Chromium not found: {args.chromium}")
    token = "synthetic-local-retest-ui-only"
    with tempfile.TemporaryDirectory(prefix="mobileag-test-plan-ui-") as temporary:
        root = Path(temporary)
        data_root = root / "data"
        repo = ScanRepository(data_root / "output")
        for scan_id, digest, line in (("ui-baseline-synthetic", "b" * 64, 12),
                                      ("ui-current-synthetic", "c" * 64, 14)):
            repo.save({
                "scan_id": scan_id, "status": "completed", "created_at": "2026-10-13T00:00:00Z",
                "package_name": "org.example.synthetic", "version": "1.0-synthetic",
                "artifact_sha256": digest, "revision": 0,
                "findings": [{"id": f"finding-{scan_id}", "rule_id": "synthetic.rule",
                              "cwe_id": "CWE-79", "file_path": "src/Foo.java",
                              "line_number": line, "status": "UNVERIFIED"}],
                "coverage": {"synthetic": {"static_status": "completed"}},
                "artifact_provenance": {"tools": {"jadx": "synthetic-1"}},
            })
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env = os.environ.copy()
        for name in list(env):
            if name.endswith("_API_KEY") or name.startswith("MOBILEAG_LLM_"):
                env.pop(name)
        env.update(MOBILEAG_DATA_DIR=str(data_root), MOBILEAG_API_TOKEN=token,
                   OFFLINE="true", APPROVED_LLM_PROVIDERS="[]", PYTHONPATH=str(ROOT),
                   MOBILEAG_ALLOWED_DEVICES="", MOBILEAG_ALLOWED_ORIGINS="",
                   MOBILEAG_ALLOWED_CONNECT="")
        log_path = root / "server.log"
        with log_path.open("w") as log:
            server = subprocess.Popen([sys.executable, "-m", "mobileag.cli", "web",
                                       "--host", "127.0.0.1", "--port", str(port)],
                                      cwd=ROOT, env=env, stdout=log, stderr=log)
            try:
                origin = f"http://127.0.0.1:{port}"
                import time
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        raise RuntimeError(f"Synthetic server exited; see {log_path}")
                    try:
                        import urllib.request
                        with urllib.request.urlopen(origin, timeout=0.5) as response:
                            if response.status == 200:
                                break
                    except Exception:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Synthetic loopback server did not become ready")
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(executable_path=args.chromium, headless=True,
                                                         args=["--no-sandbox"])
                    context = browser.new_context()
                    blocked = []
                    context.route("**/*", lambda route: route.continue_() if
                                  urlsplit(route.request.url).netloc == f"127.0.0.1:{port}"
                                  else (blocked.append(route.request.url), route.abort()))
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(origin, wait_until="domcontentloaded")
                    assert page.locator("#session-token").count() == 0
                    page.locator("#nav-scans").click()
                    page.locator("#manual-test-plan summary").click()
                    wait(page, "#test-plan-scope", lambda text: "ui-current-synthetic" in text)
                    requested = []
                    page.on("request", lambda request: requested.append(request.url)
                            if "/planned-comparison" in request.url else None)
                    page.get_by_role("button", name="Compare with baseline").click()
                    wait(page, "#test-plan-status", lambda text: "Save a plan with a baseline" in text)
                    assert requested == []
                    baseline = page.locator("#manual-test-plan label").filter(
                        has_text="Optional baseline scan ID for retest linkage").locator("input")
                    baseline.fill("ui-baseline-synthetic")
                    page.get_by_role("button", name="Save manual plan").click()
                    wait(page, "#test-plan-status", lambda text: "Saved local manual plan revision" in text)
                    page.get_by_role("button", name="Compare with baseline").click()
                    wait(page, "#test-plan-comparison", lambda text: "artifact_binding_matches" in text)
                    comparison = page.locator("#test-plan-comparison").inner_text()
                    assert len(requested) == 1 and "/api/scans/ui-current-synthetic/planned-comparison" in requested[0]
                    assert "not_proof_of_fix" in comparison and '"fixed_count": null' in comparison
                    baseline.fill("ui-baseline-synthetic")
                    page.get_by_role("button", name="Compare with baseline").click()
                    wait(page, "#test-plan-status", lambda text: "Save or explicitly reload" in text)
                    assert len(requested) == 1, "unsaved edits must not issue another comparison request"
                    assert not blocked, blocked
                    assert not errors, errors
                    browser.close()
                print("PASS: frozen-plan comparison, unproven absence, dirty-draft block; synthetic loopback only")
            finally:
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
