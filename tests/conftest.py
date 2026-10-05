"""Tests must not execute device commands or consume real provider credentials."""
import importlib
from unittest.mock import AsyncMock
import pytest

@pytest.fixture(autouse=True)
def isolated_test_environment(monkeypatch, tmp_path):
    from mobileag.dast.adb_manager import ADBManager
    monkeypatch.setattr(ADBManager, '_exec_cmd', AsyncMock(return_value=(-1,b'',b'No real device in tests')))
    frida = importlib.import_module('mobileag.dast.frida_runner')
    monkeypatch.setattr(frida, 'HAS_NATIVE_FRIDA', False)
    monkeypatch.setenv('MOBILEAG_ALLOWED_HOSTS','testserver')
    monkeypatch.setenv('MOBILEAG_ALLOWED_DEVICES','emulator-5554')
    monkeypatch.setenv('MOBILEAG_ALLOWED_CONNECT','127.0.0.1:5555')
    monkeypatch.delenv('MOBILEAG_ALLOWED_ORIGINS',raising=False)
    monkeypatch.delenv('MOBILEAG_ALLOW_PRIVATE_TARGETS',raising=False)
    for key in ['OPENAI_API_KEY','GEMINI_API_KEY','ANTHROPIC_API_KEY','DEEPSEEK_API_KEY','XAI_API_KEY']:
        monkeypatch.delenv(key,raising=False)
    web = importlib.import_module('mobileag.web.app')
    monkeypatch.setattr(web,'ACTIVE_SCANS',{})
    monkeypatch.setattr(web,'DEMO_SCAN_CACHE',None)
    monkeypatch.setattr(web,'RUNTIME_SETTINGS',web.RUNTIME_SETTINGS.copy())
    uploads=tmp_path/'uploads';uploads.mkdir()
    monkeypatch.setattr(web,'UPLOAD_DIR',uploads)
    monkeypatch.setattr(web,'OUTPUT_DIR',tmp_path/'output')
