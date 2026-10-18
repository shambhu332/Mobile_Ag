import pytest

from mobileag.dast.adb_manager import ADBManager


@pytest.mark.asyncio
async def test_installed_apk_identity_hashes_package_manager_paths_and_matches():
    adb = ADBManager()
    calls = []
    async def fake(args, **kwargs):
        calls.append(args)
        if args[-3:-1] == ["pm", "path"]:
            return 0, b"package:/data/app/org.example/base.apk\n", b""
        return 0, b"a" * 64 + b"  /data/app/org.example/base.apk\n", b""
    adb._exec_cmd = fake
    result = await adb.installed_apk_identity("emulator-1", "org.example.app", "a" * 64, guard=lambda: True)
    assert result == {"status": "matched", "apk_count": 1, "installed_sha256": "a" * 64, "reason": None}
    assert calls[0][-3:] == ["pm", "path", "org.example.app"]
    assert calls[1][-2:] == ["sha256sum", "/data/app/org.example/base.apk"]


@pytest.mark.asyncio
async def test_installed_apk_identity_does_not_equate_split_or_unavailable_to_match():
    adb = ADBManager()
    async def split(args, **kwargs):
        return 0, b"package:/data/app/x/base.apk\npackage:/data/app/x/split_config.apk\n", b""
    adb._exec_cmd = split
    result = await adb.installed_apk_identity("emulator-1", "org.example.app", "a" * 64, guard=lambda: True)
    assert result["status"] == "mismatch" and result["apk_count"] == 2
    assert "split" in result["reason"]


@pytest.mark.asyncio
async def test_installed_apk_identity_requires_validated_scope_and_inputs():
    adb = ADBManager()
    with pytest.raises(PermissionError):
        await adb.installed_apk_identity("emulator-1", "org.example.app", "a" * 64)
    with pytest.raises(ValueError):
        await adb.installed_apk_identity("emulator-1", "org.example;id", "a" * 64, guard=lambda: True)
    with pytest.raises(ValueError):
        await adb.installed_apk_identity("emulator-1", "org.example.app", "bad", guard=lambda: True)
