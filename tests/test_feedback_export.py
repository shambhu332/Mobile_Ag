"""Bounded, redacted, atomic feedback-training export regressions."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from mobileag.knowledge.feedback import FeedbackEngine


class FakeQdrantClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = 0

    async def scroll(self, **_kwargs):
        page = self.pages[self.calls]
        self.calls += 1
        return page


def _engine(pages):
    qdrant = SimpleNamespace(
        _connected=True,
        collection_name="synthetic-findings",
        client=FakeQdrantClient(pages),
    )
    return FeedbackEngine(qdrant, graph=None)


@pytest.mark.asyncio
async def test_training_export_redacts_and_atomically_replaces_destination_symlink(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("unchanged")
    output = tmp_path / "training.jsonl"
    output.symlink_to(target)
    payload = {"is_true_positive": True, "access_token": "syntheticSecretToken", "cwe": "CWE-79"}
    engine = _engine([([SimpleNamespace(payload=payload)], None)])

    await engine.export_training_data(output)

    assert output.is_file() and not output.is_symlink()
    assert target.read_text() == "unchanged"
    row = json.loads(output.read_text().strip())
    assert row["access_token"] == "[REDACTED]"
    assert row["cwe"] == "CWE-79"


@pytest.mark.asyncio
async def test_training_export_limit_failure_preserves_existing_output(tmp_path, monkeypatch):
    import mobileag.knowledge.feedback as feedback

    output = tmp_path / "training.jsonl"
    output.write_text("previous complete artifact")
    monkeypatch.setattr(feedback, "_MAX_TRAINING_EXPORT_ROWS", 0)
    engine = _engine([([SimpleNamespace(payload={"is_true_positive": False})], None)])

    await engine.export_training_data(output)

    assert output.read_text() == "previous complete artifact"
    assert not list(tmp_path.glob(".training.jsonl.*.tmp"))
