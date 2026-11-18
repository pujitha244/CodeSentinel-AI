import pytest

from backend.app.remediation.remediation_engine import RemediationEngine


def test_remediation_rejects_paths_outside_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("original", encoding="utf-8")
    engine = RemediationEngine(str(project))

    with pytest.raises(ValueError, match="inside the project"):
        engine.apply_patch("../outside.py", "changed")
    with pytest.raises(ValueError, match="inside the project"):
        engine.rollback_patch("../outside.py")

    assert outside.read_text(encoding="utf-8") == "original"


def test_remediation_rejects_stale_preview_without_writing(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("latest source", encoding="utf-8")
    engine = RemediationEngine(str(tmp_path))

    with pytest.raises(ValueError, match="changed after the patch was previewed"):
        engine.apply_patch("source.py", "patched", expected_code="older source")

    assert source.read_text(encoding="utf-8") == "latest source"
    assert not (tmp_path / "source.py.codesentinel_backup").exists()


def test_remediation_backup_and_rollback_restore_file(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("original", encoding="utf-8")
    engine = RemediationEngine(str(tmp_path))

    assert engine.apply_patch("source.py", "patched", expected_code="original")
    assert source.read_text(encoding="utf-8") == "patched"
    with pytest.raises(ValueError, match="backup already exists"):
        engine.apply_patch("source.py", "another patch", expected_code="patched")

    assert engine.rollback_patch("source.py")
    assert source.read_text(encoding="utf-8") == "original"


def test_unsupported_finding_produces_explicit_no_patch_preview(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("value = 1\n", encoding="utf-8")
    patch = RemediationEngine(str(tmp_path)).generate_patch(
        {
            "id": "finding-1",
            "title": "Unsupported issue",
            "category": "security",
            "file_path": "source.py",
            "snippet": "value = 1",
            "description": "No supported automatic fix.",
        }
    )

    assert patch["has_changes"] is False
    assert "No supported automatic change" in patch["explanation"]
