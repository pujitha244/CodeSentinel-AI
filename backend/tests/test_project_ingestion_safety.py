import io
import zipfile
from pathlib import Path

import pytest

from backend.app.core.config import settings
from backend.app.services.project_service import ProjectService


@pytest.fixture
def isolated_project_dirs(tmp_path, monkeypatch):
    projects_dir = tmp_path / "projects"
    uploads_dir = tmp_path / "uploads"
    projects_dir.mkdir()
    uploads_dir.mkdir()
    monkeypatch.setattr(settings, "PROJECTS_DIR", projects_dir)
    monkeypatch.setattr(settings, "UPLOADS_DIR", uploads_dir)
    return projects_dir, uploads_dir


def _zip_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_zip_slip_is_rejected_and_partial_extraction_is_removed(
    isolated_project_dirs,
):
    projects_dir, uploads_dir = isolated_project_dirs
    archive = _zip_bytes(
        [("safe/readme.md", "ok"), ("../outside.txt", "should not escape")]
    )

    with pytest.raises(ValueError, match="escapes the project directory"):
        ProjectService.create_project_from_zip(archive, "upload.zip")

    assert list(projects_dir.iterdir()) == []
    assert list(uploads_dir.iterdir()) == []
    assert not (projects_dir / "outside.txt").exists()


def test_zip_upload_and_single_wrapper_folder_are_supported(isolated_project_dirs):
    projects_dir, uploads_dir = isolated_project_dirs
    result = ProjectService.create_project_from_zip(
        _zip_bytes([("repository/README.md", "demo")]),
        r"C:\fakepath\repository.zip",
    )

    assert result["name"] == "repository"
    assert result["source_url"] == "repository.zip"
    assert (Path(result["root_path"]) / "README.md").read_text(encoding="utf-8") == "demo"
    assert list(uploads_dir.iterdir()) == []


def test_archive_rejects_file_over_configured_limit(
    isolated_project_dirs, monkeypatch
):
    projects_dir, _ = isolated_project_dirs
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_KB", 1)

    with pytest.raises(ValueError, match="maximum file size"):
        ProjectService.create_project_from_zip(
            _zip_bytes([("large.txt", "x" * 2048)]),
            "large.zip",
        )

    assert list(projects_dir.iterdir()) == []
