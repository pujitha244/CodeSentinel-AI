import json

from backend.app.scanners.dependency_scanner import DependencyScanner


def test_requirements_scanner_checks_declared_version_constraints(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "\n".join(
            [
                "requests==2.20.0",
                "requests==2.20.1",
                "urllib3>=1.26.5",
                "lodash>4.17.20",
                "pillow>=9.0.0,<10.0.0",
                "express @ https://example.invalid/express.whl",
            ]
        ),
        encoding="utf-8",
    )

    findings = DependencyScanner().scan(str(tmp_path), ["requirements.txt"])

    assert [finding["snippet"] for finding in findings] == [
        "requests==2.20.0",
        "urllib3>=1.26.5",
        "pillow>=9.0.0,<10.0.0",
    ]
    assert all(finding["confidence"] == 0.75 for finding in findings)
    assert all(finding["detection_method"] == "static_advisory_catalog" for finding in findings)


def test_package_json_scanner_skips_known_safe_and_unresolved_ranges(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(
        json.dumps(
            {
                "dependencies": {
                    "express": "^4.17.1",
                    "lodash": "^4.17.21",
                    "requests": "latest",
                }
            }
        ),
        encoding="utf-8",
    )

    findings = DependencyScanner().scan(str(tmp_path), ["package.json"])

    assert len(findings) == 1
    assert findings[0]["snippet"] == '"express": "^4.17.1"'
    assert "may include" in findings[0]["description"]


def test_version_parser_does_not_treat_post_release_as_vulnerable(tmp_path):
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("requests==2.20.0.post1\n", encoding="utf-8")

    assert DependencyScanner().scan(str(tmp_path), ["requirements.txt"]) == []
