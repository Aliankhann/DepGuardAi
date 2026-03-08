"""
Unit tests for scan_agent.py pure functions.

Tests manifest parsing (_parse_package_json, _parse_requirements_txt)
and severity extraction (_extract_severity) in isolation — no I/O, no DB,
no OSV calls.

Uses pytest's tmp_path fixture to write real files on disk for parser tests.
"""

import json
import pytest

from app.services.agents.scan_agent import (
    _extract_severity,
    _parse_package_json,
    _parse_requirements_txt,
)


# ---------------------------------------------------------------------------
# _parse_package_json
# ---------------------------------------------------------------------------


def test_parse_package_json_happy_path(tmp_path):
    pkg = {
        "dependencies": {"lodash": "4.17.4", "express": "4.18.2"},
        "devDependencies": {"jest": "27.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    names = {p["name"] for p in result}
    assert names == {"lodash", "express", "jest"}
    assert all(p["ecosystem"] == "npm" for p in result)


def test_parse_package_json_extracts_correct_versions(tmp_path):
    pkg = {"dependencies": {"lodash": "4.17.4", "axios": "0.21.1"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    by_name = {p["name"]: p["version"] for p in result}
    assert by_name["lodash"] == "4.17.4"
    assert by_name["axios"] == "0.21.1"


def test_parse_package_json_strips_caret_prefix(tmp_path):
    pkg = {"dependencies": {"react": "^18.3.1"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    assert result[0]["version"] == "18.3.1"


def test_parse_package_json_strips_tilde_prefix(tmp_path):
    pkg = {"dependencies": {"lodash": "~4.17.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    assert result[0]["version"] == "4.17.0"


def test_parse_package_json_no_file_returns_empty(tmp_path):
    result = _parse_package_json(tmp_path)
    assert result == []


def test_parse_package_json_no_dependencies_key(tmp_path):
    pkg = {"name": "my-app", "version": "1.0.0"}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    assert result == []


def test_parse_package_json_empty_dependencies(tmp_path):
    pkg = {"dependencies": {}, "devDependencies": {}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    assert result == []


def test_parse_package_json_includes_dev_dependencies(tmp_path):
    pkg = {"devDependencies": {"jest": "27.0.0"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    assert len(result) == 1
    assert result[0]["name"] == "jest"


def test_parse_package_json_skips_non_semver_version(tmp_path):
    """Entries without a parseable version (e.g. 'file:', 'workspace:') are skipped."""
    pkg = {"dependencies": {"local-pkg": "file:../local", "valid": "1.2.3"}}
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    result = _parse_package_json(tmp_path)
    names = {p["name"] for p in result}
    assert "local-pkg" not in names
    assert "valid" in names


# ---------------------------------------------------------------------------
# _parse_requirements_txt
# ---------------------------------------------------------------------------


def test_parse_requirements_txt_pinned_version(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    result = _parse_requirements_txt(tmp_path)
    assert len(result) == 1
    assert result[0]["name"] == "requests"
    assert result[0]["version"] == "2.28.0"
    assert result[0]["ecosystem"] == "PyPI"


def test_parse_requirements_txt_tilde_equal(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask~=2.3.0\n")
    result = _parse_requirements_txt(tmp_path)
    assert result[0]["name"] == "flask"
    assert result[0]["version"] == "2.3.0"


def test_parse_requirements_txt_ge_constraint(tmp_path):
    (tmp_path / "requirements.txt").write_text("sqlalchemy>=2.0.0\n")
    result = _parse_requirements_txt(tmp_path)
    assert result[0]["name"] == "sqlalchemy"
    assert result[0]["version"] == "2.0.0"


def test_parse_requirements_txt_strips_extras(tmp_path):
    """requests[security]==2.28.0 — extras bracket must be removed from name."""
    (tmp_path / "requirements.txt").write_text("requests[security]==2.28.0\n")
    result = _parse_requirements_txt(tmp_path)
    assert result[0]["name"] == "requests"
    assert result[0]["version"] == "2.28.0"


def test_parse_requirements_txt_skips_comments(tmp_path):
    content = "# this is a comment\nrequests==2.28.0\n"
    (tmp_path / "requirements.txt").write_text(content)
    result = _parse_requirements_txt(tmp_path)
    assert len(result) == 1
    assert result[0]["name"] == "requests"


def test_parse_requirements_txt_skips_blank_lines(tmp_path):
    content = "\n\nrequests==2.28.0\n\n"
    (tmp_path / "requirements.txt").write_text(content)
    result = _parse_requirements_txt(tmp_path)
    assert len(result) == 1


def test_parse_requirements_txt_skips_flags(tmp_path):
    """Lines starting with '-' (e.g. -r other.txt, -i https://...) are skipped."""
    content = "-r base.txt\n-i https://pypi.org/simple\nrequests==2.28.0\n"
    (tmp_path / "requirements.txt").write_text(content)
    result = _parse_requirements_txt(tmp_path)
    assert len(result) == 1


def test_parse_requirements_txt_multi_constraint_picks_first(tmp_path):
    """flask>=2.0,<3.0 — only the first constraint version is used."""
    (tmp_path / "requirements.txt").write_text("flask>=2.0,<3.0\n")
    result = _parse_requirements_txt(tmp_path)
    assert result[0]["name"] == "flask"
    assert result[0]["version"] == "2.0"


def test_parse_requirements_txt_no_file_returns_empty(tmp_path):
    result = _parse_requirements_txt(tmp_path)
    assert result == []


def test_parse_requirements_txt_multiple_packages(tmp_path):
    content = "fastapi==0.111.0\nsqlalchemy==2.0.30\nhttpx==0.27.0\n"
    (tmp_path / "requirements.txt").write_text(content)
    result = _parse_requirements_txt(tmp_path)
    assert len(result) == 3
    names = {p["name"] for p in result}
    assert names == {"fastapi", "sqlalchemy", "httpx"}


# ---------------------------------------------------------------------------
# _extract_severity
# ---------------------------------------------------------------------------


def test_extract_severity_from_database_specific(dummy_osv=None):
    vuln = {"database_specific": {"severity": "HIGH"}}
    assert _extract_severity(vuln) == "HIGH"


def test_extract_severity_normalises_to_uppercase():
    vuln = {"database_specific": {"severity": "critical"}}
    assert _extract_severity(vuln) == "CRITICAL"


def test_extract_severity_defaults_to_medium_when_missing():
    assert _extract_severity({}) == "MEDIUM"
    assert _extract_severity({"database_specific": {}}) == "MEDIUM"


def test_extract_severity_ignores_other_fields():
    vuln = {"severity": "LOW", "database_specific": {"severity": "HIGH"}}
    assert _extract_severity(vuln) == "HIGH"


def test_extract_severity_empty_string_defaults_to_medium():
    vuln = {"database_specific": {"severity": ""}}
    assert _extract_severity(vuln) == "MEDIUM"
