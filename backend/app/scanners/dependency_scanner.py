import json
import logging
import re
from pathlib import Path
from typing import List, Dict, Any
from backend.app.scanners.base_scanner import BaseScanner

KNOWN_CVE_ADVISORIES = {
    "requests": [
        {"max_version": "2.20.0", "cve": "CVE-2018-18074", "severity": "medium", "desc": "Redirect leak of Authorization headers to HTTPS hosts."}
    ],
    "urllib3": [
        {"max_version": "1.26.5", "cve": "CVE-2021-33503", "severity": "high", "desc": "ReDoS vulnerability in URL parsing leading to resource exhaustion."}
    ],
    "express": [
        {"max_version": "4.17.1", "cve": "CVE-2022-24999", "severity": "medium", "desc": "qs query string parsing vulnerability leading to prototype pollution."}
    ],
    "lodash": [
        {"max_version": "4.17.20", "cve": "CVE-2020-8203", "severity": "high", "desc": "Prototype pollution via template and defaultsDeep functions."}
    ],
    "pillow": [
        {"max_version": "9.0.0", "cve": "CVE-2022-22817", "severity": "high", "desc": "Arbitrary expression execution via PIL.ImageMath.eval."}
    ]
}

logger = logging.getLogger(__name__)


def _version_parts(version: str):
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", version):
        return None
    return tuple(int(part) for part in version.split("."))


def _possibly_affected(specifier: str, max_version: str):
    match = re.match(
        r"^\s*(===|==|~=|>=|<=|>|<|~|\^)?\s*(\d+(?:\.\d+){1,3})(?:\s*(?:,|;|$|<|>|=)|\.\*)",
        specifier,
    )
    declared = _version_parts(match.group(2)) if match else None
    cutoff = _version_parts(max_version)
    if declared is None or cutoff is None:
        return None

    width = max(len(declared), len(cutoff))
    declared += (0,) * (width - len(declared))
    cutoff += (0,) * (width - len(cutoff))
    operator = match.group(1) or "=="
    if operator == ">":
        return declared < cutoff
    if operator == ">=":
        return declared <= cutoff
    if operator in {"<", "<="}:
        return True
    return declared <= cutoff


class DependencyScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Dependency Advisory Catalog", category="dependency")

    def is_available(self) -> bool:
        return True

    def scan(self, project_root: str, target_files: List[str]) -> List[Dict[str, Any]]:
        root = Path(project_root).resolve()
        findings = []

        # 1. Check requirements.txt
        for file_rel in target_files:
            file_name = Path(file_rel).name.lower()
            file_abs = root / file_rel

            if file_name in ["requirements.txt", "requirements-dev.txt"]:
                try:
                    lines = file_abs.read_text(encoding="utf-8", errors="ignore").splitlines()
                except OSError as error:
                    logger.warning("Unable to read dependency manifest %s: %s", file_rel, error)
                    continue
                for idx, line in enumerate(lines, 1):
                    line_clean = line.strip().split("#")[0].strip()
                    if not line_clean:
                        continue
                    match = re.match(r"^([a-zA-Z0-9_-]+)\s*(.*)$", line_clean)
                    if match:
                        pkg_name = match.group(1).lower()
                        version_spec = match.group(2).strip()
                        if pkg_name in KNOWN_CVE_ADVISORIES:
                            for adv in KNOWN_CVE_ADVISORIES[pkg_name]:
                                affected = _possibly_affected(version_spec, adv["max_version"])
                                if affected is not True:
                                    continue
                                findings.append({
                                    "title": f"Vulnerable Dependency '{pkg_name}' ({adv['cve']})",
                                    "category": "dependency",
                                    "severity": adv["severity"],
                                    "confidence": 0.75,
                                    "file_path": file_rel,
                                    "start_line": idx,
                                    "end_line": idx,
                                    "snippet": line.strip(),
                                    "description": f"Declared version constraint {version_spec!r} may include {pkg_name} versions at or below {adv['max_version']}, listed for {adv['cve']}: {adv['desc']}",
                                    "impact": "Exposes application to known publicly disclosed vulnerability in third-party library.",
                                    "recommendation": f"Upgrade {pkg_name} to a version greater than {adv['max_version']}.",
                                    "verification": "Confirm the resolved dependency tree with a current package-audit tool.",
                                    "detection_method": "static_advisory_catalog"
                                })

            # 2. Check package.json
            elif file_name == "package.json":
                try:
                    data = json.loads(file_abs.read_text(encoding="utf-8", errors="ignore"))
                except (OSError, json.JSONDecodeError) as error:
                    logger.warning("Unable to parse dependency manifest %s: %s", file_rel, error)
                    continue
                deps = {
                    **(data.get("dependencies", {}) if isinstance(data.get("dependencies"), dict) else {}),
                    **(data.get("devDependencies", {}) if isinstance(data.get("devDependencies"), dict) else {}),
                }
                for pkg, ver_spec in deps.items():
                    if not isinstance(ver_spec, str):
                        continue
                    pkg_lower = pkg.lower()
                    if pkg_lower in KNOWN_CVE_ADVISORIES:
                        for adv in KNOWN_CVE_ADVISORIES[pkg_lower]:
                            affected = _possibly_affected(ver_spec, adv["max_version"])
                            if affected is not True:
                                continue
                            findings.append({
                                "title": f"Vulnerable Dependency '{pkg}' ({adv['cve']})",
                                "category": "dependency",
                                "severity": adv["severity"],
                                "confidence": 0.75,
                                "file_path": file_rel,
                                "start_line": 1,
                                "end_line": 1,
                                "snippet": f'"{pkg}": "{ver_spec}"',
                                "description": f"Declared version constraint {ver_spec!r} may include {pkg} versions at or below {adv['max_version']}, listed for {adv['cve']}: {adv['desc']}",
                                "impact": "Exposes application to known publicly disclosed vulnerability in third-party library.",
                                "recommendation": f"Upgrade {pkg} to a version greater than {adv['max_version']}.",
                                "verification": "Confirm the resolved dependency tree with a current package-audit tool.",
                                "detection_method": "static_advisory_catalog"
                            })

        return findings
