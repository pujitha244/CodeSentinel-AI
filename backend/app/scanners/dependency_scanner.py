import json
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

class DependencyScanner(BaseScanner):
    def __init__(self):
        super().__init__(name="Dependency Security Advisor (OSV Catalog)", category="dependency")

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
                    for idx, line in enumerate(lines, 1):
                        line_clean = line.strip().split("#")[0].strip()
                        if not line_clean:
                            continue
                        # Match package==version or package>=version
                        match = re.match(r'^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=)\s*([0-9\.]+)', line_clean)
                        if match:
                            pkg_name = match.group(1).lower()
                            pkg_ver = match.group(2)
                            if pkg_name in KNOWN_CVE_ADVISORIES:
                                for adv in KNOWN_CVE_ADVISORIES[pkg_name]:
                                    findings.append({
                                        "title": f"Vulnerable Dependency '{pkg_name}' ({adv['cve']})",
                                        "category": "dependency",
                                        "severity": adv["severity"],
                                        "confidence": 0.89,
                                        "file_path": file_rel,
                                        "start_line": idx,
                                        "end_line": idx,
                                        "snippet": line.strip(),
                                        "description": f"Package {pkg_name} {pkg_ver} is vulnerable to {adv['cve']}: {adv['desc']}",
                                        "impact": "Exposes application to known publicly disclosed vulnerability in third-party library.",
                                        "recommendation": f"Upgrade {pkg_name} to a version greater than {adv['max_version']}.",
                                        "verification": "Check requirements file and test with pip audit.",
                                        "detection_method": "dependency_advisory_db"
                                    })
                except Exception:
                    pass

            # 2. Check package.json
            elif file_name == "package.json":
                try:
                    data = json.loads(file_abs.read_text(encoding="utf-8", errors="ignore"))
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for pkg, ver_spec in deps.items():
                        pkg_lower = pkg.lower()
                        if pkg_lower in KNOWN_CVE_ADVISORIES:
                            clean_ver = re.sub(r'[\^~>=<]', '', ver_spec).strip()
                            for adv in KNOWN_CVE_ADVISORIES[pkg_lower]:
                                findings.append({
                                    "title": f"Vulnerable Dependency '{pkg}' ({adv['cve']})",
                                    "category": "dependency",
                                    "severity": adv["severity"],
                                    "confidence": 0.89,
                                    "file_path": file_rel,
                                    "start_line": 1,
                                    "end_line": 1,
                                    "snippet": f'"{pkg}": "{ver_spec}"',
                                    "description": f"Node dependency {pkg} is affected by {adv['cve']}: {adv['desc']}",
                                    "impact": "Third-party supply chain risk impacting client or server execution.",
                                    "recommendation": f"Update {pkg} to latest stable release > {adv['max_version']}.",
                                    "verification": "Run npm audit to confirm fix.",
                                    "detection_method": "dependency_advisory_db"
                                })
                except Exception:
                    pass

        return findings
