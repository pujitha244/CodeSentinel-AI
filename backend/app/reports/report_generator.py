import json
from datetime import datetime
from typing import Dict, Any, List

class ReportGenerator:
    @staticmethod
    def generate_json(audit: Dict[str, Any], project: Dict[str, Any], findings: List[Dict[str, Any]], chains: List[Dict[str, Any]]) -> str:
        report = {
            "meta": {
                "tool": "CodeSentinel AI",
                "version": "1.0.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "project_name": project.get("name"),
                "audit_id": audit.get("id")
            },
            "scores": {
                "engineering_health": audit.get("engineering_health_score"),
                "security": audit.get("security_score"),
                "quality": audit.get("quality_score"),
                "completeness": audit.get("completeness_score"),
                "code_slop": audit.get("slop_score")
            },
            "counts": {
                "total": audit.get("total_findings"),
                "critical": audit.get("critical_count"),
                "high": audit.get("high_count"),
                "medium": audit.get("medium_count"),
                "low": audit.get("low_count")
            },
            "vulnerability_chains": chains,
            "findings": findings
        }
        return json.dumps(report, indent=2)

    @staticmethod
    def generate_markdown(audit: Dict[str, Any], project: Dict[str, Any], findings: List[Dict[str, Any]], chains: List[Dict[str, Any]]) -> str:
        md = []
        md.append(f"# CodeSentinel AI — Security & Code Intelligence Audit Report")
        md.append(f"**Project:** {project.get('name')} | **Audit ID:** `{audit.get('id')}` | **Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        
        md.append("## 📊 Executive Health Scoreboard")
        md.append(f"| Dimension | Score | Rating |")
        md.append("|---|---|---|")
        md.append(f"| **Engineering Health** | **{audit.get('engineering_health_score')}/100** | {'Excellent' if audit.get('engineering_health_score', 0) > 80 else 'Action Required'} |")
        md.append(f"| **Security Posture** | **{audit.get('security_score')}/100** | {'Secure' if audit.get('security_score', 0) > 80 else 'Vulnerable'} |")
        md.append(f"| **Code Quality** | **{audit.get('quality_score')}/100** | Standard |")
        md.append(f"| **Completeness** | **{audit.get('completeness_score')}/100** | Evaluated |")
        md.append(f"| **Code Slop Index** | **{audit.get('slop_score')}/100** | Clean |")
        md.append("")

        if chains:
            md.append("## 🛡️ Flagship Cross-File Vulnerability Chains")
            for c in chains:
                md.append(f"### {c['id']}: {c['title']} ({c['severity'].upper()})")
                md.append(f"- **Source:** `{c['source_file']}:{c['source_line']}`")
                md.append(f"- **Sink:** `{c['sink_file']}:{c['sink_line']}`")
                md.append(f"- **Confidence:** {int(c['confidence'] * 100)}%")
                md.append(f"- **Description:** {c['description']}")
                md.append(f"- **Remediation:** {c['remediation_summary']}")
                md.append("")

        md.append("## 🔍 Detailed Findings")
        for f in findings:
            md.append(f"### [{f.get('severity', 'medium').upper()}] {f.get('id', 'FINDING')}: {f.get('title', 'Untitled')}")
            md.append(f"- **File:** `{f.get('file_path')}:{f.get('start_line', 1)}`")
            md.append(f"- **Category:** `{f.get('category', 'security')}` | **Detection Method:** `{f.get('detection_method', 'static_analysis')}`")
            md.append(f"- **Description:** {f.get('description', '')}")
            if f.get("snippet"):
                md.append("```")
                md.append(f.get("snippet"))
                md.append("```")
            md.append(f"- **Recommendation:** {f.get('recommendation', '')}")
            md.append("")

        return "\n".join(md)

    @staticmethod
    def generate_html(audit: Dict[str, Any], project: Dict[str, Any], findings: List[Dict[str, Any]], chains: List[Dict[str, Any]]) -> str:
        rows = ""
        for f in findings:
            sev_color = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "info": "#94a3b8"
            }.get(f["severity"], "#94a3b8")

            rows += f"""
            <tr style="border-bottom: 1px solid #1e293b;">
                <td style="padding: 12px; font-weight: 600; color: {sev_color}; text-transform: uppercase;">{f['severity']}</td>
                <td style="padding: 12px; font-family: monospace; color: #38bdf8;">{f['id']}</td>
                <td style="padding: 12px; color: #f8fafc; font-weight: 500;">{f['title']}</td>
                <td style="padding: 12px; font-family: monospace; color: #cbd5e1;">{f['file_path']}:{f['start_line']}</td>
                <td style="padding: 12px; color: #94a3b8; font-size: 13px;">{f['recommendation']}</td>
            </tr>
            """

        chain_cards = ""
        for c in chains:
            chain_cards += f"""
            <div style="background: #1e293b; border-left: 4px solid #ef4444; border-radius: 8px; padding: 20px; margin-bottom: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h3 style="margin: 0; color: #f8fafc; font-size: 18px;">{c['title']}</h3>
                    <span style="background: #7f1d1d; color: #fca5a5; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: bold;">CRITICAL • {int(c['confidence']*100)}% CONFIDENCE</span>
                </div>
                <p style="color: #cbd5e1; margin-bottom: 12px; line-height: 1.5;">{c['description']}</p>
                <div style="background: #0f172a; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #38bdf8; margin-bottom: 12px;">
                    <div><strong>Untrusted Source:</strong> {c['source_file']}:{c['source_line']}</div>
                    <div style="margin-top: 4px;"><strong>Dangerous Sink:</strong> {c['sink_file']}:{c['sink_line']}</div>
                </div>
                <div style="color: #4ade80; font-size: 13px;"><strong>Recommended Fix:</strong> {c['remediation_summary']}</div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CodeSentinel AI Audit Report - {project.get('name')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 24px; margin-bottom: 30px; }}
        .score-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 35px; }}
        .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; }}
        .score-num {{ font-size: 32px; font-weight: bold; margin-top: 8px; color: #38bdf8; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; background: #111827; border-radius: 8px; overflow: hidden; }}
        th {{ background: #1f2937; padding: 12px; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 28px; color: #ffffff;">🛡️ CodeSentinel AI Audit Report</h1>
                <p style="margin: 6px 0 0; color: #94a3b8;">Autonomous Security & Engineering Intelligence Audit</p>
            </div>
            <div style="text-align: right;">
                <div style="font-weight: 600; color: #38bdf8; font-size: 16px;">{project.get('name')}</div>
                <div style="color: #64748b; font-size: 12px; margin-top: 4px;">{datetime.utcnow().strftime('%B %d, %Y')}</div>
            </div>
        </div>

        <div class="score-grid">
            <div class="card">
                <div style="color: #94a3b8; font-size: 13px;">Engineering Health</div>
                <div class="score-num" style="color: #4ade80;">{audit.get('engineering_health_score')}<span style="font-size: 18px; color: #64748b;">/100</span></div>
            </div>
            <div class="card">
                <div style="color: #94a3b8; font-size: 13px;">Security Posture</div>
                <div class="score-num" style="color: #ef4444;">{audit.get('security_score')}<span style="font-size: 18px; color: #64748b;">/100</span></div>
            </div>
            <div class="card">
                <div style="color: #94a3b8; font-size: 13px;">Code Quality</div>
                <div class="score-num" style="color: #f59e0b;">{audit.get('quality_score')}<span style="font-size: 18px; color: #64748b;">/100</span></div>
            </div>
            <div class="card">
                <div style="color: #94a3b8; font-size: 13px;">Total Findings</div>
                <div class="score-num" style="color: #f8fafc;">{audit.get('total_findings')}</div>
            </div>
        </div>

        <h2 style="font-size: 20px; color: #f8fafc; margin-bottom: 16px;">Cross-File Vulnerability Chains</h2>
        {chain_cards if chains else "<p style='color: #94a3b8;'>No cross-file chains detected.</p>"}

        <h2 style="font-size: 20px; color: #f8fafc; margin-top: 40px; margin-bottom: 16px;">Comprehensive Security & Engineering Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Location</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>

        <div style="margin-top: 40px; border-top: 1px solid #1e293b; padding-top: 20px; text-align: center; color: #64748b; font-size: 12px;">
            Generated autonomously by CodeSentinel AI • Confidential Application Security Audit
        </div>
    </div>
</body>
</html>"""
        return html
