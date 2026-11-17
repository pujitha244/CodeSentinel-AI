from typing import List, Dict, Any, Tuple

class FindingCorrelator:
    @staticmethod
    def correlate_and_deduplicate(
        findings: List[Dict[str, Any]], 
        chains: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
        """
        1. Avoids double-counting: Links raw scanner findings that belong to a vulnerability chain
           under the parent chain.
        2. Deduplicates findings on the same file & start line with identical titles.
        3. Assigns unique structured IDs (e.g. CS-SEC-0001, CS-SLOP-0001, CS-GAP-0001).
        4. Calculates mathematically sound, transparent scores.
        """
        unique_findings = []
        seen_keys = set()

        # Step 1: Create Parent Findings for every Vulnerability Chain
        for chain in chains:
            chain_id = chain["id"]
            sink_file = chain["sink_file"]
            sink_line = chain["sink_line"]
            
            parent_finding = {
                "id": f"CS-CHAIN-{chain_id.split('-')[-1]}",
                "title": chain["title"],
                "category": "security",
                "severity": chain["severity"],
                "confidence": chain["confidence"],
                "file_path": sink_file,
                "start_line": sink_line,
                "end_line": sink_line,
                "snippet": chain["nodes"][-1]["data"].get("snippet", ""),
                "description": chain["description"],
                "impact": f"Verified interprocedural taint flow reaching dangerous sink in {sink_file}:{sink_line}.",
                "recommendation": chain["remediation_summary"],
                "verification": "Rerun taint analysis and security scanners to ensure untrusted input path is neutralized.",
                "detection_method": "cross_file_taint_engine",
                "status": "open",
                "chain_id": chain_id
            }
            unique_findings.append(parent_finding)
            seen_keys.add((sink_file, sink_line, chain["vulnerability_type"]))

        # Step 2: Add other findings, skipping ones already covered by chains
        sec_idx = 1
        gap_idx = 1
        loose_idx = 1
        qual_idx = 1
        secr_idx = 1
        dep_idx = 1

        for f in findings:
            key = (f["file_path"], f["start_line"], f["title"])
            if key in seen_keys:
                continue

            # Check if this raw finding is just an isolated manifestation of an already recorded chain
            file_path = f["file_path"]
            line = f["start_line"]
            category = f.get("category", "quality")
            
            # Check if covered by chain sink
            is_chain_sink = any(
                c["sink_file"] == file_path and abs(c["sink_line"] - line) <= 2
                for c in chains
            )
            if is_chain_sink and category == "security" and "SQL" in f["title"]:
                # Already captured by parent chain finding!
                continue

            seen_keys.add(key)

            # Assign prefix ID
            if category == "security":
                f_id = f"CS-SEC-{sec_idx:04d}"
                sec_idx += 1
            elif category == "secret":
                f_id = f"CS-SECR-{secr_idx:04d}"
                secr_idx += 1
            elif category == "logic_gap":
                f_id = f"CS-GAP-{gap_idx:04d}"
                gap_idx += 1
            elif category == "loose_end":
                f_id = f"CS-LOOSE-{loose_idx:04d}"
                loose_idx += 1
            elif category == "dependency":
                f_id = f"CS-DEP-{dep_idx:04d}"
                dep_idx += 1
            else:
                f_id = f"CS-QUAL-{qual_idx:04d}"
                qual_idx += 1

            f["id"] = f_id
            f["status"] = "open"
            f["chain_id"] = None
            unique_findings.append(f)

        # Step 3: Compute Transparent Scores
        counts = {
            "critical": sum(1 for f in unique_findings if f["severity"] == "critical"),
            "high": sum(1 for f in unique_findings if f["severity"] == "high"),
            "medium": sum(1 for f in unique_findings if f["severity"] == "medium"),
            "low": sum(1 for f in unique_findings if f["severity"] == "low"),
            "info": sum(1 for f in unique_findings if f["severity"] == "info"),
        }

        # Security Score formula
        sec_penalty = (counts["critical"] * 30.0) + (counts["high"] * 15.0) + (counts["medium"] * 6.0) + (counts["low"] * 2.0)
        security_score = max(0.0, min(100.0, 100.0 - sec_penalty))

        # Completeness Score formula
        loose_count = sum(1 for f in unique_findings if f["category"] == "loose_end")
        gap_count = sum(1 for f in unique_findings if f["category"] == "logic_gap")
        comp_penalty = (loose_count * 4.0) + (gap_count * 5.0)
        completeness_score = max(0.0, min(100.0, 100.0 - comp_penalty))

        # Quality Score formula
        qual_count = sum(1 for f in unique_findings if f["category"] == "quality")
        quality_score = max(0.0, min(100.0, 100.0 - (qual_count * 6.0)))

        # Weighted Engineering Health
        health_score = round((0.40 * security_score) + (0.30 * quality_score) + (0.30 * completeness_score), 1)

        scores = {
            "security_score": round(security_score, 1),
            "quality_score": round(quality_score, 1),
            "completeness_score": round(completeness_score, 1),
            "engineering_health_score": health_score,
            "counts": counts
        }

        return unique_findings, scores
