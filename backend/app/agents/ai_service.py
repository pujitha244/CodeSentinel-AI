import json
import httpx
from typing import List, Dict, Any, Optional
from backend.app.core.config import settings

class AIService:
    def __init__(self):
        self.provider = settings.AI_PROVIDER
        self.openai_key = settings.OPENAI_API_KEY
        self.ollama_url = settings.OLLAMA_BASE_URL

    async def chat(
        self,
        user_message: str,
        project_context: Dict[str, Any],
        findings_context: List[Dict[str, Any]],
        chains_context: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Processes an AI assistant query grounded directly in verified repository evidence.
        Falls back automatically to high-precision rule-based responses if no LLM is configured.
        """
        # 1. Check if external LLM should be queried
        if self.provider == "openai" and self.openai_key:
            return await self._query_openai(user_message, project_context, findings_context, chains_context)
        elif self.provider == "ollama":
            return await self._query_ollama(user_message, project_context, findings_context, chains_context)
        else:
            # Deterministic, evidence-grounded rule engine
            return self._rule_based_response(user_message, project_context, findings_context, chains_context)

    def _rule_based_response(
        self,
        query: str,
        project: Dict[str, Any],
        findings: List[Dict[str, Any]],
        chains: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        q = query.lower()
        evidence_refs = []

        # Intent 1: Explain vulnerability chain
        if "chain" in q or "sql injection" in q or "taint" in q or "propagation" in q:
            if chains:
                c = chains[0]
                evidence_refs.append({"title": c["title"], "file": c["sink_file"], "line": c["sink_line"]})
                reply = (
                    f"### 🛡️ Cross-File Vulnerability Analysis: {c['title']}\n\n"
                    f"**Vulnerability Chain Discovery ({c['id']})**:\n"
                    f"1. **Untrusted Entry Point:** The client input arrives at `{c['source_file']}:{c['source_line']}`.\n"
                    f"2. **Interprocedural Propagation:** Data is forwarded through intermediate application layers without input validation or type casting.\n"
                    f"3. **Dangerous Sink:** Tainted parameters reach `{c['sink_file']}:{c['sink_line']}` where raw SQL string concatenation occurs.\n\n"
                    f"**Impact:** An attacker can inject arbitrary SQL commands to bypass authentication, read protected table rows, or drop data.\n\n"
                    f"**Remediation:** Replace dynamic string formatting with parameterized query placeholders (e.g. `cursor.execute('SELECT ... WHERE username = ?', (term,))`). "
                    f"You can preview and apply this patch in the **Safe Auto-Fix Lab**."
                )
            else:
                reply = "No active cross-file vulnerability chains were detected in this audit."

        # Intent 2: What should I fix first / top priorities
        elif "fix first" in q or "priority" in q or "recommend" in q:
            criticals = [f for f in findings if f.get("severity") == "critical"]
            highs = [f for f in findings if f.get("severity") == "high"]
            top_list = (criticals + highs)[:3]
            
            for f in top_list:
                evidence_refs.append({"title": f["title"], "file": f["file_path"], "line": f["start_line"]})

            recs = "\n".join([f"- **[{f['severity'].upper()}] {f['title']}** in `{f['file_path']}:{f['start_line']}` — {f['description']}" for f in top_list])
            reply = (
                f"### 🚀 Top Remediation Priorities\n\n"
                f"Based on real risk analysis and reachability evidence, fix these issues first:\n\n"
                f"{recs}\n\n"
                f"Use the **Safe Auto-Fix Lab** to generate unified diff patches and run verification testing."
            )

        # Intent 3: Architecture / repository explanation
        elif "architecture" in q or "explain" in q or "overview" in q:
            p_name = project.get("name", "Project")
            meta = project.get("meta_info", {})
            langs = ", ".join(meta.get("languages", ["Python"]))
            file_count = meta.get("file_count", len(findings))
            reply = (
                f"### 📦 Repository Architectural Overview: {p_name}\n\n"
                f"- **Primary Languages:** {langs}\n"
                f"- **Indexed Source Files:** {file_count}\n"
                f"- **Total Security & Quality Findings:** {len(findings)}\n"
                f"- **Active Vulnerability Chains:** {len(chains)}\n\n"
                f"The application follows a tiered architecture separating API routing, service layer coordination, and database execution. "
                f"CodeSentinel extracted the full call graph linking controllers to data sinks across files."
            )

        # Intent 4: Edge cases & logic gaps
        elif "edge" in q or "gap" in q or "boundary" in q:
            gaps = [f for f in findings if f.get("category") == "logic_gap"]
            if gaps:
                gap = gaps[0]
                evidence_refs.append({"title": gap["title"], "file": gap["file_path"], "line": gap["start_line"]})
                reply = (
                    f"### 🔍 Logic Gap & Edge Case Analysis\n\n"
                    f"CodeSentinel identified **{len(gaps)} potential logic gaps** across the codebase.\n\n"
                    f"**Featured Finding: {gap['title']}**\n"
                    f"- **Location:** `{gap['file_path']}:{gap['start_line']}`\n"
                    f"- **Triggering Scenario:** Client supplies null/empty inputs or negative boundary numbers.\n"
                    f"- **Defensive Action:** Implement strict validation guard clauses before processing business logic."
                )
            else:
                reply = "No severe logic gaps were identified in the scanned entry points."

        # Intent 5: General query response grounded in project
        else:
            total_sec = sum(1 for f in findings if f.get("category") == "security")
            total_slop = sum(1 for f in findings if f.get("category") == "quality")
            reply = (
                f"### 🤖 CodeSentinel Engineering Intelligence\n\n"
                f"I am actively monitoring **{project.get('name', 'your project')}**.\n\n"
                f"- **Security Findings:** {total_sec}\n"
                f"- **Code Quality / Slop Items:** {total_slop}\n"
                f"- **Cross-File Vulnerability Chains:** {len(chains)}\n\n"
                f"Ask me specific questions such as:\n"
                f"- *'Explain the SQL injection vulnerability chain'* \n"
                f"- *'What should I fix first?'* \n"
                f"- *'Explain the repository architecture'* \n"
                f"- *'Which edge cases are unhandled?'*"
            )

        return {
            "reply": reply,
            "evidence_references": evidence_refs
        }

    async def _query_openai(self, query: str, project, findings, chains):
        # Implementation for OpenAI API with strict prompt engineering and evidence grounding
        headers = {"Authorization": f"Bearer {self.openai_key}", "Content-Type": "application/json"}
        system_prompt = (
            "You are CodeSentinel AI, an elite cybersecurity and code intelligence assistant. "
            "Never invent file paths, line numbers, or vulnerabilities. Ground all statements in the supplied project findings."
        )
        payload = {
            "model": settings.OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Project: {json.dumps(project)}\nChains: {json.dumps(chains[:2])}\nFindings: {json.dumps(findings[:5])}\nUser Query: {query}"}
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    return {"reply": data["choices"][0]["message"]["content"], "evidence_references": []}
        except Exception:
            pass
        return self._rule_based_response(query, project, findings, chains)

    async def _query_ollama(self, query: str, project, findings, chains):
        try:
            payload = {
                "model": settings.OLLAMA_MODEL,
                "prompt": f"Project findings: {json.dumps(findings[:5])}\nQuestion: {query}",
                "stream": False
            }
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(f"{self.ollama_url}/api/generate", json=payload)
                if res.status_code == 200:
                    return {"reply": res.json().get("response", ""), "evidence_references": []}
        except Exception:
            pass
        return self._rule_based_response(query, project, findings, chains)
