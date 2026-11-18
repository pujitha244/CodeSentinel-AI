# CodeSentinel AI — System Architecture & Design Specification

## 1. Executive Architectural Overview

CodeSentinel AI is a static cybersecurity and software engineering audit platform. It models available codebase relationships, correlates supported Python interprocedural taint flows, uncovers selected boundary conditions, and can verify remediation with a targeted static re-scan.

```mermaid
graph TD
    subgraph Ingestion
        A1[ZIP Upload] --> B[Project Service]
        A2[GitHub API Ingestion] --> B
        A3[Built-in Demo Repository] --> B
    end

    subgraph "Structural Understanding & Call Graph"
        B --> C[File Indexer & Language Detector]
        C --> D[Python AST Visitor]
        C --> E[JS/TS Token & Structural Parser]
        D --> F[Import Resolver]
        E --> F
        F --> G[Call Graph Builder]
    end

    subgraph "Static Scanners & Analyzers"
        G --> H1[Security Scanner]
        G --> H2[Secret Sentinel]
        G --> H3[Dependency CVE Advisor]
        G --> H4[Quality Standards Scanner]
        G --> H5[Code Slop Engine]
        G --> H6[Logic Gap Hunter]
        G --> H7[Loose Ends Detector]
    end

    subgraph "Flagship Interprocedural Taint Engine"
        G --> I[Source Identifier]
        I --> J[Path Propagation BFS]
        J --> K[Validation Boundary Inspector]
        K --> L[Dangerous Sink Detector]
        L --> M[Vulnerability Chain Synthesizer]
    end

    subgraph "Correlation & Prioritization"
        H1 & H2 & H3 & H4 & H5 & H6 & H7 & M --> N[Finding Correlator]
        N --> O[Transparent Health & Risk Scorer]
        O --> P[(SQLite / PostgreSQL Persistence)]
    end

    subgraph "Actionable Intelligence"
        P --> Q[Safe Auto-Fix Lab]
        P --> R[Repository-Aware AI Assistant]
        P --> S[Interactive Vulnerability Chain Explorer]
        P --> T[HTML / JSON / Markdown Report Generator]
    end
```

---

## 2. Core Architectural Subsystems

### 2.1 Repository Ingestion & Workspace Isolation
- **Zip Extraction Protection:** Protects against Zip-Slip path traversal using canonical boundary checks `os.path.realpath(target).startswith(realpath(root))`.
- **Zip-Bomb Limits:** Enforces a maximum extracted payload size (50MB) and file counts (5000 files).
- **Zero Host Execution:** Uploaded files are strictly parsed via static AST and regex lexers; no untrusted code is executed during analysis.

### 2.2 Structural Understanding & Interprocedural Call Graph
1. **Python AST Visitor (`ast.NodeVisitor`):**
   - Extracts top-level and nested classes, methods, decorators, and function signatures.
   - Extracts import statements (`import foo`, `from bar import baz`).
   - Extracts assignments and variable bindings to track object instances (e.g. `user_service = UserService()`).
   - Extracts function calls, caller objects, and arguments.
2. **Import Resolver (`ImportResolver`):**
   - Resolves relative imports (`.services`), absolute root packages (`backend.services`), and sub-modules.
3. **Call Graph Builder (`CallGraphBuilder`):**
   - Links caller functions to callee functions across multiple source files.
   - Categorizes edges as `statically_verified` (direct match via resolved imports) or `inferred` (heuristic single unique name match).

### 2.3 Flagship Cross-File Vulnerability Chain Engine (`TaintEngine`)
The flagship differentiator traces how user-controlled input travels from web entry points across application layers to reach critical sinks.

```mermaid
sequenceDiagram
    participant Client as Client Browser
    participant Route as routes.py (API Controller)
    participant Service as services.py (Service Layer)
    participant DB as database.py (SQL Sink)

    Client->>Route: GET /api/users/search?q=userInput
    Note over Route: Untrusted Source: q parameter accepted without validation
    Route->>Service: user_service.search_users(query_string)
    Note over Service: Interprocedural Flow: forwards parameter to DB layer
    Service->>DB: db.execute_raw_search(search_term)
    Note over DB: Dangerous Sink: raw f-string concatenation inside cursor.execute()
    DB-->>Client: Potential SQL Injection Vulnerability Triggered
```

### 2.4 Code Slop Intelligence Engine
Computes a transparent Code Slop score from 0–100 using documented deductions:
- Duplicate logic blocks across files (-12.5 pts each)
- Dead / uncalled functions (-10 pts each)
- Unused imports (-5 pts each)
- Excessive cyclomatic complexity and deep nesting (-5 pts each)

### 2.5 Safe Auto-Fix Remediation Lab
1. **Targeted Patch Synthesis:** Generates evidence-backed syntax replacements (e.g. replacing string concatenation in SQL queries with parameterized `?` placeholders).
2. **Unified Diff Computation:** Generates unified diffs using Python's `difflib`.
3. **Explicit User Approval:** Requires affirmative user consent before modifying files.
4. **Isolated Application & Backup:** Writes changes and creates `.codesentinel_backup`.
5. **Static Verification:** Re-runs the security scanner against the modified file to verify the finding is resolved.
6. **Rollback:** Instant restoration from `.codesentinel_backup` if needed.

---

## 3. Technology Stack

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide React, Monaco Editor (`@monaco-editor/react`).
- **Backend:** Python 3.10+, FastAPI, Pydantic v2, SQLAlchemy, SQLite (production ready for PostgreSQL).
- **Security & Linters:** AST engine, Gitleaks-pattern secret scanner, limited built-in dependency advisory catalog, and optional Semgrep & Bandit CLI integration.
- **Reporting:** Standalone responsive HTML reports, JSON findings, GitHub Markdown summaries.
