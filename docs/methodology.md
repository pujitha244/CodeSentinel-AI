# CodeSentinel AI — Audit Scoring & Analytics Methodology

## 1. Principles of Transparent Scoring

Traditional automated code auditing tools frequently output arbitrary numbers or opaque percentages. CodeSentinel AI enforces a 100% transparent scoring methodology based on verified evidence, reachability, and concrete AST metrics.

---

## 2. Mathematical Scoring Formulas

### 2.1 Security Posture Score (0–100)
Measures the vulnerability density and exposure of the project.
```text
Security Penalty = (Critical * 30.0) + (High * 15.0) + (Medium * 6.0) + (Low * 2.0)
Security Score = max(0.0, min(100.0, 100.0 - Security Penalty))
```
- **Reachability Multiplier:** Findings correlated with an active cross-file vulnerability chain are elevated to Critical severity with verified confidence (≥ 0.85).

### 2.2 Code Slop Score (0–100)
Quantifies technical debt, duplicate blocks, and maintainability friction. Lower is cleaner; higher represents excessive slop.
```text
Slop Penalty = min(25.0, Duplicates * 12.5)
             + min(30.0, DeadFunctions * 10.0)
             + min(25.0, UnusedImports * 5.0)
             + min(20.0, ComplexityHotspots * 5.0)

Code Slop Score = min(100.0, Slop Penalty)
```
- **Clean:** 0–20 pts
- **Moderate Slop:** 21–50 pts
- **High Slop:** 51–100 pts

### 2.3 Implementation Completeness Score (0–100)
Evaluates missing business logic, unhandled edge cases, and deferred engineering tasks.
```text
Completeness Penalty = (LooseEnds * 4.0) + (LogicGaps * 5.0)
Completeness Score = max(0.0, min(100.0, 100.0 - Completeness Penalty))
```

### 2.4 Overall Engineering Health Score (0–100)
Synthesizes security, quality, and completeness using a weighted composite formula:
```text
Engineering Health = (0.40 * Security Score)
                   + (0.30 * Quality Score)
                   + (0.30 * Completeness Score)
```

---

## 3. Disclaimers & Operational Boundaries
- The platform evaluates static code properties and does not guarantee formal verification or mathematical absence of all security flaws.
- Inferred relationships are clearly distinguished from statically verified AST bindings.
