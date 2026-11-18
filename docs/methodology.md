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
- **Reachability Multiplier:** Findings correlated with a statically traced source-to-sink chain are elevated to Critical severity. The chain confidence values are fixed heuristic scores, not calibrated probabilities or exploit verification.

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
- Cross-file taint chains require an identified source parameter to reach a sink expression through supported call arguments and Python local assignments. Positional and named calls, local aliases, tuple bindings, loop targets, and conservative branch joins are modeled; unsupported control flow and dynamic dispatch can still affect results.
- Chain graphs contain source, intermediate, and sink evidence only. They do not synthesize a validation boundary or claim that validation is absent without analyzing it.
- Current interprocedural taint propagation is Python-focused. JavaScript and TypeScript parsing is structural and does not provide equivalent cross-file taint guarantees.
- Shell-command analysis recognizes direct `shlex.quote(...)` expressions and keeps any raw use of the same tainted value in a mixed command expression in scope. This is not a general sanitizer framework; SQL and path sanitizers are not inferred from arbitrary helper names.
- The source, sink, and call models are syntax-based. Dynamic dispatch, complex expressions, implicit framework bindings, aliases through unsupported constructs, and some branch correlations can be missed; conservative branch joins can also retain taint after safe overwrites. JavaScript/TypeScript and Java are not supported for cross-file taint analysis.

## 4. Cross-File Chain Confidence
Chain confidence is assigned from a small set of fixed heuristic levels based on source identification and call-binding evidence. It is not calibrated, should not be read as a probability that an exploit will succeed, and is not a substitute for code review or runtime testing. The engine is conservative across supported conditional assignments, which can retain taint when every branch overwrites a value with safe data and may therefore produce false positives.
