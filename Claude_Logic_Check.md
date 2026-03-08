# CLAUDE_LOGIC_CHECK.md

Purpose:
Before implementing, modifying, or debugging DepGuard logic, Claude must read this file and verify that all reasoning, math, and AI usage follow these rules.

---

## 1. Core Rule

DepGuard is NOT a chatbot.

It is a deterministic security analysis pipeline with AI-assisted reasoning.

AI must only reason about real evidence gathered by deterministic agents.

Never invent:
- vulnerabilities
- file paths
- dependency usage
- scoring values
- code behavior

If evidence does not exist, the system must say so.

---

## 2. Pipeline Order (Must Not Change)

DepGuard must follow this order:

Scan Agent
→ Dependency/Vulnerability Agent (Backboard — normalizes OSV data, produces investigation_focus)
→ Code Agent
→ Context Agent
→ Exploitability Analysis
→ Blast Radius Estimate
→ Confidence Scoring
→ Risk Agent (Backboard reasoning)
→ Fix Agent
→ Memory Writeback

Confidence scoring must always happen AFTER blast radius estimation.

---

## 3. Logic Validation Requirements

Before implementing or modifying code, Claude must verify:

- logic is internally consistent
- no contradictory conditions exist
- all scoring rules produce deterministic outputs
- edge cases are handled

Check scenarios like:

- vulnerable package imported but vulnerable function not used
- vulnerable function used in sensitive module
- vulnerable function used in non-sensitive module
- multiple usage locations
- no usage found
- fallback AI behavior

Claude must simulate at least 3 scenarios mentally before finalizing logic.

---

## 4. Confidence Score Rules

Confidence represents:

"Confidence in the overall exploitability and impact assessment."

Confidence must be derived from evidence signals such as:

- dependency match
- import detection
- vulnerable function detection
- sensitive context
- blast radius clarity
- fallback behavior

Confidence must always output:

confidence_percent: 0–100  
confidence: low | medium | high

Mapping must be deterministic:

0–39  → low  
40–69 → medium  
70–100 → high

Confidence must NEVER exceed the range 0–100.

---

## 5. Blast Radius Rules

Blast radius estimates impact scope if the vulnerability is real.

Allowed outputs:

isolated  
module  
subsystem

Blast radius should be determined using:

- number of affected files
- number of modules
- sensitive context tags (auth, api, middleware, etc.)
- distribution of usage locations

Blast radius describes scope clarity, not automatically higher risk.

---

## 6. AI Safety Rules

When using Backboard / LLM reasoning:

The AI must always receive:

- CVE description
- dependency name + version
- usage locations
- relevant code snippets
- exploitability evidence
- blast radius context

AI must NEVER guess missing information.

If evidence is insufficient, the system must output:

"Evidence insufficient to confirm exploitability."

---

## 7. Demo Safety Rule

For the demo:

Always prefer false positives over false negatives.

If confidence is low or evidence is weak, the system should mark the issue as:

"potentially vulnerable"

instead of declaring the system safe.

---

## 8. Self-Check Before Finalizing

Before finishing a change Claude must:

1. Verify scoring math
2. Check edge cases
3. Confirm pipeline order
4. Ensure AI prompts are grounded in real evidence
5. Confirm API outputs match schemas

If any rule above is violated, Claude must correct the implementation.