# SECURESHADOW — INVENTION LOG

## 1. Problem Identified
Security operations monitor whether security controls are configured correctly. They do not detect a second failure mode: a control remains correctly configured, but the environment has changed such that the control no longer provides its intended protection. Traditional tools report "Healthy" while protection has silently degraded.

**Date identified:** Documented August 2026

## 2. Technical Solution
A system that:
- Models each security control's intended security property, assumptions, and dependencies.
- Continuously compares the actual architecture against a baseline.
- Detects architectural drift that violates assumptions.
- Validates degradation in a virtual "Security Twin" (simulated environment).
- Produces a deterministic, explainable Protection Decay Score.
- Recommends minimum-cost repairs to restore the security property.

## 3. Novel Mechanisms

### a. Security Property Model (SPM)
Every control is linked to a formal security property, not just a configuration check. The property includes explicit assumptions and dependencies.

### b. Assumption-Aware Drift Detection
Changes are not merely logged; they are checked against security assumptions to determine if protection has been invalidated.

### c. Protection Decay Score
A deterministic, mathematical score derived from broken assumptions, change types, and severity weighting. Not a black-box risk score. Fully explainable with attribution to specific changes.

### d. Minimum-Cost Repair Optimization
Multiple repair candidates are generated, each with cost factors (implementation, business impact, operational risk, time). The system selects the lowest-cost repair that restores the security property above a threshold.

### e. Security Twin (Concept)
The system can validate changes in a simulated "shadow" environment before production impact. In this MVP, the twin is a graph-based simulation.

## 4. Architecture Overview
Control → SecurityProperty → Assumptions → Dependency Graph
→ Baseline Snapshot → Continuous Monitoring
→ Drift Detection → Assumption Violation Check
→ Protection Decay Score → Attribution
→ Repair Candidate Generation → Minimum-Cost Selection

## 5. Alternatives Considered
- Simple compliance scanning (does not detect silent drift)
- Risk scoring based on CVEs/vulnerabilities (does not model assumptions)
- Manual architecture review (does not scale, not continuous)
- ML-based anomaly detection (black-box, not explainable for security decisions)

## 6. Key Technical Decisions
- MVP uses in-memory NetworkX graph, not persistent database — sufficient for demonstration
- Assumption triggers are rule-based for transparency, not ML
- Repair costs are weighted heuristics for demo, replaceable with real data
- Demo scenario is synthetic (no real infrastructure touched)

## 7. Experimental Results
The MVP demonstrates a complete pipeline on a synthetic scenario:
- Baseline: WAF protects API → Database
- Drift: New AI service connects directly to Database (bypasses WAF)
- Detection: New communication path and asset detected
- Decay: 37.5% protection loss (25% base × 1.5 critical severity)
- Repair: Least-privilege access restriction recommended (cost 24.3, 80% improvement)

The WAF remains "green" in traditional scanners. SECURESHADOW correctly identifies the silent degradation.

## 8. Dates
- Concept first documented: August 2026
- MVP prototype completed: August 2026
- File created: dashboard.py, data_model.py, graph_engine.py, drift_detection.py, decay_calculator.py, repair_engine.py

## 9. Contributors
- Arijit Dey 

## 10. Open Questions
- Real-world assumption inference from IaC/configs?
- Scaling to thousands of nodes?
- Integrating with cloud APIs for live change detection?
- Patentability assessment by a qualified patent professional?

## 11. Disclosure Warning
⚠️ This document records the invention. Do not publicly disclose the detailed mechanisms (decay formula, repair algorithm, assumption mapping) before consulting a patent professional. Public disclosure before filing may affect patent rights.

## 12. Next Steps (IP)
- Consult a patent attorney/agent for prior art search and patentability opinion.
- Consider filing a provisional patent application before any public presentation.
- Keep all design documents and this log as evidence of invention date.