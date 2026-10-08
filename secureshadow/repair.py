"""
SECURESHADOW - Minimum-Cost Repair Engine
Generates and ranks candidate repairs to select the lowest-cost intervention
that restores required security properties above an effectiveness threshold.
"""

from typing import Dict, List, Optional, Any
from .decay import DecayResult
from .drift import ChangeEvent
from .graph import SecurityGraph


class RepairCandidate:
    """
    Represents a specific architectural, policy, or operational remediation action.
    """
    def __init__(self, repair_id: str, description: str, action_type: str):
        self.repair_id = repair_id
        self.description = description
        self.action_type = action_type  # "remove_path", "add_control", "restrict_access", "add_encryption", "accept_risk"

        # Cost factors (0 - 100 scale, lower is better/cheaper)
        self.implementation_cost: float = 0.0
        self.business_impact: float = 0.0
        self.operational_risk: float = 0.0
        self.implementation_time: float = 0.0

        # Effectiveness (0 - 100 scale, higher is better)
        self.security_improvement: float = 0.0
        self.restored_assumptions: List[str] = []
        self.target_entity: Optional[str] = None

        # Derived metrics
        self.total_cost: float = 0.0
        self.cost_effectiveness_ratio: float = 0.0

    def calculate_total_cost(self) -> float:
        """
        Total cost is a weighted linear combination of all cost dimensions.
        """
        weights = {
            "implementation_cost": 0.35,
            "business_impact": 0.30,
            "operational_risk": 0.25,
            "implementation_time": 0.10,
        }
        self.total_cost = (
            self.implementation_cost * weights["implementation_cost"] +
            self.business_impact * weights["business_impact"] +
            self.operational_risk * weights["operational_risk"] +
            self.implementation_time * weights["implementation_time"]
        )

        if self.total_cost > 0:
            self.cost_effectiveness_ratio = self.security_improvement / self.total_cost
        else:
            self.cost_effectiveness_ratio = float("inf")

        return self.total_cost

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repair_id": self.repair_id,
            "description": self.description,
            "action_type": self.action_type,
            "implementation_cost": self.implementation_cost,
            "business_impact": self.business_impact,
            "operational_risk": self.operational_risk,
            "implementation_time": self.implementation_time,
            "total_cost": round(self.total_cost, 2),
            "security_improvement": self.security_improvement,
            "cost_effectiveness_ratio": round(self.cost_effectiveness_ratio, 2),
            "restored_assumptions": list(self.restored_assumptions),
            "target_entity": self.target_entity,
        }

    def __repr__(self) -> str:
        return (
            f"Repair({self.repair_id}: {self.description[:40]}... "
            f"cost={self.total_cost:.1f}, improves={self.security_improvement:.0f}%)"
        )


class RepairOptimizer:
    """
    Evaluates decay results, generates candidate interventions, and identifies
    the minimum-cost remediation meeting a specified protection threshold.
    """

    def __init__(self):
        self.candidates: List[RepairCandidate] = []

    def generate_candidates(
        self,
        decay_result: DecayResult,
        analyzed_changes: List[ChangeEvent],
        current_graph: Optional[SecurityGraph] = None,
    ) -> List[RepairCandidate]:
        """
        Generate candidate repairs tailored to the specific changes and broken assumptions.
        """
        self.candidates = []
        counter = 1

        for change in analyzed_changes:
            if not change.potentially_breaks_assumptions:
                continue

            affected_asm_id = getattr(change, "affected_assumption_id", "unknown")

            if change.change_type == "new_communication_path":
                # Option 1: Remove/block the new path
                r1 = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Remove or block the new communication path: {change.description}",
                    action_type="remove_path",
                )
                r1.implementation_cost = 20.0
                r1.business_impact = 40.0
                r1.operational_risk = 10.0
                r1.implementation_time = 15.0
                r1.security_improvement = 100.0
                r1.restored_assumptions = [affected_asm_id]
                r1.target_entity = "->".join(change.affected_entities[:2])
                self.candidates.append(r1)
                counter += 1

                # Option 2: Add a security control on the path
                r2 = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description="Add a WAF/Firewall on the new path to protect the traffic",
                    action_type="add_control",
                )
                r2.implementation_cost = 40.0
                r2.business_impact = 15.0
                r2.operational_risk = 20.0
                r2.implementation_time = 40.0
                r2.security_improvement = 95.0
                r2.restored_assumptions = [affected_asm_id]
                r2.target_entity = "->".join(change.affected_entities[:2])
                self.candidates.append(r2)
                counter += 1

                # Option 3: Restrict access / least privilege
                r3 = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description="Restrict the new service to only access necessary data (least privilege)",
                    action_type="restrict_access",
                )
                r3.implementation_cost = 30.0
                r3.business_impact = 25.0
                r3.operational_risk = 15.0
                r3.implementation_time = 25.0
                r3.security_improvement = 80.0
                r3.restored_assumptions = [affected_asm_id]
                r3.target_entity = "->".join(change.affected_entities[:2])
                self.candidates.append(r3)
                counter += 1

                # Option 4: Add encryption
                r4 = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description="Add end-to-end encryption on the new communication path",
                    action_type="add_encryption",
                )
                r4.implementation_cost = 25.0
                r4.business_impact = 10.0
                r4.operational_risk = 10.0
                r4.implementation_time = 20.0
                r4.security_improvement = 45.0
                r4.restored_assumptions = []
                r4.target_entity = "->".join(change.affected_entities[:2])
                self.candidates.append(r4)
                counter += 1

            elif change.change_type == "new_asset":
                r = RepairCandidate(
                    repair_id=f"REPAIR-{counter:03d}",
                    description=f"Conduct security review and apply controls for new asset: {change.description}",
                    action_type="add_control",
                )
                r.implementation_cost = 50.0
                r.business_impact = 20.0
                r.operational_risk = 15.0
                r.implementation_time = 50.0
                r.security_improvement = 85.0
                r.restored_assumptions = [affected_asm_id]
                r.target_entity = change.affected_entities[0] if change.affected_entities else None
                self.candidates.append(r)
                counter += 1

        # Always include baseline "accept risk" candidate
        r_accept = RepairCandidate(
            repair_id=f"REPAIR-{counter:03d}",
            description="Accept the risk and do nothing (document the exception)",
            action_type="accept_risk",
        )
        r_accept.implementation_cost = 0.0
        r_accept.business_impact = 0.0
        r_accept.operational_risk = 80.0
        r_accept.implementation_time = 0.0
        r_accept.security_improvement = 0.0
        r_accept.restored_assumptions = []
        self.candidates.append(r_accept)

        for candidate in self.candidates:
            candidate.calculate_total_cost()

        return self.candidates

    def find_minimum_cost_repair(
        self,
        min_security_improvement: float = 50.0,
    ) -> Optional[RepairCandidate]:
        """
        Find the candidate with the lowest total cost that satisfies the minimum improvement threshold.
        """
        effective_candidates = [
            c for c in self.candidates
            if c.security_improvement >= min_security_improvement
        ]

        if not effective_candidates:
            return None

        effective_candidates.sort(
            key=lambda c: (c.total_cost, -c.security_improvement)
        )
        return effective_candidates[0]

    def rank_all_candidates(self) -> List[RepairCandidate]:
        """
        Return all generated candidates ordered by total cost (ascending) and improvement (descending).
        """
        return sorted(
            self.candidates,
            key=lambda c: (c.total_cost, -c.security_improvement),
        )
