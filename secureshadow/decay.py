"""
SECURESHADOW - Protection Decay Calculator
Quantifies how much security protection has eroded and explains the specific causes.
"""

from datetime import datetime
from typing import Dict, List, Any
from .models import SecurityProperty
from .drift import ChangeEvent


class DecayContributor:
    """
    Identifies a single contributing factor to security decay, linking
    a change event to a broken assumption and its quantified impact percentage.
    """
    def __init__(
        self,
        assumption_id: str,
        assumption_desc: str,
        change_desc: str,
        impact_percent: float,
    ):
        self.assumption_id = assumption_id
        self.assumption_desc = assumption_desc
        self.change_desc = change_desc
        self.impact_percent = impact_percent

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assumption_id": self.assumption_id,
            "assumption_desc": self.assumption_desc,
            "change_desc": self.change_desc,
            "impact_percent": self.impact_percent,
        }

    def __repr__(self) -> str:
        return f"Contributor({self.assumption_id}: -{self.impact_percent:.1f}%)"


class DecayResult:
    """
    Comprehensive record of a protection decay calculation for a security property.
    """
    def __init__(self, property_id: str, property_desc: str):
        self.property_id = property_id
        self.property_desc = property_desc
        self.baseline_protection = 100.0
        self.current_protection = 100.0
        self.decay_percent = 0.0
        self.contributors: List[DecayContributor] = []
        self.broken_assumptions: List[str] = []
        self.timestamp = datetime.now()

    def add_contributor(self, contributor: DecayContributor) -> None:
        """Add a decay contributor and recalculate current protection."""
        self.contributors.append(contributor)
        total_impact = sum(c.impact_percent for c in self.contributors)
        self.current_protection = max(0.0, self.baseline_protection - total_impact)
        self.decay_percent = self.baseline_protection - self.current_protection

    def summary(self) -> str:
        """Generate a human-readable text summary of the decay calculation."""
        lines = [
            f"Security Property: {self.property_desc}",
            f"Baseline Protection: {self.baseline_protection:.0f}%",
            f"Current Protection:  {self.current_protection:.0f}%",
            f"Protection Decay:    {self.decay_percent:.0f}%",
            "",
        ]
        if self.contributors:
            lines.append("Contributors:")
            for c in self.contributors:
                lines.append(f"  - {c.change_desc}")
                lines.append(f"    Broken assumption: {c.assumption_desc}")
                lines.append(f"    Impact: -{c.impact_percent:.1f}%")
                lines.append("")
        else:
            lines.append("No decay contributors. Protection is intact.")
        return "\n".join(lines)

    def get_health_label(self) -> str:
        """Return a categorical health label based on current protection percentage."""
        if self.current_protection >= 90:
            return "HEALTHY"
        elif self.current_protection >= 70:
            return "DEGRADED"
        elif self.current_protection >= 40:
            return "AT RISK"
        else:
            return "CRITICAL"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "property_id": self.property_id,
            "property_desc": self.property_desc,
            "baseline_protection": self.baseline_protection,
            "current_protection": self.current_protection,
            "decay_percent": self.decay_percent,
            "health_label": self.get_health_label(),
            "contributors": [c.to_dict() for c in self.contributors],
            "broken_assumptions": list(self.broken_assumptions),
            "timestamp": self.timestamp.isoformat(),
        }


class DecayCalculator:
    """
    Computes deterministic decay score based on broken assumptions,
    change types, and property severity multipliers.
    """

    IMPACT_WEIGHTS = {
        "new_communication_path": 25.0,
        "new_asset": 10.0,
        "removed_control": 30.0,
        "removed_path": 5.0,
        "new_relationship": 8.0,
        "default": 15.0,
    }

    SEVERITY_MULTIPLIERS = {
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.5,
    }

    def calculate(
        self,
        security_property: SecurityProperty,
        analyzed_changes: List[ChangeEvent],
    ) -> DecayResult:
        """
        Calculate the decay score for a security property given analyzed changes.
        """
        result = DecayResult(
            property_id=security_property.property_id,
            property_desc=security_property.description,
        )

        severity_mult = self.SEVERITY_MULTIPLIERS.get(
            security_property.severity, 1.0
        )

        property_assumption_ids = [a.assumption_id for a in security_property.assumptions]

        for change in analyzed_changes:
            if change.potentially_breaks_assumptions:
                affected_asm_id = getattr(change, "affected_assumption_id", None)
                if affected_asm_id in property_assumption_ids:
                    base_impact = self.IMPACT_WEIGHTS.get(
                        change.change_type,
                        self.IMPACT_WEIGHTS["default"]
                    )
                    weighted_impact = min(base_impact * severity_mult, 50.0)

                    contributor = DecayContributor(
                        assumption_id=affected_asm_id,
                        assumption_desc=getattr(change, "affected_assumption_desc", "Unknown assumption"),
                        change_desc=change.description,
                        impact_percent=weighted_impact,
                    )
                    result.add_contributor(contributor)
                    if affected_asm_id not in result.broken_assumptions:
                        result.broken_assumptions.append(affected_asm_id)

        # Also account for any directly invalidated assumptions
        for assumption in security_property.assumptions:
            if not assumption.is_valid:
                if assumption.assumption_id not in result.broken_assumptions:
                    contributor = DecayContributor(
                        assumption_id=assumption.assumption_id,
                        assumption_desc=assumption.description,
                        change_desc="Assumption manually invalidated",
                        impact_percent=min(15.0 * severity_mult, 50.0),
                    )
                    result.add_contributor(contributor)
                    result.broken_assumptions.append(assumption.assumption_id)

        return result
