"""
SECURESHADOW - Infrastructure Loaders
Ingests real Infrastructure as Code (IaC) and cloud configurations.
"""

from .terraform import TerraformLoader

__all__ = ["TerraformLoader"]
