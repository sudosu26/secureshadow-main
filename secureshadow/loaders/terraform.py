"""
SECURESHADOW - Terraform Show -JSON Loader
Parses standard `terraform show -json` (plan or state) into typed Asset,
SecurityControl, and CommunicationPath objects, constructing a SecurityGraph.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple

from ..models import Asset, SecurityControl, Assumption, SecurityProperty, CommunicationPath
from ..graph import SecurityGraph


class TerraformLoader:
    """
    Ingests and parses Terraform JSON schemas (plan or state representation).
    Translates cloud resources and ingress/egress relationships into graph entities.
    """

    COMPUTE_TYPES = {
        "aws_instance": "compute",
        "aws_ecs_service": "service",
        "aws_lambda_function": "serverless",
        "google_compute_instance": "compute",
        "azurerm_linux_virtual_machine": "compute",
        "azurerm_virtual_machine": "compute",
    }

    DATABASE_TYPES = {
        "aws_db_instance": "database",
        "aws_rds_cluster": "database",
        "aws_dynamodb_table": "database",
        "aws_s3_bucket": "storage",
        "google_sql_database_instance": "database",
        "azurerm_mssql_database": "database",
        "azurerm_storage_account": "storage",
    }

    GATEWAY_TYPES = {
        "aws_lb": "load_balancer",
        "aws_alb": "load_balancer",
        "aws_elb": "load_balancer",
        "aws_api_gateway_rest_api": "api_gateway",
        "aws_apigatewayv2_api": "api_gateway",
    }

    FIREWALL_TYPES = {
        "aws_security_group": "firewall",
        "google_compute_firewall": "firewall",
        "azurerm_network_security_group": "firewall",
    }

    WAF_TYPES = {
        "aws_wafv2_web_acl": "waf",
        "aws_waf_web_acl": "waf",
    }

    def __init__(self):
        pass

    def _load_dict(self, input_data: Union[dict, str, Path]) -> dict:
        """Helper to accept dict, JSON string, or file path."""
        if isinstance(input_data, dict):
            return input_data
        if isinstance(input_data, (str, Path)):
            p = Path(input_data)
            if p.exists() and p.is_file():
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                return json.loads(str(input_data))
        raise ValueError(f"Unsupported input type: {type(input_data)}")

    def _collect_module_resources(self, module_data: dict) -> List[dict]:
        """Recursively gather all resources from root and child modules."""
        resources = list(module_data.get("resources", []))
        for child in module_data.get("child_modules", []):
            resources.extend(self._collect_module_resources(child))
        return resources

    def extract_raw_resources(self, tf_json: dict) -> List[dict]:
        """Extract resource list from plan or state format."""
        if "values" in tf_json and "root_module" in tf_json["values"]:
            return self._collect_module_resources(tf_json["values"]["root_module"])
        elif "planned_values" in tf_json and "root_module" in tf_json["planned_values"]:
            return self._collect_module_resources(tf_json["planned_values"]["root_module"])
        elif "resource_changes" in tf_json:
            # Plan format with resource changes
            res_list = []
            for rc in tf_json.get("resource_changes", []):
                vals = rc.get("change", {}).get("after") or rc.get("change", {}).get("before") or {}
                res_list.append({
                    "address": rc.get("address"),
                    "type": rc.get("type"),
                    "name": rc.get("name"),
                    "values": vals,
                })
            return res_list
        return []

    def build_graph_from_json(
        self,
        tf_input: Union[dict, str, Path],
    ) -> Tuple[SecurityGraph, List[Assumption], List[SecurityProperty]]:
        """
        Parses Terraform JSON and constructs the SecurityGraph, along with inferred
        assumptions and security properties.
        """
        data = self._load_dict(tf_input)
        raw_resources = self.extract_raw_resources(data)

        graph = SecurityGraph()
        assets: Dict[str, Asset] = {}
        controls: Dict[str, SecurityControl] = {}
        sg_to_assets: Dict[str, List[Asset]] = {}
        sg_rules: List[dict] = []
        sg_map: Dict[str, SecurityControl] = {}
        waf_controls: List[SecurityControl] = []
        lb_assets: List[Asset] = []
        db_assets: List[Asset] = []

        # 1. First pass: Instantiate Assets and Controls
        for res in raw_resources:
            res_type = res.get("type", "")
            res_name = res.get("name", "")
            res_addr = res.get("address", f"{res_type}.{res_name}")
            vals = res.get("values", {}) or {}

            # Check WAF
            if res_type in self.WAF_TYPES:
                ctrl_id = vals.get("id") or res_addr
                ctrl_name = vals.get("name") or res_name or "Web Application Firewall"
                waf_ctrl = SecurityControl(ctrl_id, ctrl_name, "waf", status="active")
                controls[ctrl_id] = waf_ctrl
                waf_controls.append(waf_ctrl)
                graph.add_control(waf_ctrl)
                continue

            # Check Firewall / Security Groups
            if res_type in self.FIREWALL_TYPES:
                ctrl_id = vals.get("id") or res_addr
                ctrl_name = vals.get("name") or res_name or f"Security Group ({res_name})"
                sg_ctrl = SecurityControl(ctrl_id, ctrl_name, "firewall", status="active")
                controls[ctrl_id] = sg_ctrl
                sg_map[ctrl_id] = sg_ctrl
                sg_map[res_addr] = sg_ctrl
                graph.add_control(sg_ctrl)

                # Collect inline ingress rules if present
                for ing in vals.get("ingress", []):
                    sg_rules.append({
                        "target_sg": ctrl_id,
                        "from_port": ing.get("from_port", 0),
                        "to_port": ing.get("to_port", 0),
                        "protocol": ing.get("protocol", "TCP"),
                        "cidr_blocks": ing.get("cidr_blocks", []),
                        "security_groups": ing.get("security_groups", []),
                    })
                continue

            # Check standalone security group rule
            if res_type == "aws_security_group_rule":
                rule_type = vals.get("type", "ingress")
                if rule_type == "ingress":
                    sg_rules.append({
                        "target_sg": vals.get("security_group_id") or vals.get("security_group"),
                        "from_port": vals.get("from_port", 0),
                        "to_port": vals.get("to_port", 0),
                        "protocol": vals.get("protocol", "TCP"),
                        "cidr_blocks": vals.get("cidr_blocks", []),
                        "source_sg": vals.get("source_security_group_id"),
                        "security_groups": [vals.get("source_security_group_id")] if vals.get("source_security_group_id") else [],
                    })
                continue

            # Check Compute
            if res_type in self.COMPUTE_TYPES:
                asset_id = vals.get("id") or res_addr
                name = (vals.get("tags") or {}).get("Name") or res_name
                ip = vals.get("private_ip") or vals.get("public_ip")
                asset = Asset(asset_id, name, self.COMPUTE_TYPES[res_type], ip)
                assets[asset_id] = asset
                graph.add_asset(asset)

                # Link associated security groups
                sgs = vals.get("vpc_security_group_ids") or vals.get("security_groups") or []
                for sg_id in sgs:
                    sg_to_assets.setdefault(sg_id, []).append(asset)
                continue

            # Check Database / Storage
            if res_type in self.DATABASE_TYPES:
                asset_id = vals.get("id") or res_addr
                name = vals.get("identifier") or (vals.get("tags") or {}).get("Name") or res_name
                ip = vals.get("endpoint") or vals.get("address")
                asset = Asset(asset_id, name, self.DATABASE_TYPES[res_type], ip)
                assets[asset_id] = asset
                db_assets.append(asset)
                graph.add_asset(asset)

                sgs = vals.get("vpc_security_group_ids") or []
                for sg_id in sgs:
                    sg_to_assets.setdefault(sg_id, []).append(asset)
                continue

            # Check Gateway / Load Balancer
            if res_type in self.GATEWAY_TYPES:
                asset_id = vals.get("id") or res_addr
                name = vals.get("name") or res_name
                ip = vals.get("dns_name")
                asset = Asset(asset_id, name, self.GATEWAY_TYPES[res_type], ip)
                assets[asset_id] = asset
                lb_assets.append(asset)
                graph.add_asset(asset)

                sgs = vals.get("security_groups") or []
                for sg_id in sgs:
                    sg_to_assets.setdefault(sg_id, []).append(asset)
                continue

        # 2. Link Security Groups to Assets they protect
        for sg_id, protected_assets in sg_to_assets.items():
            ctrl = sg_map.get(sg_id)
            if ctrl:
                for asset in protected_assets:
                    ctrl.add_protected_asset(asset)
                    graph.graph.add_edge(
                        ctrl.control_id,
                        asset.asset_id,
                        relationship="PROTECTS",
                        label="PROTECTS",
                    )

        # 3. Associate WAF with Public Gateways / Load Balancers
        for waf in waf_controls:
            for lb in lb_assets:
                waf.add_protected_asset(lb)
                graph.graph.add_edge(
                    waf.control_id,
                    lb.asset_id,
                    relationship="PROTECTS",
                    label="PROTECTS",
                )

        # 4. Infer Communication Paths from Ingress Rules
        internet_asset = None
        path_idx = 1

        for rule in sg_rules:
            target_sg = rule.get("target_sg")
            target_assets = sg_to_assets.get(target_sg, [])
            protocol = str(rule.get("protocol", "TCP")).upper()

            # External Internet Ingress (0.0.0.0/0)
            if "0.0.0.0/0" in rule.get("cidr_blocks", []):
                if internet_asset is None:
                    internet_asset = Asset("asset-ext", "Public Internet", "external")
                    graph.add_asset(internet_asset)

                for tgt in target_assets:
                    p = CommunicationPath(f"path-tf-{path_idx:03d}", internet_asset, tgt, protocol)
                    path_idx += 1
                    # If target is protected by WAF (e.g. ALB with WAF), path passes through WAF
                    for waf in waf_controls:
                        if tgt in waf.protects:
                            p.add_control(waf)
                    # And passes through SG
                    sg_ctrl = sg_map.get(target_sg)
                    if sg_ctrl:
                        p.add_control(sg_ctrl)
                    graph.add_path(p)

            # Ingress from other Security Groups
            source_sgs = rule.get("security_groups", [])
            for src_sg in source_sgs:
                source_assets = sg_to_assets.get(src_sg, [])
                for src_asset in source_assets:
                    for tgt_asset in target_assets:
                        if src_asset.asset_id != tgt_asset.asset_id:
                            p = CommunicationPath(
                                f"path-tf-{path_idx:03d}",
                                src_asset,
                                tgt_asset,
                                protocol,
                            )
                            path_idx += 1
                            sg_ctrl = sg_map.get(target_sg)
                            if sg_ctrl:
                                p.add_control(sg_ctrl)
                            graph.add_path(p)

        # 5. Synthesize Baseline Security Properties and Assumptions
        assumptions: List[Assumption] = []
        properties: List[SecurityProperty] = []

        if waf_controls and lb_assets:
            waf = waf_controls[0]
            asm = Assumption(
                "asm-tf-001",
                f"All public external ingress must pass through {waf.name}",
                waf.control_id,
            )
            assumptions.append(asm)
            graph.add_assumption(asm)

            prop = SecurityProperty(
                "prop-tf-001",
                "Perimeter protection: external ingress inspected by WAF",
                waf.control_id,
                severity="critical",
            )
            prop.add_assumption(asm)
            properties.append(prop)

        # If we have databases, define confidentiality property
        if db_assets:
            for idx, db in enumerate(db_assets, 1):
                ctrl_id = waf_controls[0].control_id if waf_controls else (
                    list(controls.keys())[0] if controls else "ctrl-default"
                )
                db_asm = Assumption(
                    f"asm-tf-db-{idx:03d}",
                    f"Database '{db.name}' only accessible via authorized application tiers, not unreviewed services",
                    ctrl_id,
                )
                assumptions.append(db_asm)
                graph.add_assumption(db_asm)

                db_prop = SecurityProperty(
                    f"prop-tf-db-{idx:03d}",
                    f"Confidentiality & access integrity for {db.name}",
                    ctrl_id,
                    severity="critical",
                )
                db_prop.add_assumption(db_asm)
                if assumptions:
                    db_prop.add_assumption(assumptions[0])
                properties.append(db_prop)

        return graph, assumptions, properties
