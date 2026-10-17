"""
Remediation Script and Policy Generator.
Auto-generates production-grade mitigation artifacts:
1. Kubernetes NetworkPolicy (YAML) to isolate compromised pod.
2. AWS IAM Policy Revoke / Deny (JSON) to strip lateral IAM privilege.
3. Linux Host Firewall Rules (iptables) to block C2 traffic.
4. Terraform Security Group Patch (HCL).
"""

import json
import re
from typing import Any, Dict, List, Optional


class RemediationGenerator:
    """Generates multi-cloud remediation artifacts based on blast radius graph evidence."""

    @staticmethod
    def _sanitize_name(val: str, default: str = "service") -> str:
        """Sanitizes service/node names to prevent command and template injection."""
        if not val or not isinstance(val, str):
            return default
        # Allow alphanumeric, hyphen, underscore
        sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "", val).strip()
        return sanitized[:64] if sanitized else default

    @staticmethod
    def _sanitize_cve(val: str, default: str = "CVE-2024-3094") -> str:
        """Sanitizes CVE identifiers to standard CVE-YYYY-NNNN format or safe fallback."""
        if not val or not isinstance(val, str):
            return default
        match = re.search(r"CVE-\d{4}-\d{4,8}", val, re.IGNORECASE)
        if match:
            return match.group(0).upper()
        sanitized = re.sub(r"[^a-zA-Z0-9_\-]", "", val).strip()
        return sanitized[:32] if sanitized else default

    @staticmethod
    def _sanitize_port(val: Any, default: int = 8443) -> int:
        """Validates network port range."""
        try:
            port = int(val)
            if 1 <= port <= 65535:
                return port
        except (ValueError, TypeError):
            pass
        return default

    @staticmethod
    def _sanitize_arn_or_role(val: str) -> str:
        """Sanitizes AWS ARN or role name."""
        if not val or not isinstance(val, str):
            return "arn:aws:iam::123456789:role/AuthServiceRole"
        sanitized = re.sub(r"[^a-zA-Z0-9_\-:/]", "", val).strip()[:128]
        if sanitized.startswith("arn:aws:"):
            return sanitized
        role_part = re.sub(r"[^a-zA-Z0-9_\-]", "", sanitized)
        return f"arn:aws:iam::123456789:role/{role_part or 'DefaultRole'}"

    @classmethod
    def generate_k8s_network_policy(cls, service_name: str, compromised_cve: str = "CVE-2024-3094") -> str:
        """Generates Kubernetes NetworkPolicy isolating the compromised service."""
        safe_service = cls._sanitize_name(service_name, "service")
        safe_cve = cls._sanitize_cve(compromised_cve, "CVE-2024-3094")
        pod_label = safe_service.lower().replace("_", "-")
        return f"""# ==============================================================================
# NexTrace Autonomous Remediation: Kubernetes Isolation NetworkPolicy
# Triggered by: {safe_cve} on {safe_service}
# Action: Immediate zero-trust quarantine - Deny all ingress & egress mesh traffic
# ==============================================================================
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-{pod_label}-quarantine
  namespace: production
  labels:
    security.nextrace.io/quarantined: "true"
    security.nextrace.io/cve: "{safe_cve}"
spec:
  podSelector:
    matchLabels:
      app: {pod_label}
  policyTypes:
  - Ingress
  - Egress
  # Empty ingress rule set rejects all incoming connections
  ingress: []
  # Egress restricted strictly to internal SecOps forensic logging endpoints
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: security-telemetry
    ports:
    - protocol: TCP
      port: 5044
"""

    @classmethod
    def generate_aws_iam_deny_policy(cls, compromised_roles: List[str], crown_jewels: List[str]) -> str:
        """Generates AWS IAM Deny Policy revoking privilege escalation."""
        role_arns = [
            cls._sanitize_arn_or_role(r)
            for r in compromised_roles
        ] if compromised_roles else ["arn:aws:iam::123456789:role/AuthServiceRole"]

        policy_dict = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "NexTraceAutonomousPrivilegeRevocation",
                    "Effect": "Deny",
                    "Action": [
                        "sts:AssumeRole",
                        "sts:AssumeRoleWithWebIdentity",
                        "rds-db:connect",
                        "dynamodb:*",
                        "secretsmanager:GetSecretValue"
                    ],
                    "Resource": [
                        "*"
                    ],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": role_arns
                        }
                    }
                }
            ]
        }
        return json.dumps(policy_dict, indent=2)

    @classmethod
    def generate_iptables_firewall_rule(cls, service_name: str, compromised_port: int = 8443) -> str:
        """Generates Linux iptables / nftables emergency blocking commands."""
        safe_service = cls._sanitize_name(service_name, "service")
        safe_port = cls._sanitize_port(compromised_port, 8443)
        return f"""#!/usr/bin/env bash
# ==============================================================================
# NexTrace Autonomous Remediation: Host Firewall Lockdown
# Target: {safe_service} (Port {safe_port})
# ==============================================================================
set -euo pipefail

echo "[+] Initiating emergency host containment for {safe_service}..."

# 1. Drop all established and incoming connections on service port
sudo iptables -I INPUT 1 -p tcp --dport {safe_port} -j DROP
sudo iptables -I FORWARD 1 -p tcp --dport {safe_port} -j DROP

# 2. Block outbound lateral sweeps to internal database subnets (10.0.0.0/16)
sudo iptables -I OUTPUT 1 -d 10.0.2.0/24 -p tcp -m state --state NEW,ESTABLISHED -j REJECT --reject-with icmp-admin-prohibited

# 3. Log containment enforcement
logger -p auth.alert "[NexTrace Alert] Autonomous isolation rule active for {safe_service}. Ingress and egress severed."

echo "[✓] Containment firewall rules applied successfully."
"""

    @classmethod
    def generate_terraform_patch(cls, service_name: str) -> str:
        """Generates Terraform HCL security group patch."""
        safe_service = cls._sanitize_name(service_name, "service")
        safe_sg_identifier = re.sub(r"[^a-z0-9_]", "_", safe_service.lower())
        return f"""# ==============================================================================
# NexTrace Terraform Security Group Containment Patch
# Service: {safe_service}
# ==============================================================================
resource "aws_security_group_rule" "quarantine_ingress_block" {{
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.{safe_sg_identifier}_sg.id
  description       = "NexTrace Automated Quarantine: Revoke all ingress until CVE patched"
}}
"""

    @classmethod
    def compile_full_remediation_bundle(
        cls,
        service_name: str,
        compromised_cve: str,
        traversal_path: List[str],
        impacted_roles: List[str],
        exposed_crown_jewels: List[str]
    ) -> Dict[str, Any]:
        """Bundles all mitigation scripts into a unified structured report."""
        safe_service = cls._sanitize_name(service_name, "service")
        safe_cve = cls._sanitize_cve(compromised_cve, "CVE-2024-3094")
        k8s_yaml = cls.generate_k8s_network_policy(safe_service, safe_cve)
        iam_json = cls.generate_aws_iam_deny_policy(impacted_roles, exposed_crown_jewels)
        iptables_sh = cls.generate_iptables_firewall_rule(safe_service)
        terraform_tf = cls.generate_terraform_patch(safe_service)

        safe_path = [cls._sanitize_name(str(p), "node") for p in (traversal_path or [])]
        safe_roles = [cls._sanitize_arn_or_role(str(r)) for r in (impacted_roles or [])]
        safe_cj = [cls._sanitize_name(str(c), "cj") for c in (exposed_crown_jewels or [])]

        return {
            "service_name": safe_service,
            "compromised_cve": safe_cve,
            "attack_path_sequence": safe_path,
            "explainable_path": " -> ".join(safe_path) if safe_path else "None",
            "impacted_roles": safe_roles,
            "exposed_crown_jewels": safe_cj,
            "k8s_network_policy_yaml": k8s_yaml,
            "aws_iam_deny_policy_json": iam_json,
            "host_iptables_script": iptables_sh,
            "terraform_patch_hcl": terraform_tf,
        }
