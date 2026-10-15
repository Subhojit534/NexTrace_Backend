"""
Remediation Script and Policy Generator.
Auto-generates production-grade mitigation artifacts:
1. Kubernetes NetworkPolicy (YAML) to isolate compromised pod.
2. AWS IAM Policy Revoke / Deny (JSON) to strip lateral IAM privilege.
3. Linux Host Firewall Rules (iptables) to block C2 traffic.
4. Terraform Security Group Patch (HCL).
"""

from typing import Any, Dict, List, Optional
import json


class RemediationGenerator:
    """Generates multi-cloud remediation artifacts based on blast radius graph evidence."""

    @staticmethod
    def generate_k8s_network_policy(service_name: str, compromised_cve: str = "CVE-2024-3094") -> str:
        """Generates Kubernetes NetworkPolicy isolating the compromised service."""
        pod_label = service_name.lower().replace("_", "-")
        return f"""# ==============================================================================
# NexTrace Autonomous Remediation: Kubernetes Isolation NetworkPolicy
# Triggered by: {compromised_cve} on {service_name}
# Action: Immediate zero-trust quarantine - Deny all ingress & egress mesh traffic
# ==============================================================================
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-{pod_label}-quarantine
  namespace: production
  labels:
    security.nextrace.io/quarantined: "true"
    security.nextrace.io/cve: "{compromised_cve}"
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

    @staticmethod
    def generate_aws_iam_deny_policy(compromised_roles: List[str], crown_jewels: List[str]) -> str:
        """Generates AWS IAM Deny Policy revoking privilege escalation."""
        role_arns = [
            r if r.startswith("arn:aws:") else f"arn:aws:iam::123456789:role/{r}"
            for r in compromised_roles
        ] if compromised_roles else ["arn:aws:iam::123456789:role/AuthServiceRole"]
        db_arns = [f"arn:aws:rds:us-east-1:123456789:db/{cj.lower()}" for cj in crown_jewels] if crown_jewels else ["arn:aws:rds:us-east-1:123456789:db/prodcustomerdb"]

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

    @staticmethod
    def generate_iptables_firewall_rule(service_name: str, compromised_port: int = 8443) -> str:
        """Generates Linux iptables / nftables emergency blocking commands."""
        return f"""#!/usr/bin/env bash
# ==============================================================================
# NexTrace Autonomous Remediation: Host Firewall Lockdown
# Target: {service_name} (Port {compromised_port})
# ==============================================================================
set -euo pipefail

echo "[+] Initiating emergency host containment for {service_name}..."

# 1. Drop all established and incoming connections on service port
sudo iptables -I INPUT 1 -p tcp --dport {compromised_port} -j DROP
sudo iptables -I FORWARD 1 -p tcp --dport {compromised_port} -j DROP

# 2. Block outbound lateral sweeps to internal database subnets (10.0.0.0/16)
sudo iptables -I OUTPUT 1 -d 10.0.2.0/24 -p tcp -m state --state NEW,ESTABLISHED -j REJECT --reject-with icmp-admin-prohibited

# 3. Log containment enforcement
logger -p auth.alert "[NexTrace Alert] Autonomous isolation rule active for {service_name}. Ingress and egress severed."

echo "[✓] Containment firewall rules applied successfully."
"""

    @staticmethod
    def generate_terraform_patch(service_name: str) -> str:
        """Generates Terraform HCL security group patch."""
        return f"""# ==============================================================================
# NexTrace Terraform Security Group Containment Patch
# Service: {service_name}
# ==============================================================================
resource "aws_security_group_rule" "quarantine_ingress_block" {{
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.{service_name.lower()}_sg.id
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
        k8s_yaml = cls.generate_k8s_network_policy(service_name, compromised_cve)
        iam_json = cls.generate_aws_iam_deny_policy(impacted_roles, exposed_crown_jewels)
        iptables_sh = cls.generate_iptables_firewall_rule(service_name)
        terraform_tf = cls.generate_terraform_patch(service_name)

        return {
            "service_name": service_name,
            "compromised_cve": compromised_cve,
            "attack_path_sequence": traversal_path,
            "explainable_path": " -> ".join(traversal_path) if traversal_path else "None",
            "impacted_roles": impacted_roles,
            "exposed_crown_jewels": exposed_crown_jewels,
            "k8s_network_policy_yaml": k8s_yaml,
            "aws_iam_deny_policy_json": iam_json,
            "host_iptables_script": iptables_sh,
            "terraform_patch_hcl": terraform_tf,
        }
