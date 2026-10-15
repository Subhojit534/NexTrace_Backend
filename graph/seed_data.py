"""
NexTrace Synthetic Graph Universe Seed Data.
Defines 34 enterprise nodes (Services, IAM Roles, Databases, CVEs, Teams, Libraries)
and realistic attack exposure relationships.
"""

import json
from pathlib import Path

NODES = [
    # 1. Edge & Entrypoint Services
    {
        "label": "Service",
        "properties": {
            "name": "PublicAPIGateway",
            "tier": "Edge",
            "public_facing": True,
            "status": "HEALTHY",
            "runtime": "Kong/Envoy",
            "environment": "Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "CustomerWebPortal",
            "tier": "Edge",
            "public_facing": True,
            "status": "HEALTHY",
            "runtime": "Next.js/Node",
            "environment": "Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "PartnerWebhookIngress",
            "tier": "Edge",
            "public_facing": True,
            "status": "HEALTHY",
            "runtime": "Go/Fiber",
            "environment": "Production",
            "criticality": "MEDIUM",
        },
    },
    # 2. Internal Microservices
    {
        "label": "Service",
        "properties": {
            "name": "AuthService",
            "tier": "Core",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Python/FastAPI",
            "environment": "Production",
            "criticality": "CRITICAL",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "PaymentService",
            "tier": "Core",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Java/Spring",
            "environment": "Production",
            "criticality": "CRITICAL",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "OrderService",
            "tier": "Core",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Node/Express",
            "environment": "Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "InventoryService",
            "tier": "Internal",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Go/Gin",
            "environment": "Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "NotificationWorker",
            "tier": "Internal",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Python/Celery",
            "environment": "Production",
            "criticality": "LOW",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "AnalyticsEngine",
            "tier": "Data",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Python/Pandas",
            "environment": "Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "DataPipelineWorker",
            "tier": "Data",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Scala/Spark",
            "environment": "Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "AdminPortal",
            "tier": "Management",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "React/Node",
            "environment": "Internal-VPN",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "SecretsManagerAgent",
            "tier": "Security",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "HashiCorp/Vault",
            "environment": "Production",
            "criticality": "CRITICAL",
        },
    },
    # 3. Third-party Libraries / Dependencies
    {
        "label": "Library",
        "properties": {
            "name": "libcrypto_v1_1",
            "version": "1.1.1u",
            "ecosystem": "C/OpenSSL",
            "license": "Apache-2.0",
        },
    },
    {
        "label": "Library",
        "properties": {
            "name": "fastjson_v1_2",
            "version": "1.2.80",
            "ecosystem": "Maven",
            "license": "Apache-2.0",
        },
    },
    {
        "label": "Library",
        "properties": {
            "name": "xz_utils_5_6_0",
            "version": "5.6.0",
            "ecosystem": "C/Tukaani",
            "license": "GPL-2.0",
        },
    },
    {
        "label": "Library",
        "properties": {
            "name": "pyyaml_5_3",
            "version": "5.3.1",
            "ecosystem": "PyPI",
            "license": "MIT",
        },
    },
    # 4. Vulnerabilities (CVEs)
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2024-3094_XZBackdoor",
            "cve_id": "CVE-2024-3094",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "description": "Malicious backdoor in upstream xz-utils liblzma enabling unauthorized authentication bypass and RCE.",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2022-25845_FastjsonRCE",
            "cve_id": "CVE-2022-25845",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "description": "AutoType bypass deserialization vulnerability leading to arbitrary remote command execution.",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2024-21626_RuncEscape",
            "cve_id": "CVE-2024-21626",
            "cvss": 8.6,
            "severity": "HIGH",
            "attack_vector": "LOCAL",
            "description": "Leaked file descriptors in runc container runtime allow container breakout to host filesystem.",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2023-44487_RapidReset",
            "cve_id": "CVE-2023-44487",
            "cvss": 7.5,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "description": "HTTP/2 Rapid Reset protocol flaw enabling DDoS resource exhaustion.",
        },
    },
    # 5. IAM Roles & Permissions
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_APIGatewayExecution",
            "arn": "arn:aws:iam::123456789:role/APIGatewayRole",
            "privilege_level": "RESTRICTED",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_AuthServicePrivileged",
            "arn": "arn:aws:iam::123456789:role/AuthServiceRole",
            "privilege_level": "ELEVATED",
            "max_session_duration": 7200,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_PaymentAdmin",
            "arn": "arn:aws:iam::123456789:role/PaymentAdminRole",
            "privilege_level": "HIGH_PRIVILEGE",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_DBAccessProxy",
            "arn": "arn:aws:iam::123456789:role/DBAccessProxyRole",
            "privilege_level": "DATABASE_ADMIN",
            "max_session_duration": 7200,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_AnalyticsReader",
            "arn": "arn:aws:iam::123456789:role/AnalyticsReaderRole",
            "privilege_level": "READ_ONLY",
            "max_session_duration": 14400,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_K8sClusterAdmin",
            "arn": "arn:aws:iam::123456789:role/K8sClusterAdminRole",
            "privilege_level": "ROOT_ADMIN",
            "max_session_duration": 3600,
        },
    },
    # 6. Databases & Crown Jewels
    {
        "label": "Database",
        "properties": {
            "name": "ProdCustomerDB",
            "crown_jewel": True,
            "classification": "Confidential",
            "engine": "PostgreSQL RDS Multi-AZ",
            "records_count": "2.4M records",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "PCI_PaymentVault",
            "crown_jewel": True,
            "classification": "PCI-DSS Top Secret",
            "engine": "AWS DynamoDB Encrypted KMS",
            "records_count": "850K tokens",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "UserCredentialsStore",
            "crown_jewel": True,
            "classification": "Top Secret",
            "engine": "Hardware Security Redis",
            "records_count": "2.4M hashes",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "AuditLogsDB",
            "crown_jewel": False,
            "classification": "Internal",
            "engine": "Elasticsearch OpenSearch",
            "records_count": "150M events",
            "contains_pii": False,
        },
    },
    # 7. Engineering & Security Teams
    {
        "label": "Team",
        "properties": {
            "name": "SecOpsTeam",
            "on_call": "secops-tier1",
            "slack_channel": "#secops-incidents",
            "lead": "chief-security@enterprise.corp",
        },
    },
    {
        "label": "Team",
        "properties": {
            "name": "PlatformTeam",
            "on_call": "infra-sre",
            "slack_channel": "#cloud-platform",
            "lead": "infra-lead@enterprise.corp",
        },
    },
    {
        "label": "Team",
        "properties": {
            "name": "BillingTeam",
            "on_call": "billing-eng",
            "slack_channel": "#payments-billing",
            "lead": "billing-lead@enterprise.corp",
        },
    },
    {
        "label": "Team",
        "properties": {
            "name": "CoreBackendTeam",
            "on_call": "core-backend",
            "slack_channel": "#core-services",
            "lead": "backend-architect@enterprise.corp",
        },
    },
]

RELATIONSHIPS = [
    # Ingress to internal calls
    {"from": "PublicAPIGateway", "rel": "CALLS", "to": "AuthService", "props": {"protocol": "HTTPS/gRPC", "port": 8443, "status": "ACTIVE"}},
    {"from": "PublicAPIGateway", "rel": "CALLS", "to": "OrderService", "props": {"protocol": "HTTPS/REST", "port": 8080, "status": "ACTIVE"}},
    {"from": "CustomerWebPortal", "rel": "CALLS", "to": "AuthService", "props": {"protocol": "HTTPS/REST", "port": 8443, "status": "ACTIVE"}},
    {"from": "CustomerWebPortal", "rel": "CALLS", "to": "InventoryService", "props": {"protocol": "HTTPS/REST", "port": 8081, "status": "ACTIVE"}},
    {"from": "PartnerWebhookIngress", "rel": "CALLS", "to": "NotificationWorker", "props": {"protocol": "mTLS/HTTP", "port": 9000, "status": "ACTIVE"}},

    # Microservice mesh calls
    {"from": "AuthService", "rel": "CALLS", "to": "PaymentService", "props": {"protocol": "gRPC", "port": 9090, "status": "ACTIVE"}},
    {"from": "OrderService", "rel": "CALLS", "to": "PaymentService", "props": {"protocol": "REST", "port": 9090, "status": "ACTIVE"}},
    {"from": "OrderService", "rel": "CALLS", "to": "InventoryService", "props": {"protocol": "REST", "port": 8081, "status": "ACTIVE"}},
    {"from": "PaymentService", "rel": "CALLS", "to": "SecretsManagerAgent", "props": {"protocol": "HTTPS", "port": 8200, "status": "ACTIVE"}},
    {"from": "DataPipelineWorker", "rel": "CALLS", "to": "AnalyticsEngine", "props": {"protocol": "Kafka/TCP", "port": 9092, "status": "ACTIVE"}},

    # Dependency relations
    {"from": "AuthService", "rel": "DEPENDS_ON", "to": "xz_utils_5_6_0", "props": {"scope": "compiled-native"}},
    {"from": "AuthService", "rel": "DEPENDS_ON", "to": "libcrypto_v1_1", "props": {"scope": "runtime"}},
    {"from": "OrderService", "rel": "DEPENDS_ON", "to": "fastjson_v1_2", "props": {"scope": "runtime"}},
    {"from": "DataPipelineWorker", "rel": "DEPENDS_ON", "to": "pyyaml_5_3", "props": {"scope": "runtime"}},

    # IAM Privileges
    {"from": "PublicAPIGateway", "rel": "CAN_ASSUME", "to": "IAMRole_APIGatewayExecution", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},
    {"from": "AuthService", "rel": "CAN_ASSUME", "to": "IAMRole_AuthServicePrivileged", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},
    {"from": "PaymentService", "rel": "CAN_ASSUME", "to": "IAMRole_PaymentAdmin", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},
    {"from": "AdminPortal", "rel": "CAN_ASSUME", "to": "IAMRole_K8sClusterAdmin", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},
    {"from": "AnalyticsEngine", "rel": "CAN_ASSUME", "to": "IAMRole_AnalyticsReader", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},

    # Privilege escalation / role chaining
    {"from": "IAMRole_AuthServicePrivileged", "rel": "CAN_ASSUME", "to": "IAMRole_DBAccessProxy", "props": {"trust_policy": "sts:AssumeRoleChain", "status": "PERMITTED"}},
    {"from": "IAMRole_K8sClusterAdmin", "rel": "CAN_ASSUME", "to": "IAMRole_PaymentAdmin", "props": {"trust_policy": "sts:AssumeRoleChain", "status": "PERMITTED"}},

    # Database Access (Crown Jewel Exposure)
    {"from": "IAMRole_DBAccessProxy", "rel": "ACCESSES", "to": "ProdCustomerDB", "props": {"permissions": ["SELECT", "INSERT", "UPDATE"], "status": "PERMITTED"}},
    {"from": "IAMRole_DBAccessProxy", "rel": "ACCESSES", "to": "UserCredentialsStore", "props": {"permissions": ["HGETALL", "HSET"], "status": "PERMITTED"}},
    {"from": "IAMRole_PaymentAdmin", "rel": "ACCESSES", "to": "PCI_PaymentVault", "props": {"permissions": ["GetItem", "PutItem", "Decrypt"], "status": "PERMITTED"}},
    {"from": "IAMRole_PaymentAdmin", "rel": "ACCESSES", "to": "ProdCustomerDB", "props": {"permissions": ["SELECT", "UPDATE"], "status": "PERMITTED"}},
    {"from": "IAMRole_AnalyticsReader", "rel": "ACCESSES", "to": "AuditLogsDB", "props": {"permissions": ["READ"], "status": "PERMITTED"}},

    # Vulnerability mappings
    {"from": "xz_utils_5_6_0", "rel": "HAS_VULNERABILITY", "to": "CVE-2024-3094_XZBackdoor", "props": {"status": "UNPATCHED"}},
    {"from": "fastjson_v1_2", "rel": "HAS_VULNERABILITY", "to": "CVE-2022-25845_FastjsonRCE", "props": {"status": "UNPATCHED"}},
    {"from": "AuthService", "rel": "AFFECTED_BY", "to": "CVE-2024-3094_XZBackdoor", "props": {"exploitability": "CONFIRMED"}},
    {"from": "OrderService", "rel": "AFFECTED_BY", "to": "CVE-2022-25845_FastjsonRCE", "props": {"exploitability": "SUSPECTED"}},
    {"from": "NotificationWorker", "rel": "AFFECTED_BY", "to": "CVE-2023-44487_RapidReset", "props": {"exploitability": "EXPOSED"}},

    # Team ownership
    {"from": "AuthService", "rel": "MAINTAINED_BY", "to": "CoreBackendTeam", "props": {"sla": "Tier-1"}},
    {"from": "PaymentService", "rel": "MAINTAINED_BY", "to": "BillingTeam", "props": {"sla": "Tier-1"}},
    {"from": "PublicAPIGateway", "rel": "MAINTAINED_BY", "to": "PlatformTeam", "props": {"sla": "Tier-0"}},
    {"from": "ProdCustomerDB", "rel": "MAINTAINED_BY", "to": "PlatformTeam", "props": {"sla": "Tier-0"}},
    {"from": "PCI_PaymentVault", "rel": "MAINTAINED_BY", "to": "SecOpsTeam", "props": {"sla": "Tier-0"}},
]

# ==============================================================================
# PRESET 2: Google Cloud Online Boutique (11-Tier Microservice Benchmark)
# ==============================================================================
ONLINE_BOUTIQUE_NODES = [
    # 1. 11-Tier Microservices
    {
        "label": "Service",
        "properties": {
            "name": "frontend",
            "tier": "Frontend/Edge",
            "public_facing": True,
            "status": "HEALTHY",
            "runtime": "Go",
            "environment": "GKE-Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "cartservice",
            "tier": "Core/Stateful",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "C#/.NET",
            "environment": "GKE-Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "productcatalogservice",
            "tier": "Core",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Go",
            "environment": "GKE-Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "currencyservice",
            "tier": "Supporting",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Node.js",
            "environment": "GKE-Production",
            "criticality": "LOW",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "paymentservice",
            "tier": "Core/Sensitive",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Node.js",
            "environment": "GKE-Production",
            "criticality": "CRITICAL",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "shippingservice",
            "tier": "Fulfillment",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Go",
            "environment": "GKE-Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "emailservice",
            "tier": "Notification",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Python",
            "environment": "GKE-Production",
            "criticality": "LOW",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "checkoutservice",
            "tier": "Core Orchestrator",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Go",
            "environment": "GKE-Production",
            "criticality": "CRITICAL",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "recommendationservice",
            "tier": "Analytics/ML",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Python",
            "environment": "GKE-Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "adservice",
            "tier": "Marketing",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Java",
            "environment": "GKE-Production",
            "criticality": "LOW",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "redis-cart",
            "tier": "Data/Cache",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Redis",
            "environment": "GKE-Production",
            "criticality": "HIGH",
        },
    },
    # 2. Crown Jewels & Databases
    {
        "label": "Database",
        "properties": {
            "name": "CreditCardVault",
            "crown_jewel": True,
            "classification": "PCI-DSS Top Secret",
            "engine": "Google Cloud Spanner",
            "records_count": "1.2M tokens",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "CustomerOrderStore",
            "crown_jewel": True,
            "classification": "Confidential",
            "engine": "Cloud Firestore / Bigtable",
            "records_count": "4.8M orders",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "SessionStateStore",
            "crown_jewel": False,
            "classification": "Internal",
            "engine": "Memorystore Redis",
            "records_count": "500K sessions",
            "contains_pii": False,
        },
    },
    # 3. IAM Roles & Workload Identities
    {
        "label": "IAMRole",
        "properties": {
            "name": "GCP_SA_Frontend",
            "arn": "frontend-sa@boutique-prod.iam.gserviceaccount.com",
            "privilege_level": "RESTRICTED",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "GCP_SA_CheckoutService",
            "arn": "checkout-sa@boutique-prod.iam.gserviceaccount.com",
            "privilege_level": "ELEVATED",
            "max_session_duration": 7200,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "GCP_SA_PaymentProcessor",
            "arn": "payment-sa@boutique-prod.iam.gserviceaccount.com",
            "privilege_level": "HIGH_PRIVILEGE",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "GCP_SA_SpannerDBAdmin",
            "arn": "spanner-admin@boutique-prod.iam.gserviceaccount.com",
            "privilege_level": "DATABASE_ADMIN",
            "max_session_duration": 7200,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "GCP_SA_ClusterAdmin",
            "arn": "cluster-admin@boutique-prod.iam.gserviceaccount.com",
            "privilege_level": "ROOT_ADMIN",
            "max_session_duration": 3600,
        },
    },
    # 4. Libraries & Dependencies
    {
        "label": "Library",
        "properties": {
            "name": "grpc_go_1_45",
            "version": "1.45.0",
            "ecosystem": "Go/gRPC",
            "license": "Apache-2.0",
        },
    },
    {
        "label": "Library",
        "properties": {
            "name": "express_cart_jwt",
            "version": "2.1.0",
            "ecosystem": "npm",
            "license": "MIT",
        },
    },
    {
        "label": "Library",
        "properties": {
            "name": "redis_py_4_3",
            "version": "4.3.4",
            "ecosystem": "PyPI",
            "license": "MIT",
        },
    },
    # 5. Vulnerabilities
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2023-32731_gRPCHttp2",
            "cve_id": "CVE-2023-32731",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "description": "gRPC HTTP/2 stream cancellation vulnerability leading to memory corruption and potential RCE.",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2023-44487_RapidReset",
            "cve_id": "CVE-2023-44487",
            "cvss": 7.5,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "description": "HTTP/2 Rapid Reset protocol flaw enabling DDoS resource exhaustion.",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2022-29217_PyJWTKeyConfusion",
            "cve_id": "CVE-2022-29217",
            "cvss": 8.8,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "description": "Key confusion vulnerability in JWT parsing allowing auth token forgery and privilege escalation.",
        },
    },
    # 6. Teams
    {
        "label": "Team",
        "properties": {
            "name": "CloudSRETeam",
            "on_call": "gcp-sre",
            "slack_channel": "#boutique-sre",
            "lead": "sre-lead@boutique.cloud",
        },
    },
    {
        "label": "Team",
        "properties": {
            "name": "CheckoutCoreTeam",
            "on_call": "checkout-eng",
            "slack_channel": "#boutique-checkout",
            "lead": "checkout-lead@boutique.cloud",
        },
    },
    {
        "label": "Team",
        "properties": {
            "name": "SecOpsTeam",
            "on_call": "secops-gcp",
            "slack_channel": "#boutique-secops",
            "lead": "secops@boutique.cloud",
        },
    },
]

ONLINE_BOUTIQUE_RELATIONSHIPS = [
    # Ingress calls from frontend
    {"from": "frontend", "rel": "CALLS", "to": "checkoutservice", "props": {"protocol": "gRPC", "port": 5050, "status": "ACTIVE"}},
    {"from": "frontend", "rel": "CALLS", "to": "cartservice", "props": {"protocol": "gRPC", "port": 7070, "status": "ACTIVE"}},
    {"from": "frontend", "rel": "CALLS", "to": "productcatalogservice", "props": {"protocol": "gRPC", "port": 3550, "status": "ACTIVE"}},
    {"from": "frontend", "rel": "CALLS", "to": "recommendationservice", "props": {"protocol": "gRPC", "port": 8080, "status": "ACTIVE"}},
    {"from": "frontend", "rel": "CALLS", "to": "adservice", "props": {"protocol": "gRPC", "port": 9555, "status": "ACTIVE"}},
    {"from": "frontend", "rel": "CALLS", "to": "currencyservice", "props": {"protocol": "gRPC", "port": 7000, "status": "ACTIVE"}},
    {"from": "frontend", "rel": "CALLS", "to": "shippingservice", "props": {"protocol": "gRPC", "port": 50051, "status": "ACTIVE"}},

    # CheckoutService orchestration mesh calls
    {"from": "checkoutservice", "rel": "CALLS", "to": "cartservice", "props": {"protocol": "gRPC", "port": 7070, "status": "ACTIVE"}},
    {"from": "checkoutservice", "rel": "CALLS", "to": "paymentservice", "props": {"protocol": "gRPC", "port": 50051, "status": "ACTIVE"}},
    {"from": "checkoutservice", "rel": "CALLS", "to": "shippingservice", "props": {"protocol": "gRPC", "port": 50051, "status": "ACTIVE"}},
    {"from": "checkoutservice", "rel": "CALLS", "to": "emailservice", "props": {"protocol": "gRPC", "port": 8080, "status": "ACTIVE"}},
    {"from": "checkoutservice", "rel": "CALLS", "to": "currencyservice", "props": {"protocol": "gRPC", "port": 7000, "status": "ACTIVE"}},
    {"from": "checkoutservice", "rel": "CALLS", "to": "productcatalogservice", "props": {"protocol": "gRPC", "port": 3550, "status": "ACTIVE"}},

    # Core dependencies & storage
    {"from": "cartservice", "rel": "CALLS", "to": "redis-cart", "props": {"protocol": "Redis/TCP", "port": 6379, "status": "ACTIVE"}},
    {"from": "recommendationservice", "rel": "CALLS", "to": "productcatalogservice", "props": {"protocol": "gRPC", "port": 3550, "status": "ACTIVE"}},

    # IAM / Workload Identity assignments
    {"from": "frontend", "rel": "CAN_ASSUME", "to": "GCP_SA_Frontend", "props": {"trust_policy": "gcp:WorkloadIdentityUser", "status": "PERMITTED"}},
    {"from": "checkoutservice", "rel": "CAN_ASSUME", "to": "GCP_SA_CheckoutService", "props": {"trust_policy": "gcp:WorkloadIdentityUser", "status": "PERMITTED"}},
    {"from": "paymentservice", "rel": "CAN_ASSUME", "to": "GCP_SA_PaymentProcessor", "props": {"trust_policy": "gcp:WorkloadIdentityUser", "status": "PERMITTED"}},

    # IAM Escalation & chaining
    {"from": "GCP_SA_CheckoutService", "rel": "CAN_ASSUME", "to": "GCP_SA_PaymentProcessor", "props": {"trust_policy": "iam.serviceAccounts.actAs", "status": "PERMITTED"}},
    {"from": "GCP_SA_PaymentProcessor", "rel": "CAN_ASSUME", "to": "GCP_SA_SpannerDBAdmin", "props": {"trust_policy": "iam.serviceAccounts.actAs", "status": "PERMITTED"}},

    # Database Access (Crown Jewels)
    {"from": "GCP_SA_PaymentProcessor", "rel": "ACCESSES", "to": "CreditCardVault", "props": {"permissions": ["spanner.databases.read", "spanner.databases.write"], "status": "PERMITTED"}},
    {"from": "GCP_SA_SpannerDBAdmin", "rel": "ACCESSES", "to": "CreditCardVault", "props": {"permissions": ["spanner.databases.admin"], "status": "PERMITTED"}},
    {"from": "GCP_SA_CheckoutService", "rel": "ACCESSES", "to": "CustomerOrderStore", "props": {"permissions": ["datastore.entities.get", "datastore.entities.put"], "status": "PERMITTED"}},
    {"from": "redis-cart", "rel": "ACCESSES", "to": "SessionStateStore", "props": {"permissions": ["SET", "GET"], "status": "PERMITTED"}},

    # Libraries & CVE relationships
    {"from": "checkoutservice", "rel": "DEPENDS_ON", "to": "grpc_go_1_45", "props": {"scope": "runtime"}},
    {"from": "frontend", "rel": "DEPENDS_ON", "to": "grpc_go_1_45", "props": {"scope": "runtime"}},
    {"from": "grpc_go_1_45", "rel": "HAS_VULNERABILITY", "to": "CVE-2023-32731_gRPCHttp2", "props": {"status": "UNPATCHED"}},
    {"from": "checkoutservice", "rel": "AFFECTED_BY", "to": "CVE-2023-32731_gRPCHttp2", "props": {"exploitability": "CONFIRMED"}},
    {"from": "frontend", "rel": "AFFECTED_BY", "to": "CVE-2023-44487_RapidReset", "props": {"exploitability": "SUSPECTED"}},
    {"from": "paymentservice", "rel": "AFFECTED_BY", "to": "CVE-2022-29217_PyJWTKeyConfusion", "props": {"exploitability": "CONFIRMED"}},

    # Team Ownership
    {"from": "frontend", "rel": "MAINTAINED_BY", "to": "CloudSRETeam", "props": {"sla": "Tier-0"}},
    {"from": "checkoutservice", "rel": "MAINTAINED_BY", "to": "CheckoutCoreTeam", "props": {"sla": "Tier-0"}},
    {"from": "paymentservice", "rel": "MAINTAINED_BY", "to": "SecOpsTeam", "props": {"sla": "Tier-0"}},
    {"from": "CreditCardVault", "rel": "MAINTAINED_BY", "to": "SecOpsTeam", "props": {"sla": "Tier-0"}},
    {"from": "CustomerOrderStore", "rel": "MAINTAINED_BY", "to": "CheckoutCoreTeam", "props": {"sla": "Tier-1"}},
]


# ==============================================================================
# PRESET 3: AWS Cloud IAM Privilege Escalation Attack Graph
# ==============================================================================
AWS_IAM_NODES = [
    # 1. Cloud Workloads & Services
    {
        "label": "Service",
        "properties": {
            "name": "PublicWebAPI",
            "tier": "Edge",
            "public_facing": True,
            "status": "HEALTHY",
            "runtime": "FastAPI/ALB",
            "environment": "AWS-Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "DevEC2Workload",
            "tier": "Compute",
            "public_facing": True,
            "status": "HEALTHY",
            "runtime": "Amazon Linux 2023 / Docker",
            "environment": "AWS-Development",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "ECSOrderFulfillment",
            "tier": "Container",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Node.js / Fargate",
            "environment": "AWS-Production",
            "criticality": "HIGH",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "LambdaDataIngest",
            "tier": "Serverless",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "Python 3.11",
            "environment": "AWS-Production",
            "criticality": "MEDIUM",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "BatchETLRunner",
            "tier": "Batch",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "AWS Glue / PySpark",
            "environment": "AWS-Production",
            "criticality": "LOW",
        },
    },
    {
        "label": "Service",
        "properties": {
            "name": "InternalBastion",
            "tier": "Management",
            "public_facing": False,
            "status": "HEALTHY",
            "runtime": "OpenSSH / SSM",
            "environment": "AWS-SecurityVPC",
            "criticality": "HIGH",
        },
    },
    # 2. IAM Roles & Escalation Chaining
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_EC2InstanceProfile",
            "arn": "arn:aws:iam::123456789:role/EC2BasicInstanceProfile",
            "privilege_level": "RESTRICTED",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_DevDeployer",
            "arn": "arn:aws:iam::123456789:role/DevDeployerRole",
            "privilege_level": "ELEVATED",
            "max_session_duration": 7200,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_SecOpsPrivilegeEscalator",
            "arn": "arn:aws:iam::123456789:role/SecOpsAuditorRole",
            "privilege_level": "HIGH_PRIVILEGE",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_AWSOrganizationAdmin",
            "arn": "arn:aws:iam::123456789:role/AWSOrganizationAdminRole",
            "privilege_level": "ROOT_ADMIN",
            "max_session_duration": 3600,
        },
    },
    {
        "label": "IAMRole",
        "properties": {
            "name": "IAMRole_RDSProxy",
            "arn": "arn:aws:iam::123456789:role/RDSProxyAdminRole",
            "privilege_level": "DATABASE_ADMIN",
            "max_session_duration": 7200,
        },
    },
    # 3. Databases & Crown Jewels
    {
        "label": "Database",
        "properties": {
            "name": "S3_FinancialAuditDataLake",
            "crown_jewel": True,
            "classification": "PCI-DSS Confidential",
            "engine": "Amazon S3 Encrypted SSE-KMS",
            "records_count": "12TB raw financials",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "RDS_ProductionCustomerVault",
            "crown_jewel": True,
            "classification": "Top Secret",
            "engine": "Amazon Aurora PostgreSQL Multi-AZ",
            "records_count": "5.5M records",
            "contains_pii": True,
        },
    },
    {
        "label": "Database",
        "properties": {
            "name": "CloudTrailSecurityLogs",
            "crown_jewel": False,
            "classification": "Internal",
            "engine": "CloudWatch / Athena",
            "records_count": "200M events",
            "contains_pii": False,
        },
    },
    # 4. Libraries
    {
        "label": "Library",
        "properties": {
            "name": "boto3_1_28",
            "version": "1.28.1",
            "ecosystem": "PyPI",
            "license": "Apache-2.0",
        },
    },
    {
        "label": "Library",
        "properties": {
            "name": "urllib3_1_26",
            "version": "1.26.15",
            "ecosystem": "PyPI",
            "license": "MIT",
        },
    },
    # 5. Vulnerabilities
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2023-38035_SSRF_IMDSv1",
            "cve_id": "CVE-2023-38035",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "attack_vector": "NETWORK",
            "description": "SSRF vulnerability allowing metadata theft via AWS Instance Metadata Service (IMDSv1).",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2024-28056_IAMPolicyInjection",
            "cve_id": "CVE-2024-28056",
            "cvss": 8.8,
            "severity": "HIGH",
            "attack_vector": "NETWORK",
            "description": "IAM assume-role trust policy injection enabling unauthorized privilege escalation to AdministratorAccess.",
        },
    },
    {
        "label": "Vulnerability",
        "properties": {
            "name": "CVE-2024-21626_ContainerEscape",
            "cve_id": "CVE-2024-21626",
            "cvss": 8.6,
            "severity": "HIGH",
            "attack_vector": "LOCAL",
            "description": "runc container escape enabling host takeover and IAM credential harvesting.",
        },
    },
    # 6. Teams
    {
        "label": "Team",
        "properties": {
            "name": "CloudInfrastructureTeam",
            "on_call": "aws-infra",
            "slack_channel": "#aws-infra",
            "lead": "cloud-architect@enterprise.corp",
        },
    },
    {
        "label": "Team",
        "properties": {
            "name": "SecOpsRedTeam",
            "on_call": "secops-iam",
            "slack_channel": "#iam-governance",
            "lead": "iam-lead@enterprise.corp",
        },
    },
]

AWS_IAM_RELATIONSHIPS = [
    # Workload communication
    {"from": "PublicWebAPI", "rel": "CALLS", "to": "ECSOrderFulfillment", "props": {"protocol": "HTTPS", "port": 443, "status": "ACTIVE"}},
    {"from": "DevEC2Workload", "rel": "CALLS", "to": "LambdaDataIngest", "props": {"protocol": "AWS-SDK/HTTPS", "port": 443, "status": "ACTIVE"}},
    {"from": "ECSOrderFulfillment", "rel": "CALLS", "to": "LambdaDataIngest", "props": {"protocol": "AWS-SDK/HTTPS", "port": 443, "status": "ACTIVE"}},
    {"from": "LambdaDataIngest", "rel": "CALLS", "to": "BatchETLRunner", "props": {"protocol": "SQS/EventBridge", "port": 443, "status": "ACTIVE"}},

    # IAM Role Assumptions
    {"from": "DevEC2Workload", "rel": "CAN_ASSUME", "to": "IAMRole_EC2InstanceProfile", "props": {"trust_policy": "ec2:AssumeRole", "status": "PERMITTED"}},
    {"from": "PublicWebAPI", "rel": "CAN_ASSUME", "to": "IAMRole_DevDeployer", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},
    {"from": "ECSOrderFulfillment", "rel": "CAN_ASSUME", "to": "IAMRole_DevDeployer", "props": {"trust_policy": "sts:AssumeRole", "status": "PERMITTED"}},

    # IAM Privilege Escalation Chaining
    {"from": "IAMRole_EC2InstanceProfile", "rel": "CAN_ASSUME", "to": "IAMRole_DevDeployer", "props": {"technique": "iam:PassRole / sts:AssumeRole", "status": "PERMITTED"}},
    {"from": "IAMRole_DevDeployer", "rel": "CAN_ASSUME", "to": "IAMRole_SecOpsPrivilegeEscalator", "props": {"technique": "iam:CreatePolicyVersion escalation", "status": "PERMITTED"}},
    {"from": "IAMRole_SecOpsPrivilegeEscalator", "rel": "CAN_ASSUME", "to": "IAMRole_AWSOrganizationAdmin", "props": {"technique": "iam:AttachRolePolicy to AdministratorAccess", "status": "PERMITTED"}},
    {"from": "IAMRole_SecOpsPrivilegeEscalator", "rel": "CAN_ASSUME", "to": "IAMRole_RDSProxy", "props": {"trust_policy": "sts:AssumeRoleChain", "status": "PERMITTED"}},

    # Database & Data Lake Access (Crown Jewels)
    {"from": "IAMRole_AWSOrganizationAdmin", "rel": "ACCESSES", "to": "S3_FinancialAuditDataLake", "props": {"permissions": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"], "status": "PERMITTED"}},
    {"from": "IAMRole_RDSProxy", "rel": "ACCESSES", "to": "RDS_ProductionCustomerVault", "props": {"permissions": ["rds-db:connect", "SELECT", "UPDATE"], "status": "PERMITTED"}},
    {"from": "LambdaDataIngest", "rel": "ACCESSES", "to": "CloudTrailSecurityLogs", "props": {"permissions": ["logs:PutLogEvents"], "status": "PERMITTED"}},

    # Dependencies & Vulnerabilities
    {"from": "DevEC2Workload", "rel": "DEPENDS_ON", "to": "urllib3_1_26", "props": {"scope": "runtime"}},
    {"from": "PublicWebAPI", "rel": "DEPENDS_ON", "to": "boto3_1_28", "props": {"scope": "runtime"}},
    {"from": "urllib3_1_26", "rel": "HAS_VULNERABILITY", "to": "CVE-2023-38035_SSRF_IMDSv1", "props": {"status": "UNPATCHED"}},
    {"from": "DevEC2Workload", "rel": "AFFECTED_BY", "to": "CVE-2023-38035_SSRF_IMDSv1", "props": {"exploitability": "CONFIRMED"}},
    {"from": "PublicWebAPI", "rel": "AFFECTED_BY", "to": "CVE-2024-28056_IAMPolicyInjection", "props": {"exploitability": "CONFIRMED"}},
    {"from": "ECSOrderFulfillment", "rel": "AFFECTED_BY", "to": "CVE-2024-21626_ContainerEscape", "props": {"exploitability": "SUSPECTED"}},

    # Team Ownership
    {"from": "PublicWebAPI", "rel": "MAINTAINED_BY", "to": "CloudInfrastructureTeam", "props": {"sla": "Tier-0"}},
    {"from": "DevEC2Workload", "rel": "MAINTAINED_BY", "to": "CloudInfrastructureTeam", "props": {"sla": "Tier-1"}},
    {"from": "S3_FinancialAuditDataLake", "rel": "MAINTAINED_BY", "to": "SecOpsRedTeam", "props": {"sla": "Tier-0"}},
    {"from": "RDS_ProductionCustomerVault", "rel": "MAINTAINED_BY", "to": "SecOpsRedTeam", "props": {"sla": "Tier-0"}},
]


def normalize_graph_json(data: dict):
    """
    Normalizes arbitrary JSON graph topologies into standard NexTrace nodes & relationships format.
    Accepts:
    - Standard NexTrace format: {"nodes": [...], "relationships": [...]}
    - D3/Cytoscape format: {"nodes": [...], "edges": [...]} or {"nodes": [...], "links": [...]}
    - Flat property structures or nested 'properties'
    """
    if isinstance(data, list):
        raw_nodes = [item for item in data if isinstance(item, dict) and (item.get("group") == "nodes" or ("source" not in item and "source" not in item.get("data", {})))]
        raw_rels = [item for item in data if isinstance(item, dict) and (item.get("group") == "edges" or "source" in item or "source" in item.get("data", {}))]
    elif isinstance(data, dict):
        elements = data.get("elements")
        if isinstance(elements, dict):
            raw_nodes = elements.get("nodes", [])
            raw_rels = elements.get("relationships", elements.get("edges", elements.get("links", [])))
        elif isinstance(elements, list):
            raw_nodes = [item for item in elements if isinstance(item, dict) and (item.get("group") == "nodes" or ("source" not in item and "source" not in item.get("data", {})))]
            raw_rels = [item for item in elements if isinstance(item, dict) and (item.get("group") == "edges" or "source" in item or "source" in item.get("data", {}))]
        else:
            raw_nodes = data.get("nodes", [])
            raw_rels = data.get("relationships", data.get("edges", data.get("links", [])))
    else:
        raw_nodes, raw_rels = [], []

    normalized_nodes = []
    normalized_rels = []

    has_explicit_public = False
    for item in raw_nodes:
        if isinstance(item, dict):
            p = item.get("properties", {}) if isinstance(item.get("properties"), dict) else {}
            d = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
            if item.get("public_facing") is True or p.get("public_facing") is True or d.get("public_facing") is True:
                has_explicit_public = True
                break

    for item in raw_nodes:
        if not isinstance(item, dict):
            continue
        nested_data = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
        label = item.get("label", item.get("type", nested_data.get("label", nested_data.get("type", "Service"))))
        props = dict(item.get("properties", {}))

        for k, v in nested_data.items():
            if k not in ["label", "type"] and k not in props:
                props[k] = v
        for k, v in item.items():
            if k not in ["label", "type", "properties", "data", "position", "group", "classes"] and k not in props:
                props[k] = v

        if "name" not in props:
            props["name"] = props.get("id", item.get("id", item.get("name", "UnknownNode")))

        name_lower = str(props.get("name", "")).lower()
        tier_lower = str(props.get("tier", "")).lower()
        if "public_facing" not in props:
            if not has_explicit_public:
                if any(term in name_lower for term in ["ingress", "gateway", "frontend", "public", "edge", "web", "portal"]):
                    props["public_facing"] = True
                elif any(term in tier_lower for term in ["edge", "frontend", "public", "ingress"]):
                    props["public_facing"] = True

        if "crown_jewel" not in props:
            if label in ["Database", "DataStore", "CrownJewel", "Vault"] or any(term in name_lower for term in ["vault", "crowndb", "secret", "datalake", "database", "ordersdb", "customerdb"]):
                props["crown_jewel"] = True

        node_entry = dict(props)
        node_entry["label"] = label
        node_entry["properties"] = props
        normalized_nodes.append(node_entry)

    for item in raw_rels:
        if not isinstance(item, dict):
            continue
        nested_data = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
        from_node = item.get("from", item.get("source", item.get("from_node", nested_data.get("source", nested_data.get("from", "")))))
        to_node = item.get("to", item.get("target", item.get("to_node", nested_data.get("target", nested_data.get("to", "")))))
        rel_type = item.get("rel", item.get("type", item.get("label", item.get("relationship", nested_data.get("label", nested_data.get("type", "CALLS"))))))
        props = dict(item.get("props", item.get("properties", {})))

        for k, v in nested_data.items():
            if k not in ["from", "to", "source", "target", "label", "type"] and k not in props:
                props[k] = v
        for k, v in item.items():
            if k not in ["from", "to", "source", "target", "from_node", "to_node", "rel", "type", "label", "relationship", "props", "properties", "data", "position", "group", "classes"] and k not in props:
                props[k] = v

        if from_node and to_node:
            normalized_rels.append({
                "from": str(from_node),
                "rel": str(rel_type),
                "to": str(to_node),
                "props": props
            })

    return normalized_nodes, normalized_rels


def validate_graph_data(nodes, relationships):
    """Validates structural integrity of parsed graph nodes and relationships."""
    if not nodes:
        return False, "Graph must contain at least 1 node."
    node_names = set()
    for n in nodes:
        name = n.get("properties", {}).get("name")
        if not name:
            return False, f"Found node without a 'name' property: {n}"
        node_names.add(name)

    for r in relationships:
        u = r.get("from")
        v = r.get("to")
        if u not in node_names:
            return False, f"Relationship source '{u}' does not match any node name in graph."
        if v not in node_names:
            return False, f"Relationship target '{v}' does not match any node name in graph."

    return True, None


def _load_sample_json_topology(filename: str):
    p = Path(__file__).resolve().parent.parent / "sample_graphs" / filename
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
            return normalize_graph_json(d)
        except Exception:
            pass
    return [], []

OTEL_NODES, OTEL_RELATIONSHIPS = _load_sample_json_topology("opentelemetry_astronomy_shop.json")
SOCK_NODES, SOCK_RELATIONSHIPS = _load_sample_json_topology("sockshop_microservices.json")


# ==============================================================================
# PRESETS REGISTRY & SAMPLE JSON UTILITIES
# ==============================================================================
PRESETS = {
    "fintech_enterprise": {
        "id": "fintech_enterprise",
        "name": "FinTech Enterprise Core (Default 34-Node Mesh)",
        "description": "Enterprise microservice mesh with Tier-0/1 services, AWS IAM roles, and PCI/Customer database crown jewels.",
        "nodes": NODES,
        "relationships": RELATIONSHIPS,
        "scenarios": {
            "Scenario A (AuthService RCE - Zero-Day CVE-2024-3094)": {
                "text": "CRITICAL ZERO-DAY: Remote code execution backdoor detected in AuthService via xz-utils liblzma (CVE-2024-3094). Ingress observed from PublicAPIGateway.",
                "service": "AuthService",
                "cve": "CVE-2024-3094"
            },
            "Scenario B (OrderService Deserialization CVE-2022-25845)": {
                "text": "HIGH SEVERITY: Remote arbitrary deserialization exploit observed in OrderService (CVE-2022-25845 Fastjson). Outbound calls to PaymentService detected.",
                "service": "OrderService",
                "cve": "CVE-2022-25845"
            },
            "Scenario C (NotificationWorker DDoS CVE-2023-44487)": {
                "text": "HIGH SEVERITY: HTTP/2 Rapid Reset protocol resource exhaustion attack on NotificationWorker (CVE-2023-44487) from PartnerWebhookIngress.",
                "service": "NotificationWorker",
                "cve": "CVE-2023-44487"
            }
        }
    },
    "google_online_boutique": {
        "id": "google_online_boutique",
        "name": "Google Cloud Online Boutique (11-Tier Benchmark)",
        "description": "Google's 11-tier microservice architecture with Workload Identities, gRPC mesh, and CreditCardVault.",
        "nodes": ONLINE_BOUTIQUE_NODES,
        "relationships": ONLINE_BOUTIQUE_RELATIONSHIPS,
        "scenarios": {
            "Scenario A (CheckoutService gRPC RCE - CVE-2023-32731)": {
                "text": "CRITICAL: HTTP/2 stream memory corruption exploit detected in CheckoutService via gRPC-Go (CVE-2023-32731) with active lateral pivot to PaymentProcessor.",
                "service": "checkoutservice",
                "cve": "CVE-2023-32731"
            },
            "Scenario B (PaymentService Key Confusion - CVE-2022-29217)": {
                "text": "CRITICAL: JWT token forgery and key confusion exploit in PaymentService (CVE-2022-29217) accessing CreditCardVault.",
                "service": "paymentservice",
                "cve": "CVE-2022-29217"
            },
            "Scenario C (Frontend Rapid Reset DoS - CVE-2023-44487)": {
                "text": "HIGH: HTTP/2 Rapid Reset protocol flooding attack against frontend (CVE-2023-44487).",
                "service": "frontend",
                "cve": "CVE-2023-44487"
            }
        }
    },
    "aws_cloud_iam": {
        "id": "aws_cloud_iam",
        "name": "AWS Cloud IAM Privilege Escalation",
        "description": "Multi-step AWS IAM privilege escalation attack graph from compromised EC2/APIs to Root Organization Admin.",
        "nodes": AWS_IAM_NODES,
        "relationships": AWS_IAM_RELATIONSHIPS,
        "scenarios": {
            "Scenario A (DevEC2Workload SSRF Credential Theft - CVE-2023-38035)": {
                "text": "CRITICAL: SSRF exploit against DevEC2Workload stealing IMDSv1 session tokens, pivoting via IAM role escalation to AWS Organization Admin.",
                "service": "DevEC2Workload",
                "cve": "CVE-2023-38035"
            },
            "Scenario B (PublicWebAPI IAM Policy Injection - CVE-2024-28056)": {
                "text": "HIGH SEVERITY: IAM AssumeRole trust policy injection on PublicWebAPI (CVE-2024-28056) attempting database takeover on RDS Production Customer Vault.",
                "service": "PublicWebAPI",
                "cve": "CVE-2024-28056"
            },
            "Scenario C (ECS Container Breakout - CVE-2024-21626)": {
                "text": "HIGH SEVERITY: runc container escape in ECSOrderFulfillment attempting host level credential exfiltration.",
                "service": "ECSOrderFulfillment",
                "cve": "CVE-2024-21626"
            }
        }
    },
    "opentelemetry_demo": {
        "id": "opentelemetry_demo",
        "name": "OpenTelemetry Astronomy Shop",
        "description": "Official OpenTelemetry polyglot microservices benchmark featuring Envoy edge proxy, Go/Node.js/C#/.NET services, and PostgreSQL card vaults.",
        "nodes": OTEL_NODES,
        "relationships": OTEL_RELATIONSHIPS,
        "scenarios": {
            "Scenario A (CheckoutService Memory Corruption - CVE-2023-32731)": {
                "text": "CRITICAL: gRPC memory corruption in CheckoutService (CVE-2023-32731) pivoting to PaymentService and OTel_PaymentVault.",
                "service": "CheckoutService",
                "cve": "CVE-2023-32731"
            },
            "Scenario B (PaymentService Deserialization - CVE-2022-25845)": {
                "text": "HIGH SEVERITY: Arbitrary code execution in PaymentService targeting OTel_PaymentVault customer secrets.",
                "service": "PaymentService",
                "cve": "CVE-2022-25845"
            },
            "Scenario C (CartService Memory Leak - CVE-2023-44487)": {
                "text": "HIGH SEVERITY: HTTP/2 Rapid Reset protocol flooding attack against CartService.",
                "service": "CartService",
                "cve": "CVE-2023-44487"
            }
        }
    },
    "sock_shop": {
        "id": "sock_shop",
        "name": "Weaveworks Sock Shop Cloud-Native",
        "description": "Standard cloud-native microservices benchmark with Traefik edge router, Spring Boot order services, and MongoDB vaults.",
        "nodes": SOCK_NODES,
        "relationships": SOCK_RELATIONSHIPS,
        "scenarios": {
            "Scenario A (Spring4Shell RCE in orders-service - CVE-2022-22965)": {
                "text": "CRITICAL: Spring4Shell Remote Code Execution in orders-service (CVE-2022-22965) targeting payment-vault and user credentials.",
                "service": "orders-service",
                "cve": "CVE-2022-22965"
            },
            "Scenario B (Payment Service RCE - CVE-2023-32731)": {
                "text": "HIGH SEVERITY: Remote execution attempt in payment-service targeting pci-payment-vault credit card records.",
                "service": "payment-service",
                "cve": "CVE-2023-32731"
            },
            "Scenario C (Front-End Rapid Reset DoS - CVE-2023-44487)": {
                "text": "HIGH SEVERITY: HTTP/2 DoS flood targeting edge front-end container.",
                "service": "front-end",
                "cve": "CVE-2023-44487"
            }
        }
    }
}


def list_presets():
    """Returns metadata for all available architecture presets."""
    return [
        {
            "id": pid,
            "name": p["name"],
            "description": p["description"],
            "node_count": len(p["nodes"]),
            "relationship_count": len(p["relationships"])
        }
        for pid, p in PRESETS.items()
    ]


def get_preset(preset_id: str):
    """Retrieves preset data by ID, returning a dedicated descriptor for 'custom' or defaulting to fintech_enterprise."""
    if preset_id == "custom":
        return {
            "id": "custom",
            "name": "Custom Uploaded Graph Universe",
            "description": "User-defined custom attack graph topology loaded via JSON file upload or raw JSON input.",
            "nodes": [],
            "relationships": [],
            "scenarios": {}
        }
    return PRESETS.get(preset_id, PRESETS["fintech_enterprise"])


def get_sample_graph_json():
    """Returns sample valid JSON template for custom graph uploads."""
    sample = {
        "nodes": [
            {
                "label": "Service",
                "properties": {
                    "name": "CustomEdgeGateway",
                    "tier": "Edge",
                    "public_facing": True,
                    "status": "HEALTHY",
                    "criticality": "HIGH"
                }
            },
            {
                "label": "Service",
                "properties": {
                    "name": "CustomBackendService",
                    "tier": "Core",
                    "public_facing": False,
                    "status": "HEALTHY",
                    "criticality": "HIGH"
                }
            },
            {
                "label": "IAMRole",
                "properties": {
                    "name": "IAMRole_CustomBackendAdmin",
                    "privilege_level": "HIGH_PRIVILEGE"
                }
            },
            {
                "label": "Database",
                "properties": {
                    "name": "CustomCrownJewelDB",
                    "crown_jewel": True,
                    "classification": "Top Secret"
                }
            }
        ],
        "relationships": [
            {
                "from": "CustomEdgeGateway",
                "rel": "CALLS",
                "to": "CustomBackendService",
                "props": {"protocol": "HTTPS"}
            },
            {
                "from": "CustomBackendService",
                "rel": "CAN_ASSUME",
                "to": "IAMRole_CustomBackendAdmin",
                "props": {"status": "PERMITTED"}
            },
            {
                "from": "IAMRole_CustomBackendAdmin",
                "rel": "ACCESSES",
                "to": "CustomCrownJewelDB",
                "props": {"status": "PERMITTED"}
            }
        ]
    }
    import json
    return json.dumps(sample, indent=2)

