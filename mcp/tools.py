"""
Standardized Model Context Protocol (MCP) Tool Definitions.
Adheres to the official Model Context Protocol (MCP) Tool Specification.
"""

from typing import Any, Dict, List, Optional
from graph.queries import GraphInvestigatorQueries


MCP_TOOL_DEFINITIONS = [
    {
        "name": "mcp_query_blast_radius",
        "description": "Discovers downstream impacted microservices, accessible IAM roles, and exposed crown jewel databases across 1 to 4 hops using variable-length Cypher traversal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "The exact name of the compromised or alerted service (e.g. 'AuthService').",
                },
                "max_hops": {
                    "type": "integer",
                    "description": "Traversal depth (2 to 4 hops). Default is 4.",
                    "default": 4,
                    "minimum": 1,
                    "maximum": 5,
                },
            },
            "required": ["service_name"],
        },
    },
    {
        "name": "mcp_trace_attack_shortest_path",
        "description": "Executes FalkorDB's built-in shortestPath() Cypher graph algorithm to identify attack exposure paths from public ingress entrypoints to protected crown jewel databases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entrypoint": {
                    "type": "string",
                    "description": "Optional specific entrypoint service (e.g. 'PublicAPIGateway'). If omitted, checks all public-facing services.",
                },
                "target_crown_jewel": {
                    "type": "string",
                    "description": "Optional specific crown jewel database (e.g. 'ProdCustomerDB'). If omitted, checks all crown jewels.",
                },
                "through_service": {
                    "type": "string",
                    "description": "Optional intermediate service to trace exposure through (e.g. 'AuthService' or 'OrderService').",
                },
            },
        },
    },
    {
        "name": "mcp_quarantine_service",
        "description": "Autonomous state mutation tool that updates node status to QUARANTINED in FalkorDB, isolating compromised workloads from the mesh.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "The service name to quarantine in the graph.",
                },
                "reason": {
                    "type": "string",
                    "description": "Incident reason for quarantine (e.g. 'Active Zero-Day CVE-2024-3094 exploit').",
                },
            },
            "required": ["service_name"],
        },
    },
    {
        "name": "mcp_sever_compromised_edge",
        "description": "Autonomous state mutation tool that severs vulnerable network communication or IAM permission edges in FalkorDB, cutting off lateral movement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_service": {
                    "type": "string",
                    "description": "The source service whose outbound communication should be severed.",
                },
                "to_target": {
                    "type": "string",
                    "description": "Optional specific target node. If omitted, severs all outbound CALLS and CAN_ASSUME edges.",
                },
                "reason": {
                    "type": "string",
                    "description": "Policy enforcement reason for severing edge.",
                },
            },
            "required": ["from_service"],
        },
    },
    {
        "name": "mcp_verify_path_severance",
        "description": "Re-runs shortestPath() Cypher algorithm to mathematically verify that all attack paths between public ingress and crown jewels have been eliminated.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entrypoint": {
                    "type": "string",
                    "description": "Entrypoint to re-check. Default is all public services.",
                },
                "target_crown_jewel": {
                    "type": "string",
                    "description": "Crown jewel to re-check. Default is all crown jewels.",
                },
                "through_service": {
                    "type": "string",
                    "description": "Compromised service to verify attack elimination through.",
                },
            },
        },
    },
    {
        "name": "mcp_calculate_chokepoints",
        "description": "Calculates critical graph bottleneck nodes (chokepoints) that lie on the most attack paths connecting public entrypoints to protected crown jewel databases.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "top_k": {
                    "type": "integer",
                    "description": "Number of top bottleneck nodes to return (default 5).",
                    "default": 5,
                },
            },
        },
    },
    {
        "name": "mcp_get_graph_summary",
        "description": "Retrieves the enterprise cloud graph topology summary, including node counts, entrypoints, crown jewels, and quarantined nodes.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def execute_mcp_tool(tool_name: str, arguments: Dict[str, Any], queries_engine: Optional[GraphInvestigatorQueries] = None) -> Dict[str, Any]:
    """Dispatches tool execution by name conforming to MCP specification."""
    engine = queries_engine or GraphInvestigatorQueries()

    if tool_name == "mcp_query_blast_radius":
        service_name = arguments.get("service_name")
        max_hops = int(arguments.get("max_hops", 4))
        return engine.discover_blast_radius(service_name=service_name, max_hops=max_hops)

    elif tool_name == "mcp_trace_attack_shortest_path":
        entrypoint = arguments.get("entrypoint")
        target_crown_jewel = arguments.get("target_crown_jewel")
        through_service = arguments.get("through_service")
        return engine.trace_attack_shortest_path(entrypoint=entrypoint, target_crown_jewel=target_crown_jewel, through_service=through_service)

    elif tool_name == "mcp_quarantine_service":
        service_name = arguments.get("service_name")
        reason = arguments.get("reason", "Autonomous containment action")
        return engine.quarantine_service(service_name=service_name, reason=reason)

    elif tool_name == "mcp_sever_compromised_edge":
        from_service = arguments.get("from_service")
        to_target = arguments.get("to_target")
        reason = arguments.get("reason", "Edge severance containment")
        return engine.sever_compromised_edge(from_service=from_service, to_target=to_target, reason=reason)

    elif tool_name == "mcp_verify_path_severance":
        entrypoint = arguments.get("entrypoint")
        target_crown_jewel = arguments.get("target_crown_jewel")
        through_service = arguments.get("through_service")
        return engine.verify_path_severance(entrypoint=entrypoint, target_crown_jewel=target_crown_jewel, through_service=through_service)

    elif tool_name == "mcp_calculate_chokepoints":
        top_k = int(arguments.get("top_k", 5))
        return engine.calculate_bottleneck_chokepoints(top_k=top_k)

    elif tool_name == "mcp_get_graph_summary":
        return engine.get_graph_summary()

    else:
        raise ValueError(f"Unknown MCP tool: {tool_name}")
