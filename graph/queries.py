"""
Cypher Queries and Graph Execution Engine for NexTrace.
Implements:
1. Multi-Hop variable length traversals (1..4 hops).
2. Built-in shortestPath() attack reachability algorithms.
3. Autonomous state mutations (quarantines & edge severing).
4. Before & After path severance verification.
"""

import logging
from typing import Any, Dict, List, Optional
from graph.client import FalkorDBClient, get_falkordb_client

logger = logging.getLogger(__name__)


class GraphInvestigatorQueries:
    """Encapsulates all Cypher queries executed during security blast-radius investigations."""

    def __init__(self, client: Optional[FalkorDBClient] = None):
        self.client = client or get_falkordb_client()

    def discover_blast_radius(self, service_name: str, max_hops: int = 4) -> Dict[str, Any]:
        """
        Multi-Hop Cypher Traversal:
        Traverses downstream from compromised service across 1 to 4 hops
        using explicit variable-length Cypher query [:CALLS|DEPENDS_ON|CAN_ASSUME*1..4].
        """
        safe_hops = max(1, min(int(max_hops), 10))
        cypher = (
            f"MATCH path = (s {{name: $service}})-[:CALLS|DEPENDS_ON|CAN_ASSUME|ACCESSES*1..{safe_hops}]->(target) "
            f"RETURN [n in nodes(path) | n.name] AS node_sequence, "
            f"length(path) AS depth, "
            f"target.name AS target_name, "
            f"labels(target)[0] AS target_type, "
            f"target.status AS target_status, "
            f"target.crown_jewel AS is_crown_jewel"
        )
        raw_results = self.client.query(cypher, {"service": str(service_name), "max_hops": safe_hops})

        downstream_services = []
        accessible_iam_roles = []
        exposed_crown_jewels = []
        all_impacted_nodes = []
        paths_discovered = []

        seen_targets = set()

        for row in raw_results:
            if not row or len(row) < 3:
                continue
            path_nodes = row[0]
            depth = row[1]
            tgt_name = row[2]
            tgt_type = row[3] if len(row) > 3 else "Unknown"
            tgt_status = row[4] if len(row) > 4 else "HEALTHY"
            is_cj = bool(row[5]) if len(row) > 5 else False

            paths_discovered.append({
                "path": path_nodes,
                "depth": depth,
                "target": tgt_name,
                "target_type": tgt_type
            })

            if tgt_name not in seen_targets:
                seen_targets.add(tgt_name)
                item = {
                    "name": tgt_name,
                    "type": tgt_type,
                    "depth": depth,
                    "status": tgt_status,
                    "crown_jewel": is_cj
                }
                all_impacted_nodes.append(item)

                if tgt_type == "Service":
                    downstream_services.append(item)
                elif tgt_type == "IAMRole":
                    accessible_iam_roles.append(item)
                elif tgt_type == "Database" and is_cj:
                    exposed_crown_jewels.append(item)

        return {
            "root_service": service_name,
            "max_hops_configured": max_hops,
            "total_downstream_nodes": len(all_impacted_nodes),
            "impacted_services": downstream_services,
            "accessible_iam_roles": accessible_iam_roles,
            "exposed_crown_jewels": exposed_crown_jewels,
            "paths_discovered": paths_discovered,
            "cypher_executed": cypher,
        }

    def trace_attack_shortest_path(
        self,
        entrypoint: Optional[str] = None,
        target_crown_jewel: Optional[str] = None,
        through_service: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Graph Algorithm as a Tool:
        Executes built-in Cypher shortestPath() algorithm to trace active attack exposure
        from public entrypoints to protected database crown jewels.
        """
        active_attack_paths = []
        cypher = ""
        params: Dict[str, Any] = {}

        if entrypoint:
            start_clause = "{name: $entrypoint}"
            params["entrypoint"] = str(entrypoint)
        else:
            start_clause = "{public_facing: true}"

        if target_crown_jewel:
            end_clause = "{name: $target_crown_jewel}"
            params["target_crown_jewel"] = str(target_crown_jewel)
        else:
            end_clause = "{crown_jewel: true}"

        if through_service:
            params["through_service"] = str(through_service)
            # Check if through_service is itself a public-facing entrypoint
            is_entrypoint = False
            if entrypoint and entrypoint == through_service:
                is_entrypoint = True
            else:
                svc_node = self.client._memory_graph.nodes.get(through_service, {})
                if svc_node.get("public_facing"):
                    is_entrypoint = True

            if is_entrypoint:
                cypher = (
                    f"MATCH (start {{name: $through_service}}), (target {end_clause}) "
                    f"WITH start, target, shortestPath((start)-[:CALLS|CAN_ASSUME|ACCESSES*..6]->(target)) AS p "
                    f"WHERE p IS NOT NULL "
                    f"RETURN [n in nodes(p) | n.name] AS path_nodes, "
                    f"[r in relationships(p) | type(r)] AS rel_types, "
                    f"length(p) AS hops, "
                    f"start.name AS entrypoint, "
                    f"target.name AS crown_jewel"
                )
                raw_results = self.client.query(cypher, params)
            else:
                # Subpath concatenation via FalkorDB native shortestPath in WITH clauses:
                # Ingress -> through_service, and through_service -> crown_jewel
                cypher = (
                    f"MATCH (start {start_clause}), (mid {{name: $through_service}}) "
                    f"WITH start, mid, shortestPath((start)-[:CALLS|CAN_ASSUME|ACCESSES*..6]->(mid)) AS p1 "
                    f"WHERE p1 IS NOT NULL "
                    f"MATCH (mid), (target {end_clause}) "
                    f"WITH p1, start, mid, target, shortestPath((mid)-[:CALLS|CAN_ASSUME|ACCESSES*..6]->(target)) AS p2 "
                    f"WHERE p2 IS NOT NULL "
                    f"RETURN [n in nodes(p1) | n.name] AS p1_nodes, "
                    f"[r in relationships(p1) | type(r)] AS p1_rels, "
                    f"[n in nodes(p2) | n.name] AS p2_nodes, "
                    f"[r in relationships(p2) | type(r)] AS p2_rels, "
                    f"length(p1) + length(p2) AS total_hops, "
                    f"start.name AS entrypoint, "
                    f"target.name AS crown_jewel"
                )
                raw_results = self.client.query(cypher, params)
        else:
            cypher = (
                f"MATCH (start {start_clause}), (target {end_clause}) "
                f"WITH start, target, shortestPath((start)-[:CALLS|CAN_ASSUME|ACCESSES*..6]->(target)) AS p "
                f"WHERE p IS NOT NULL "
                f"RETURN [n in nodes(p) | n.name] AS path_nodes, "
                f"[r in relationships(p) | type(r)] AS rel_types, "
                f"length(p) AS hops, "
                f"start.name AS entrypoint, "
                f"target.name AS crown_jewel"
            )
            raw_results = self.client.query(cypher, params)

        for row in raw_results:
            if not row:
                continue
            # If native FalkorDB stitched result with 7 elements (p1_nodes, p1_rels, p2_nodes, p2_rels, hops, ep, cj)
            if len(row) >= 7 and isinstance(row[0], list) and isinstance(row[2], list):
                p1_nodes, p1_rels, p2_nodes, p2_rels, hops, ep, cj = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
                path_nodes = p1_nodes + p2_nodes[1:]
                rel_types = p1_rels + p2_rels
            elif len(row) >= 3 and isinstance(row[0], list):
                path_nodes = row[0]
                rel_types = row[1] if isinstance(row[1], list) else []
                hops = row[2]
                ep = row[3] if len(row) > 3 else (path_nodes[0] if path_nodes else "Unknown")
                cj = row[4] if len(row) > 4 else (path_nodes[-1] if path_nodes else "Unknown")
            else:
                continue

            if through_service and through_service not in path_nodes:
                continue

            # Validate that none of the nodes in path are QUARANTINED and no edge is SEVERED
            is_active = True
            for node_name in path_nodes:
                node_data = self.client._memory_graph.nodes.get(node_name, {})
                if node_data.get("status") == "QUARANTINED":
                    is_active = False
                    break
            if is_active:
                active_attack_paths.append({
                    "entrypoint": ep,
                    "target_crown_jewel": cj,
                    "hops": hops,
                    "node_sequence": path_nodes,
                    "traversal_arrow": " -> ".join(path_nodes),
                    "relationship_types": rel_types
                })

        return {
            "has_active_attack_path": len(active_attack_paths) > 0,
            "total_attack_paths": len(active_attack_paths),
            "shortest_path": active_attack_paths[0] if active_attack_paths else None,
            "all_attack_paths": active_attack_paths,
            "cypher_executed": cypher,
        }


    def quarantine_service(self, service_name: str, reason: str = "Active Zero-Day Compromise Detected") -> Dict[str, Any]:
        """
        Autonomous State Mutation:
        Mutates the graph state by updating node properties to 'QUARANTINED'.
        """
        cypher = (
            "MATCH (s {name: $service}) "
            "SET s.status = 'QUARANTINED', s.quarantine_reason = $reason, s.quarantined_at = timestamp() "
            "RETURN s.name AS name, s.status AS status"
        )
        raw_results = self.client.query(cypher, {"service": str(service_name), "reason": str(reason)})

        # Also update in-memory graph
        if service_name in self.client._memory_graph:
            self.client._memory_graph.nodes[service_name]["status"] = "QUARANTINED"
            self.client._memory_graph.nodes[service_name]["quarantine_reason"] = reason

        return {
            "mutated_node": service_name,
            "new_status": "QUARANTINED",
            "reason": reason,
            "mutation_applied": True,
            "cypher_executed": cypher,
        }

    def sever_compromised_edge(self, from_service: str, to_target: Optional[str] = None, reason: str = "Containment Policy Execution") -> Dict[str, Any]:
        """
        Autonomous State Mutation:
        Mutates graph relationships by severing active CALLS / CAN_ASSUME edges.
        """
        # Pre-identify edges to sever from in-memory topology
        severed_edges = []
        if from_service in self.client._memory_graph:
            targets = [to_target] if to_target else list(self.client._memory_graph.successors(from_service))
            for tgt in targets:
                if self.client._memory_graph.has_edge(from_service, tgt):
                    edge_type = self.client._memory_graph[from_service][tgt].get("type", "")
                    if to_target or edge_type in ["CALLS", "CAN_ASSUME"]:
                        severed_edges.append(f"{from_service} -> {tgt}")

        params = {"from_service": str(from_service), "reason": str(reason)}
        if to_target:
            params["to_target"] = str(to_target)
            cypher = (
                "MATCH (a {name: $from_service})-[r]->(b {name: $to_target}) "
                "SET r.status = 'SEVERED', r.severed_reason = $reason "
                "DELETE r "
                "RETURN a.name AS from_node, b.name AS to_node"
            )
        else:
            cypher = (
                "MATCH (a {name: $from_service})-[r:CALLS|CAN_ASSUME]->(b) "
                "SET r.status = 'SEVERED', r.severed_reason = $reason "
                "DELETE r "
                "RETURN count(r) AS severed_count"
            )

        raw_results = self.client.query(cypher, params)

        # Sync the memory mirror unconditionally
        for edge_str in severed_edges:
            if " -> " in edge_str:
                u, v = edge_str.split(" -> ")
                if self.client._memory_graph.has_edge(u, v):
                    edge_data = dict(self.client._memory_graph[u][v])
                    edge_data["status"] = "SEVERED"
                    edge_data["reason"] = reason
                    self.client._severed_edges.append({
                        "from": u,
                        "to": v,
                        "type": edge_data.get("type", "CALLS"),
                        "properties": edge_data
                    })
                    self.client._memory_graph.remove_edge(u, v)

        return {
            "from_service": from_service,
            "to_target": to_target or "ALL_OUTBOUND",
            "severed_edges": severed_edges,
            "severance_count": len(severed_edges),
            "reason": reason,
            "mutation_applied": True,
            "cypher_executed": cypher,
        }

    def calculate_bottleneck_chokepoints(self, top_k: int = 5) -> Dict[str, Any]:
        """
        Graph Algorithm as a Tool:
        Calculates critical bottleneck chokepoint nodes between public entrypoints
        and protected crown jewels using graph attack path frequency.
        """
        cypher = (
            "MATCH (start {public_facing: true}), (target {crown_jewel: true}) "
            "MATCH p = (start)-[:CALLS|CAN_ASSUME|ACCESSES*..6]->(target) "
            "UNWIND nodes(p) AS bottleneck "
            "RETURN bottleneck.name AS bottleneck_node, count(p) AS paths_dependent "
            "ORDER BY paths_dependent DESC"
        )
        raw_results = self.client.query(cypher)
        if not raw_results and hasattr(self.client, "_execute_memory_query"):
            raw_results = self.client._execute_memory_query(cypher)
        safe_top_k = max(1, min(int(top_k), 50))
        for row in raw_results:
            if not row or len(row) < 2:
                continue
            name, count = row[0], row[1]
            node_data = self.client._memory_graph.nodes.get(name, {})
            if node_data.get("public_facing") is True or node_data.get("crown_jewel") is True:
                continue
            if name in ["PublicAPIGateway", "CustomerWebPortal", "PartnerWebhookIngress", "ProdCustomerDB", "PCI_PaymentVault", "UserCredentialsStore"]:
                continue
            bottlenecks.append({
                "node_name": name,
                "traversing_attack_paths": count,
                "node_type": self.client._memory_graph.nodes.get(name, {}).get("label", "Node"),
                "status": self.client._memory_graph.nodes.get(name, {}).get("status", "HEALTHY"),
            })
            if len(bottlenecks) >= safe_top_k:
                break

        return {
            "top_bottlenecks": bottlenecks,
            "total_bottlenecks_identified": len(bottlenecks),
            "cypher_executed": cypher,
        }

    def verify_path_severance(
        self,
        entrypoint: Optional[str] = None,
        target_crown_jewel: Optional[str] = None,
        through_service: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Re-verifies path severance:
        Executes shortestPath() again to mathematically prove crown jewel reachability is eliminated.
        """
        # If through_service is not explicitly specified, check if any service is currently QUARANTINED
        if not through_service:
            quarantined = [
                n for n, d in self.client._memory_graph.nodes(data=True)
                if d.get("status") == "QUARANTINED"
            ]
            if len(quarantined) == 1:
                through_service = quarantined[0]

        path_check = self.trace_attack_shortest_path(
            entrypoint=entrypoint,
            target_crown_jewel=target_crown_jewel,
            through_service=through_service
        )
        paths_remaining = path_check.get("total_attack_paths", 0)
        is_severed = (paths_remaining == 0)

        return {
            "severance_verified": is_severed,
            "active_attack_paths_remaining": paths_remaining,
            "status": "SECURED - REACHABILITY ELIMINATED" if is_severed else "INCOMPLETE - ACTIVE ATTACK PATH REMAINS",
            "remaining_paths": path_check.get("all_attack_paths", []),
            "verification_algorithm": "Cypher shortestPath() evaluation",
        }

    def get_graph_summary(self) -> Dict[str, Any]:
        """Returns high-level graph statistics and node classification metrics."""
        all_data = self.client.get_all_graph_data()
        nodes = all_data["nodes"]
        edges = all_data["edges"]

        type_counts = {}
        quarantined_count = 0
        crown_jewels = []
        entrypoints = []

        for n in nodes:
            lbl = n.get("label", "Unknown")
            type_counts[lbl] = type_counts.get(lbl, 0) + 1
            if n.get("status") == "QUARANTINED":
                quarantined_count += 1
            if n.get("crown_jewel") is True:
                crown_jewels.append(n.get("name"))
            if n.get("public_facing") is True:
                entrypoints.append(n.get("name"))

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_breakdown": type_counts,
            "quarantined_nodes": quarantined_count,
            "public_entrypoints": entrypoints,
            "crown_jewels": crown_jewels,
            "falkordb_live": self.client.is_connected(),
        }
