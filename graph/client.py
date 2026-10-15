"""
FalkorDB Client Wrapper.
Provides robust FalkorDB connectivity with graph seeding, query execution,
and an in-memory graph fallback mirror for resilient offline/hybrid operation.
"""

import time
import logging
from typing import Any, Dict, List, Optional
import networkx as nx

from config import (
    FALKORDB_HOST,
    FALKORDB_PORT,
    FALKORDB_GRAPH,
    FALKORDB_PASSWORD,
    FALKORDB_USERNAME,
    FALKORDB_SSL,
)
from graph.seed_data import (
    NODES,
    RELATIONSHIPS,
    PRESETS,
    get_preset,
    normalize_graph_json,
    validate_graph_data,
)

logger = logging.getLogger(__name__)


class FalkorDBClient:
    """Manages FalkorDB connection and graph state."""

    def __init__(
        self,
        host: str = FALKORDB_HOST,
        port: int = FALKORDB_PORT,
        graph_name: str = FALKORDB_GRAPH,
        password: Optional[str] = FALKORDB_PASSWORD,
        username: Optional[str] = FALKORDB_USERNAME,
        ssl: bool = FALKORDB_SSL,
    ):
        self.host = host
        self.port = port
        self.graph_name = graph_name
        self.password = password
        self.username = username
        self.ssl = ssl
        self.driver = None
        self.graph = None
        self._connected = False
        self._last_conn_check = 0.0
        self._memory_graph = nx.DiGraph()
        self._severed_edges: List[Dict[str, Any]] = []
        self._active_preset: str = "fintech_enterprise"
        self._current_nodes: List[Dict[str, Any]] = list(NODES)
        self._current_relationships: List[Dict[str, Any]] = list(RELATIONSHIPS)
        self._init_connection()
        self._seed_memory_graph()

    def _init_connection(self) -> bool:
        self._last_conn_check = time.time()
        try:
            from falkordb import FalkorDB
            self.driver = FalkorDB(
                host=self.host,
                port=self.port,
                password=self.password,
                username=self.username,
                ssl=self.ssl,
                socket_connect_timeout=1.0,
                socket_timeout=2.0,
            )
            self.graph = self.driver.select_graph(self.graph_name)
            self.graph.query("RETURN 1 AS ping")
            self._connected = True
            logger.info("Connected successfully to FalkorDB at %s:%s (Graph: %s)", self.host, self.port, self.graph_name)
            return True
        except Exception as e:
            self._connected = False
            self.driver = None
            self.graph = None
            logger.warning("FalkorDB not reachable at %s:%s (%s). Using in-memory graph engine mirror.", self.host, self.port, e)
            return False

    def is_connected(self) -> bool:
        """Check if live FalkorDB instance is currently active with throttled checks."""
        now = time.time()
        if not self._connected:
            if now - self._last_conn_check > 5.0:
                return self._init_connection()
            return False
        try:
            self.graph.query("RETURN 1 AS ping")
            return True
        except Exception:
            self._connected = False
            return False

    def _seed_memory_graph(
        self,
        nodes: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None
    ):
        """Populates the in-memory graph mirror with active or provided nodes and edges."""
        self._memory_graph.clear()
        self._severed_edges.clear()
        target_nodes = nodes if nodes is not None else self._current_nodes
        target_rels = relationships if relationships is not None else self._current_relationships

        for node in target_nodes:
            props = dict(node.get("properties", {}))
            props["label"] = node.get("label", "Node")
            if "name" not in props and "name" in node:
                props["name"] = node["name"]
            node_name = props.get("name", "Unknown")
            self._memory_graph.add_node(node_name, **props)

        for edge in target_rels:
            from_node = edge.get("from") or edge.get("source")
            to_node = edge.get("to") or edge.get("target")
            rel_type = edge.get("rel") or edge.get("type") or "CALLS"
            props = dict(edge.get("props") or edge.get("properties") or {})
            if from_node and to_node:
                self._memory_graph.add_edge(
                    from_node,
                    to_node,
                    type=rel_type,
                    **props
                )

    def seed_database(
        self,
        nodes: Optional[List[Dict[str, Any]]] = None,
        relationships: Optional[List[Dict[str, Any]]] = None,
        preset_name: Optional[str] = None,
        force: bool = True,
        custom_nodes: Optional[List[Dict[str, Any]]] = None,
        custom_relationships: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Seeds the enterprise or custom graph into FalkorDB and the in-memory mirror."""
        if custom_nodes is not None and nodes is None:
            nodes = custom_nodes
        if custom_relationships is not None and relationships is None:
            relationships = custom_relationships

        if nodes is not None and relationships is not None:
            self._active_preset = "custom"
            self._current_nodes = list(nodes)
            self._current_relationships = list(relationships)
            self._custom_nodes = list(nodes)
            self._custom_relationships = list(relationships)
        elif preset_name and preset_name in PRESETS:
            preset = get_preset(preset_name)
            self._active_preset = preset.get("id", preset_name)
            self._current_nodes = list(preset.get("nodes", []))
            self._current_relationships = list(preset.get("relationships", []))
        elif (preset_name == "custom" or self._active_preset == "custom") and hasattr(self, "_custom_nodes") and self._custom_nodes:
            self._active_preset = "custom"
            self._current_nodes = list(self._custom_nodes)
            self._current_relationships = list(self._custom_relationships)
        elif preset_name:
            preset = get_preset(preset_name)
            self._active_preset = preset.get("id", preset_name)
            self._current_nodes = list(preset.get("nodes", []))
            self._current_relationships = list(preset.get("relationships", []))
        else:
            self._active_preset = "fintech_enterprise"
            self._current_nodes = list(NODES)
            self._current_relationships = list(RELATIONSHIPS)

        self._seed_memory_graph(self._current_nodes, self._current_relationships)

        falkor_success = False
        nodes_created = 0
        rels_created = 0

        if self.is_connected():
            try:
                if force:
                    try:
                        self.graph.query("MATCH (n) DETACH DELETE n")
                    except Exception:
                        pass
                    try:
                        self.graph.delete()
                    except Exception:
                        pass
                    self.graph = self.driver.select_graph(self.graph_name)

                # Batch create nodes
                for node in self._current_nodes:
                    label = node.get("label", "Node")
                    props = dict(node.get("properties", {}))
                    if "name" not in props and "name" in node:
                        props["name"] = node["name"]
                    prop_strs = []
                    for k, v in props.items():
                        if isinstance(v, str):
                            escaped = v.replace("'", "\\'")
                            prop_strs.append(f"{k}: '{escaped}'")
                        elif isinstance(v, bool):
                            prop_strs.append(f"{k}: {'true' if v else 'false'}")
                        elif isinstance(v, (int, float)):
                            prop_strs.append(f"{k}: {v}")
                    props_cypher = "{" + ", ".join(prop_strs) + "}"
                    cypher = f"CREATE (n:{label} {props_cypher})"
                    self.graph.query(cypher)
                    nodes_created += 1

                # Create relationships
                for edge in self._current_relationships:
                    from_node = edge.get("from") or edge.get("source") or ""
                    to_node = edge.get("to") or edge.get("target") or ""
                    from_escaped = str(from_node).replace("'", "\\'")
                    to_escaped = str(to_node).replace("'", "\\'")
                    rel_type = edge.get("rel") or edge.get("type") or "CALLS"
                    props = edge.get("props") or edge.get("properties") or {}
                    prop_strs = []
                    for k, v in props.items():
                        if isinstance(v, str):
                            escaped = v.replace("'", "\\'")
                            prop_strs.append(f"{k}: '{escaped}'")
                        elif isinstance(v, bool):
                            prop_strs.append(f"{k}: {'true' if v else 'false'}")
                        elif isinstance(v, (int, float)):
                            prop_strs.append(f"{k}: {v}")
                        elif isinstance(v, list):
                            escaped_items = [f"'{str(x).replace(chr(39), chr(92) + chr(39))}'" for x in v]
                            arr_str = "[" + ", ".join(escaped_items) + "]"
                            prop_strs.append(f"{k}: {arr_str}")
                    props_cypher = " {" + ", ".join(prop_strs) + "}" if prop_strs else ""

                    cypher = (
                        f"MATCH (a {{name: '{from_escaped}'}}), (b {{name: '{to_escaped}'}}) "
                        f"CREATE (a)-[r:{rel_type}{props_cypher}]->(b)"
                    )
                    self.graph.query(cypher)
                    rels_created += 1

                falkor_success = True
            except Exception as e:
                logger.error("Error seeding FalkorDB: %s", e)
                falkor_success = False
                self._connected = False

        return {
            "status": "success",
            "falkordb_seeded": falkor_success,
            "memory_seeded": True,
            "total_nodes": len(self._current_nodes),
            "total_relationships": len(self._current_relationships),
            "preset": self._active_preset,
        }

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[List[Any]]:
        """Executes Cypher on FalkorDB if connected, with fallback to in-memory evaluation."""
        if self.is_connected():
            try:
                res = self.graph.query(cypher, params)
                results = res.result_set if hasattr(res, "result_set") else []
                if results or not self._memory_graph.nodes:
                    return results
                mem_results = self._execute_memory_query(cypher, params)
                return mem_results if mem_results else results
            except Exception as e:
                self._connected = False
                logger.warning("FalkorDB query error: %s. Falling back to memory engine.", e)

        return self._execute_memory_query(cypher, params)

    def _execute_memory_query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[List[Any]]:
        """Evaluates Cypher queries on the in-memory graph mirror."""
        cypher_upper = cypher.upper()

        # 1. Bottleneck node analysis: UNWIND nodes(p) AS bottleneck OR BOTTLENECK
        if "BOTTLENECK" in cypher_upper or ("UNWIND" in cypher_upper and "NODES" in cypher_upper):
            entrypoints = [n for n, d in self._memory_graph.nodes(data=True) if d.get("public_facing") is True]
            if not entrypoints:
                entrypoints = [n for n in self._memory_graph.nodes if self._memory_graph.in_degree(n) == 0] or list(self._memory_graph.nodes)[:1]
            crown_jewels = [n for n, d in self._memory_graph.nodes(data=True) if d.get("crown_jewel") is True]
            if not crown_jewels:
                crown_jewels = [n for n in self._memory_graph.nodes if self._memory_graph.out_degree(n) == 0 and n not in entrypoints] or list(self._memory_graph.nodes)[-1:]
            node_counts: Dict[str, int] = {}
            for ep in entrypoints:
                for cj in crown_jewels:
                    try:
                        for p in nx.all_shortest_paths(self._memory_graph, ep, cj):
                            for node in p[1:-1]:  # exclude ep and cj themselves
                                node_counts[node] = node_counts.get(node, 0) + 1
                    except Exception:
                        continue
            sorted_bottlenecks = sorted(node_counts.items(), key=lambda x: x[1], reverse=True)
            return [[name, count] for name, count in sorted_bottlenecks]

        # 2. shortestPath() algorithm (check next so variable-length hops do not intercept)
        if "SHORTESTPATH" in cypher_upper:
            import re
            ep_match = re.search(r"start(?::\w+)?\s*\{name:\s*['\"]([^'\"]+)['\"]\}", cypher)
            target_match = re.search(r"target(?::\w+)?\s*\{name:\s*['\"]([^'\"]+)['\"]\}", cypher)

            # Check for through_service in WHERE clause, mid node, or params
            through_service = None
            through_match = re.search(r"n\.name\s*=\s*['\"]([^'\"]+)['\"]", cypher)
            if through_match:
                through_service = through_match.group(1)
            else:
                mid_match = re.search(r"mid(?::\w+)?\s*\{name:\s*['\"]([^'\"]+)['\"]\}", cypher)
                if mid_match:
                    through_service = mid_match.group(1)
            if not through_service and params and "through_service" in params:
                through_service = params["through_service"]

            if ep_match:
                entrypoints = [ep_match.group(1)]
            else:
                entrypoints = [n for n, d in self._memory_graph.nodes(data=True) if d.get("public_facing") is True]
                if not entrypoints:
                    entrypoints = [n for n in self._memory_graph.nodes if self._memory_graph.in_degree(n) == 0] or list(self._memory_graph.nodes)[:1]

            if target_match:
                crown_jewels = [target_match.group(1)]
            else:
                crown_jewels = [n for n, d in self._memory_graph.nodes(data=True) if d.get("crown_jewel") is True]
                if not crown_jewels:
                    crown_jewels = [n for n in self._memory_graph.nodes if self._memory_graph.out_degree(n) == 0 and n not in entrypoints] or list(self._memory_graph.nodes)[-1:]

            # Active subgraph excluding quarantined nodes and severed edges
            active_subgraph = nx.DiGraph()
            for node, data in self._memory_graph.nodes(data=True):
                if data.get("status") != "QUARANTINED":
                    active_subgraph.add_node(node, **data)

            for u, v, d in self._memory_graph.edges(data=True):
                if d.get("status") != "SEVERED":
                    if u in active_subgraph and v in active_subgraph:
                        active_subgraph.add_edge(u, v, **d)

            results = []
            for ep in entrypoints:
                for cj in crown_jewels:
                    if ep not in active_subgraph or cj not in active_subgraph:
                        continue
                    try:
                        if through_service:
                            if through_service not in active_subgraph:
                                continue
                            if ep == through_service:
                                if nx.has_path(active_subgraph, through_service, cj):
                                    path = nx.shortest_path(active_subgraph, through_service, cj)
                                else:
                                    continue
                            elif cj == through_service:
                                if nx.has_path(active_subgraph, ep, through_service):
                                    path = nx.shortest_path(active_subgraph, ep, through_service)
                                else:
                                    continue
                            else:
                                if nx.has_path(active_subgraph, ep, through_service) and nx.has_path(active_subgraph, through_service, cj):
                                    p1 = nx.shortest_path(active_subgraph, ep, through_service)
                                    p2 = nx.shortest_path(active_subgraph, through_service, cj)
                                    path = p1[:-1] + p2
                                else:
                                    continue
                        else:
                            if nx.has_path(active_subgraph, ep, cj):
                                path = nx.shortest_path(active_subgraph, ep, cj)
                            else:
                                continue

                        hops = len(path) - 1
                        rel_types = []
                        for i in range(hops):
                            edge_d = active_subgraph.get_edge_data(path[i], path[i+1]) or {}
                            rel_types.append(edge_d.get("type", "CALLS"))
                        results.append([path, rel_types, hops, ep, cj])
                    except Exception:
                        continue

            results.sort(key=lambda x: x[2])
            return results

        # 2. Multi-Hop variable length blast radius: MATCH path = (s {name: ...})-[*1..4]->(target)
        if "MATCH" in cypher_upper and ("*1.." in cypher or "*..4" in cypher or "*1..4" in cypher or "*1..3" in cypher or "*1..2" in cypher or "*1..1" in cypher or "*.." in cypher or "*1" in cypher):
            import re
            m = re.search(r"name:\s*['\"]([^'\"]+)['\"]", cypher)
            start_name = m.group(1) if m else (params.get("service") if params else None)
            if not start_name:
                for node in self._memory_graph.nodes:
                    if node.lower() in cypher.lower():
                        start_name = node
                        break

            # Parse min_hops and max_hops
            min_hops = 1
            max_hops = 4
            hop_match = re.search(r"\*(\d*)\.\.(\d+)", cypher)
            if hop_match:
                if hop_match.group(1):
                    min_hops = int(hop_match.group(1))
                if hop_match.group(2):
                    max_hops = int(hop_match.group(2))
            elif params and "max_hops" in params:
                max_hops = int(params["max_hops"])

            # Parse allowed relationship types if specified
            rel_filter = None
            rel_match = re.search(r"-\[:([A-Z_|]+)\*", cypher)
            if rel_match:
                rel_filter = set(rel_match.group(1).split("|"))

            if start_name and start_name in self._memory_graph:
                results = []
                visited = set([start_name])
                queue = [(start_name, 0, [start_name])]
                while queue:
                    curr, depth, path = queue.pop(0)
                    if min_hops <= depth <= max_hops:
                        curr_node_data = self._memory_graph.nodes[curr]
                        results.append([
                            path,
                            depth,
                            curr,
                            curr_node_data.get("label", "Node"),
                            curr_node_data.get("status", "HEALTHY"),
                            curr_node_data.get("crown_jewel", False)
                        ])
                    if depth < max_hops:
                        for neighbor in self._memory_graph.successors(curr):
                            edge_data = self._memory_graph.get_edge_data(curr, neighbor) or {}
                            rel_type = edge_data.get("type", "")
                            if rel_filter and rel_type not in rel_filter:
                                continue
                            if neighbor not in visited:
                                visited.add(neighbor)
                                queue.append((neighbor, depth + 1, path + [neighbor]))
                return results

        # 3. SET service.status = 'QUARANTINED'
        if "SET" in cypher_upper and "QUARANTINED" in cypher_upper:
            import re
            m = re.search(r"name:\s*['\"]([^'\"]+)['\"]", cypher)
            node_name = m.group(1) if m else (params.get("service") if params else None)
            if node_name and node_name in self._memory_graph:
                self._memory_graph.nodes[node_name]["status"] = "QUARANTINED"
                return [[node_name, "QUARANTINED"]]

        # 4. DELETE / Sever edge
        if "DELETE" in cypher_upper or ("SET" in cypher_upper and "SEVERED" in cypher_upper):
            import re
            names = re.findall(r"name:\s*['\"]([^'\"]+)['\"]", cypher)
            if len(names) >= 2:
                from_node, to_node = names[0], names[1]
                if self._memory_graph.has_edge(from_node, to_node):
                    edge_data = dict(self._memory_graph[from_node][to_node])
                    edge_data["status"] = "SEVERED"
                    self._severed_edges.append({
                        "from": from_node,
                        "to": to_node,
                        "type": edge_data.get("type", "CALLS"),
                        "properties": edge_data
                    })
                    self._memory_graph.remove_edge(from_node, to_node)
                    return [[from_node, to_node]]
            elif len(names) == 1:
                from_node = names[0]
                if from_node in self._memory_graph:
                    rel_filter = None
                    m_rel = re.search(r"-\[r:([A-Z_|]+)\]->", cypher)
                    if m_rel:
                        rel_filter = set(m_rel.group(1).split("|"))
                    severed_count = 0
                    for u, v in list(self._memory_graph.out_edges(from_node)):
                        edge_data = dict(self._memory_graph[u][v])
                        edge_type = edge_data.get("type", "")
                        if not rel_filter or edge_type in rel_filter:
                            edge_data["status"] = "SEVERED"
                            self._severed_edges.append({
                                "from": u,
                                "to": v,
                                "type": edge_type,
                                "properties": edge_data
                            })
                            self._memory_graph.remove_edge(u, v)
                            severed_count += 1
                    return [[from_node, severed_count]]

        # 5. Bottleneck node analysis: UNWIND nodes(p) AS bottleneck
        if "BOTTLENECK" in cypher_upper or ("UNWIND" in cypher_upper and "NODES" in cypher_upper):
            entrypoints = [n for n, d in self._memory_graph.nodes(data=True) if d.get("public_facing") is True]
            crown_jewels = [n for n, d in self._memory_graph.nodes(data=True) if d.get("crown_jewel") is True]
            node_counts: Dict[str, int] = {}
            for ep in entrypoints:
                for cj in crown_jewels:
                    try:
                        for p in nx.all_shortest_paths(self._memory_graph, ep, cj):
                            for node in p[1:-1]:  # exclude ep and cj themselves
                                node_counts[node] = node_counts.get(node, 0) + 1
                    except Exception:
                        continue
            sorted_bottlenecks = sorted(node_counts.items(), key=lambda x: x[1], reverse=True)
            return [[name, count] for name, count in sorted_bottlenecks]

        # 6. Graph overview count
        if "COUNT" in cypher_upper:
            return [[len(self._memory_graph.nodes), len(self._memory_graph.edges)]]

        return []

    def get_all_graph_data(self) -> Dict[str, Any]:
        """Returns all nodes and edges formatted for visualizers and graph inspectors."""
        nodes_data = []
        edges_data = []

        if self.is_connected():
            try:
                node_query = "MATCH (n) RETURN labels(n)[0] AS label, n.name AS name, properties(n) AS props"
                n_res = self.graph.query(node_query).result_set
                for row in n_res:
                    lbl, name, props = row[0], row[1], row[2]
                    props_dict = dict(props) if isinstance(props, dict) else {}
                    props_dict["label"] = lbl
                    props_dict["name"] = name
                    nodes_data.append(props_dict)

                edge_query = "MATCH (a)-[r]->(b) RETURN a.name AS from_node, type(r) AS rel_type, b.name AS to_node, properties(r) AS props"
                e_res = self.graph.query(edge_query).result_set
                for row in e_res:
                    u, rel_type, v, props = row[0], row[1], row[2], row[3]
                    props_dict = dict(props) if isinstance(props, dict) else {}
                    edges_data.append({
                        "from": u,
                        "to": v,
                        "label": rel_type,
                        "properties": props_dict
                    })
                for se in self._severed_edges:
                    edges_data.append({
                        "from": se["from"],
                        "to": se["to"],
                        "label": se.get("type", "CONNECTED_TO"),
                        "properties": dict(se.get("properties", {"status": "SEVERED"}))
                    })
                return {"nodes": nodes_data, "edges": edges_data}
            except Exception as e:
                logger.warning("FalkorDB fetch failed: %s. Using memory snapshot.", e)

        for node, data in self._memory_graph.nodes(data=True):
            d = dict(data)
            d["name"] = node
            nodes_data.append(d)

        for u, v, data in self._memory_graph.edges(data=True):
            edges_data.append({
                "from": u,
                "to": v,
                "label": data.get("type", "CONNECTED_TO"),
                "properties": dict(data)
            })

        # Also include severed edges with SEVERED status so visualizers highlight them
        for se in self._severed_edges:
            edges_data.append({
                "from": se["from"],
                "to": se["to"],
                "label": se.get("type", "CONNECTED_TO"),
                "properties": dict(se.get("properties", {"status": "SEVERED"}))
            })

        return {"nodes": nodes_data, "edges": edges_data}


_client_instance = None

def get_falkordb_client() -> FalkorDBClient:
    global _client_instance
    if _client_instance is None:
        _client_instance = FalkorDBClient()
    return _client_instance
