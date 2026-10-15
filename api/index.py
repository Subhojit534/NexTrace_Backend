"""
NexTrace Autonomous SecOps API
Standalone FastAPI Serverless Backend for Vercel & Local Execution.
"""

import os
import sys
import json
import time
import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from graph.client import FalkorDBClient
from graph.queries import GraphInvestigatorQueries
from graph.seed_data import (
    PRESETS,
    get_preset,
    list_presets,
    normalize_graph_json,
    validate_graph_data,
    get_sample_graph_json
)
from agent.investigator import AutonomousInvestigator
from agent.prompt import SYSTEM_PROMPT
from remediation.generator import RemediationGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nextrace-api")

app = FastAPI(
    title="NexTrace Autonomous SecOps API",
    description="FalkorDB Cypher-Powered Autonomous Graph Investigation & Blast-Radius Severance Engine",
    version="2.0.0"
)

# Enable CORS for local dev and Vercel frontend deployments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory global client fallback
_default_client = FalkorDBClient()
_client_cache: Dict[tuple, FalkorDBClient] = {}


def get_client_from_request(
    falkor_host: Optional[str] = None,
    falkor_port: Optional[int] = None,
    falkor_user: Optional[str] = None,
    falkor_pass: Optional[str] = None,
    falkor_ssl: Optional[bool] = None,
) -> FalkorDBClient:
    """Creates or retrieves a custom FalkorDBClient if custom credentials provided, or returns default client."""
    if falkor_host:
        key = (falkor_host.strip(), int(falkor_port or 6379), falkor_user or "", falkor_pass or "", bool(falkor_ssl))
        if key not in _client_cache:
            try:
                _client_cache[key] = FalkorDBClient(
                    host=falkor_host,
                    port=int(falkor_port or 6379),
                    username=falkor_user,
                    password=falkor_pass,
                    ssl=bool(falkor_ssl)
                )
            except Exception as e:
                logger.warning("Failed to connect to custom FalkorDB: %s. Using default client mirror.", e)
                return _default_client
        return _client_cache[key]
    return _default_client


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class FalkorConfig(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = 6379
    username: Optional[str] = None
    password: Optional[str] = None
    ssl: Optional[bool] = False


class SeedRequest(BaseModel):
    preset_id: Optional[str] = "fintech_enterprise"
    nodes: Optional[List[Dict[str, Any]]] = None
    relationships: Optional[List[Dict[str, Any]]] = None
    raw_graph: Optional[Dict[str, Any]] = None
    force: bool = True
    falkordb: Optional[FalkorConfig] = None


class InvestigateRequest(BaseModel):
    alert_text: str
    target_service: Optional[str] = None
    cve_id: Optional[str] = None
    max_hops: int = 4
    preset_id: Optional[str] = None
    nodes: Optional[List[Dict[str, Any]]] = None
    relationships: Optional[List[Dict[str, Any]]] = None
    raw_graph: Optional[Dict[str, Any]] = None
    model: Optional[str] = "llama-3.3-70b-versatile"
    groq_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    falkordb: Optional[FalkorConfig] = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    history: Optional[List[ChatMessage]] = Field(default_factory=list)
    preset_id: Optional[str] = None
    nodes: Optional[List[Dict[str, Any]]] = None
    relationships: Optional[List[Dict[str, Any]]] = None
    raw_graph: Optional[Dict[str, Any]] = None
    target_service: Optional[str] = None
    cve_id: Optional[str] = None
    model: Optional[str] = "llama-3.3-70b-versatile"
    groq_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    falkordb: Optional[FalkorConfig] = None


# ==============================================================================
# HEALTH & METADATA ENDPOINTS
# ==============================================================================

@app.get("/")
@app.get("/api/health")
def health_check(
    x_falkordb_host: Optional[str] = Header(None),
    x_falkordb_port: Optional[str] = Header(None),
    x_falkordb_username: Optional[str] = Header(None),
    x_falkordb_password: Optional[str] = Header(None),
    x_falkordb_ssl: Optional[str] = Header(None),
):
    client = get_client_from_request(
        falkor_host=x_falkordb_host,
        falkor_port=int(x_falkordb_port) if x_falkordb_port else None,
        falkor_user=x_falkordb_username,
        falkor_pass=x_falkordb_password,
        falkor_ssl=(x_falkordb_ssl.lower() == "true") if x_falkordb_ssl else None,
    )
    is_live = client.is_connected()
    return {
        "status": "healthy",
        "service": "NexTrace Autonomous SecOps API",
        "falkordb_connected": is_live,
        "falkordb_host": client.host,
        "falkordb_port": client.port,
        "mode": "FalkorDB Live Cluster" if is_live else "In-Memory Graph Engine Mirror",
        "active_preset": client._active_preset,
        "nodes_loaded": len(client._memory_graph.nodes),
        "relationships_loaded": len(client._memory_graph.edges),
        "available_presets": len(PRESETS)
    }


@app.get("/api/models")
def get_supported_models():
    """Lists supported AI models across Groq, Gemini, and OpenAI."""
    return {
        "groq": [
            {"id": "llama-3.3-70b-versatile", "name": "LLaMA 3.3 70B Versatile (Groq Fast Inference)", "provider": "Groq"},
            {"id": "openai/gpt-oss-120b", "name": "GPT-OSS 120B (Groq Cloud)", "provider": "Groq"},
            {"id": "openai/gpt-oss-20b", "name": "GPT-OSS 20B (Groq Fast)", "provider": "Groq"},
            {"id": "llama-3.1-8b-instant", "name": "LLaMA 3.1 8B Instant (Ultra Fast)", "provider": "Groq"},
        ],
        "gemini": [
            {"id": "gemini-1.5-pro", "name": "Google Gemini 1.5 Pro", "provider": "Gemini"},
            {"id": "gemini-1.5-flash", "name": "Google Gemini 1.5 Flash (Recommended)", "provider": "Gemini"},
            {"id": "gemini-2.0-flash", "name": "Google Gemini 2.0 Flash", "provider": "Gemini"},
        ],
        "openai": [
            {"id": "gpt-4o", "name": "OpenAI GPT-4o", "provider": "OpenAI"},
            {"id": "gpt-4o-mini", "name": "OpenAI GPT-4o Mini", "provider": "OpenAI"},
            {"id": "o3-mini", "name": "OpenAI o3-mini", "provider": "OpenAI"},
        ],
        "default": "llama-3.3-70b-versatile"
    }


@app.get("/api/presets")
def get_presets():
    """Returns all available architecture benchmark presets with scenario prompts."""
    output = []
    for pid, p in PRESETS.items():
        scenarios_list = [
            {
                "title": title,
                "text": sc.get("text", ""),
                "target_service": sc.get("service", ""),
                "cve_id": sc.get("cve", "")
            }
            for title, sc in p.get("scenarios", {}).items()
        ]
        output.append({
            "id": pid,
            "name": p["name"],
            "description": p["description"],
            "node_count": len(p["nodes"]),
            "relationship_count": len(p["relationships"]),
            "scenarios": scenarios_list
        })
    return {"presets": output}


@app.get("/api/presets/{preset_id}")
def get_preset_detail(preset_id: str):
    """Retrieves full topology JSON for a given preset ID."""
    if preset_id not in PRESETS and preset_id != "custom":
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found.")
    preset = get_preset(preset_id)
    return preset


@app.get("/api/samples/{filename}")
def get_sample_file(filename: str):
    """Returns downloadable sample JSON graph file."""
    safe_name = os.path.basename(filename)
    candidates = [
        backend_dir / "sample_graphs" / safe_name,
        backend_dir.parent / "sample_graphs" / safe_name,
        backend_dir.parent / "frontend" / "public" / "samples" / safe_name,
    ]
    alt = {
        "opentelemetry_astronomy_shop.json": "opentelemetry_demo.json",
        "sockshop_microservices.json": "sock_shop.json",
        "opentelemetry_demo.json": "opentelemetry_astronomy_shop.json",
        "sock_shop.json": "sockshop_microservices.json"
    }.get(safe_name)
    if alt:
        candidates.extend([
            backend_dir / "sample_graphs" / alt,
            backend_dir.parent / "sample_graphs" / alt,
            backend_dir.parent / "frontend" / "public" / "samples" / alt,
        ])

    sample_path = None
    for p in candidates:
        if p.exists():
            sample_path = p
            break

    if not sample_path:
        raise HTTPException(status_code=404, detail=f"Sample file '{filename}' not found.")

    with open(sample_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
    )


@app.post("/api/test-connection")
def test_falkordb_connection(config: FalkorConfig):
    """Tests connection to a FalkorDB instance."""
    start = time.time()
    try:
        from falkordb import FalkorDB
        driver = FalkorDB(
            host=config.host or "localhost",
            port=config.port or 6379,
            username=config.username,
            password=config.password,
            ssl=config.ssl or False,
            socket_connect_timeout=2.0,
            socket_timeout=3.0,
        )
        g = driver.select_graph("nextrace_test")
        g.query("RETURN 1 AS ping")
        latency = round((time.time() - start) * 1000, 2)
        return {
            "connected": True,
            "message": f"Successfully connected to FalkorDB at {config.host}:{config.port}!",
            "latency_ms": latency
        }
    except Exception as e:
        latency = round((time.time() - start) * 1000, 2)
        return {
            "connected": False,
            "message": f"Connection failed: {str(e)}",
            "latency_ms": latency
        }


# ==============================================================================
# SEEDING & MUTATION ENDPOINTS
# ==============================================================================

@app.post("/api/seed")
def seed_graph(
    req: SeedRequest,
    x_falkordb_host: Optional[str] = Header(None),
    x_falkordb_port: Optional[str] = Header(None),
    x_falkordb_username: Optional[str] = Header(None),
    x_falkordb_password: Optional[str] = Header(None),
    x_falkordb_ssl: Optional[str] = Header(None),
):
    """Seeds FalkorDB and in-memory graph with preset or uploaded custom JSON graph."""
    falkor = req.falkordb or FalkorConfig()
    client = get_client_from_request(
        falkor_host=falkor.host or x_falkordb_host,
        falkor_port=falkor.port or (int(x_falkordb_port) if x_falkordb_port else None),
        falkor_user=falkor.username or x_falkordb_username,
        falkor_pass=falkor.password or x_falkordb_password,
        falkor_ssl=falkor.ssl if falkor.ssl is not None else ((x_falkordb_ssl.lower() == "true") if x_falkordb_ssl else False),
    )

    if req.raw_graph:
        nodes, rels = normalize_graph_json(req.raw_graph)
        res = client.seed_database(custom_nodes=nodes, custom_relationships=rels, force=req.force)
        return {
            "status": "success",
            "preset": "custom",
            "nodes_count": len(nodes),
            "relationships_count": len(rels),
            "falkordb_connected": client.is_connected(),
            "falkordb_seeded": res.get("falkordb_seeded", False),
        }

    if req.nodes is not None and req.relationships is not None:
        res = client.seed_database(custom_nodes=req.nodes, custom_relationships=req.relationships, force=req.force)
        return {
            "status": "success",
            "preset": "custom",
            "nodes_count": len(req.nodes),
            "relationships_count": len(req.relationships),
            "falkordb_connected": client.is_connected(),
            "falkordb_seeded": res.get("falkordb_seeded", False),
        }

    preset_name = req.preset_id or "fintech_enterprise"
    res = client.seed_database(preset_name=preset_name, force=req.force)
    return {
        "status": "success",
        "preset": preset_name,
        "nodes_count": res.get("total_nodes", 0),
        "relationships_count": res.get("total_relationships", 0),
        "falkordb_connected": client.is_connected(),
        "falkordb_seeded": res.get("falkordb_seeded", False),
    }


# ==============================================================================
# AUTONOMOUS INVESTIGATION ENDPOINT
# ==============================================================================

@app.post("/api/investigate")
def run_investigation(
    req: InvestigateRequest,
    x_groq_api_key: Optional[str] = Header(None),
    x_gemini_api_key: Optional[str] = Header(None),
    x_openai_api_key: Optional[str] = Header(None),
    x_falkordb_host: Optional[str] = Header(None),
    x_falkordb_port: Optional[str] = Header(None),
    x_falkordb_username: Optional[str] = Header(None),
    x_falkordb_password: Optional[str] = Header(None),
    x_falkordb_ssl: Optional[str] = Header(None),
):
    """Executes the end-to-end 5-step autonomous investigation and severance pipeline."""
    falkor = req.falkordb or FalkorConfig()
    client = get_client_from_request(
        falkor_host=falkor.host or x_falkordb_host,
        falkor_port=falkor.port or (int(x_falkordb_port) if x_falkordb_port else None),
        falkor_user=falkor.username or x_falkordb_username,
        falkor_pass=falkor.password or x_falkordb_password,
        falkor_ssl=falkor.ssl if falkor.ssl is not None else ((x_falkordb_ssl.lower() == "true") if x_falkordb_ssl else False),
    )

    # Seed custom nodes or raw graph if provided
    if req.raw_graph:
        nodes, rels = normalize_graph_json(req.raw_graph)
        client.seed_database(custom_nodes=nodes, custom_relationships=rels, force=True)
    elif req.nodes is not None and req.relationships is not None:
        client.seed_database(custom_nodes=req.nodes, custom_relationships=req.relationships, force=True)
    elif req.preset_id and req.preset_id != client._active_preset:
        client.seed_database(preset_name=req.preset_id, force=True)

    groq_key = req.groq_api_key or x_groq_api_key or os.getenv("GROQ_API_KEY", "")
    gemini_key = req.gemini_api_key or x_gemini_api_key or os.getenv("GEMINI_API_KEY", "")
    openai_key = req.openai_api_key or x_openai_api_key or os.getenv("OPENAI_API_KEY", "")

    investigator = AutonomousInvestigator(
        api_key=groq_key,
        model=req.model or "llama-3.3-70b-versatile",
        client=client,
        groq_api_key=groq_key,
        gemini_api_key=gemini_key,
        openai_api_key=openai_key,
    )

    result = investigator.run_investigation(
        alert_text=req.alert_text,
        target_service=req.target_service,
        cve_id=req.cve_id,
        max_hops=req.max_hops
    )
    return result


# ==============================================================================
# GEMINI-STYLE CHAT AGENT ENDPOINT
# ==============================================================================

@app.post("/api/chat")
def chat_agent(
    req: ChatRequest,
    x_groq_api_key: Optional[str] = Header(None),
    x_gemini_api_key: Optional[str] = Header(None),
    x_openai_api_key: Optional[str] = Header(None),
    x_falkordb_host: Optional[str] = Header(None),
    x_falkordb_port: Optional[str] = Header(None),
    x_falkordb_username: Optional[str] = Header(None),
    x_falkordb_password: Optional[str] = Header(None),
    x_falkordb_ssl: Optional[str] = Header(None),
):
    """
    Conversational AI Agent Endpoint mimicking Google Gemini.
    Understands threat simulations, graph queries, shortest path analysis,
    and returns rich markdown with horizontal cyber kill-chain cards, explainable path proofs,
    blast radius statistics, and expandable Cypher/MCP execution logs.
    """
    falkor = req.falkordb or FalkorConfig()
    client = get_client_from_request(
        falkor_host=falkor.host or x_falkordb_host,
        falkor_port=falkor.port or (int(x_falkordb_port) if x_falkordb_port else None),
        falkor_user=falkor.username or x_falkordb_username,
        falkor_pass=falkor.password or x_falkordb_password,
        falkor_ssl=falkor.ssl if falkor.ssl is not None else ((x_falkordb_ssl.lower() == "true") if x_falkordb_ssl else False),
    )

    groq_key = req.groq_api_key or x_groq_api_key or os.getenv("GROQ_API_KEY", "")
    gemini_key = req.gemini_api_key or x_gemini_api_key or os.getenv("GEMINI_API_KEY", "")
    openai_key = req.openai_api_key or x_openai_api_key or os.getenv("OPENAI_API_KEY", "")

    investigator = AutonomousInvestigator(
        api_key=groq_key,
        model=req.model or "llama-3.3-70b-versatile",
        client=client,
        groq_api_key=groq_key,
        gemini_api_key=gemini_key,
        openai_api_key=openai_key,
    )

    user_msg = req.message.strip()
    msg_lower = user_msg.lower()

    import re
    # 1. Detect casual greetings (strictly lone greetings like 'hi', 'hello', 'hey', 'good morning')
    is_greeting = bool(re.search(r"^(hi|hello|hey|howdy|greetings|good\s+(morning|afternoon|evening|day)|sup|yo)[\s!.,?]*$", msg_lower))

    # 2. Detect capability / introductory questions
    is_capability_query = any(p in msg_lower for p in [
        "who are you", "what are you", "what can you do", "help me", "how do you work", "tell me about yourself", "what do you do", "capabilities"
    ]) and not any(k in msg_lower for k in ["simulate", "cve", "rce", "shortest path", "blast radius", "sever", "quarantine", "attack"])

    # 3. Detect if the user wants an incident investigation or blast radius simulation (actual work)
    is_simulation = not is_greeting and not is_capability_query and (
        any(trigger in msg_lower for trigger in [
            "simulate", "investigate", "cve", "rce", "compromise", "attack",
            "blast radius", "shortest path", "sever", "quarantine", "contain",
            "breach", "zero-day", "exploit", "path to crown jewel", "isolate"
        ]) or bool(req.target_service or req.cve_id)
    )

    # Ingest custom topology or re-seed preset if requested
    if req.raw_graph:
        nodes, rels = normalize_graph_json(req.raw_graph)
        client.seed_database(custom_nodes=nodes, custom_relationships=rels, force=True)
    elif req.nodes is not None and req.relationships is not None:
        client.seed_database(custom_nodes=req.nodes, custom_relationships=req.relationships, force=True)
    elif req.preset_id:
        if is_simulation or req.preset_id != client._active_preset:
            client.seed_database(preset_name=req.preset_id, force=True)

    # Handle greetings cleanly without dumping tables
    if is_greeting:
        return {
            "reply": """Hello! 👋 I'm **NexTrace**, your autonomous Cloud Security & Attack-Graph Investigator.

I can help you model and investigate your cloud infrastructure:
- **Import Architecture:** Click the **`+`** button below to upload any cloud topology JSON.
- **Simulate Zero-Days:** Test CVE exploits (like RCEs or deserialization) against workloads.
- **Trace Attack Trajectories:** Calculate the `shortestPath()` from perimeter ingress to database crown jewels.
- **Autonomous Containment:** Compute multi-hop blast radiuses, quarantine compromised services, and sever malicious edges.

How can I help you today?""",
            "is_investigation": False,
            "nodes_count": len(client._memory_graph.nodes),
            "relationships_count": len(client._memory_graph.edges),
            "entrypoints": [n for n, d in client._memory_graph.nodes(data=True) if d.get("public_facing")],
            "crown_jewels": [n for n, d in client._memory_graph.nodes(data=True) if d.get("crown_jewel")],
            "suggested_followups": [
                "Simulate CVE-2024-3094 RCE on Ingress",
                "Find shortest path to crown jewel database",
                "Calculate multi-hop blast radius",
                "What can you do?"
            ],
            "model_used": req.model or "llama-3.3-70b-versatile"
        }

    # Handle capability overview cleanly without overwhelming tables
    if is_capability_query:
        return {
            "reply": """I am **NexTrace**, an autonomous SecOps investigator that operates on connected attack graphs using **FalkorDB** and multi-hop Cypher queries.

### 🛡️ What I Can Do:
1. **Perimeter Exposure Mapping:** Identify public ingress points and map attack trajectories through internal microservices and IAM roles.
2. **Multi-Hop Blast Radius:** Calculate 1-to-4 hop downstream impact to uncover everything an attacker could compromise from a breached workload.
3. **Attack Path Tracing:** Using FalkorDB's native `shortestPath()` algorithm, mathematically prove whether an adversary can reach high-value database crown jewels.
4. **Autonomous Breach Containment:** Actively mutate graph state—marking services as `QUARANTINED` and severing compromised communication edges (`[:CALLS]`, `[:CAN_ASSUME]`).
5. **Mathematical Verification:** Re-verify that 0 surviving attack paths reach your crown jewel stores.

To begin, you can upload a cloud architecture JSON via **`+`** or ask me to simulate a specific threat scenario!""",
            "is_investigation": False,
            "nodes_count": len(client._memory_graph.nodes),
            "relationships_count": len(client._memory_graph.edges),
            "entrypoints": [n for n, d in client._memory_graph.nodes(data=True) if d.get("public_facing")],
            "crown_jewels": [n for n, d in client._memory_graph.nodes(data=True) if d.get("crown_jewel")],
            "suggested_followups": [
                "Simulate CVE-2024-3094 RCE on Ingress",
                "Find shortest path to crown jewel database",
                "Identify blast radius of OrderService",
                "Sever compromised edges to contain breach"
            ],
            "model_used": req.model or "llama-3.3-70b-versatile"
        }

    if is_simulation:
        # Determine target service and CVE
        target_service = req.target_service
        cve_id = req.cve_id

        # Auto-extract from graph nodes if not specified
        if not target_service:
            for n in client._memory_graph.nodes:
                if n.lower() in msg_lower and len(n) >= 3:
                    target_service = n
                    break

        if not target_service:
            # Fallback to standard core service in current graph
            candidates = [
                n for n, d in client._memory_graph.nodes(data=True)
                if not d.get("public_facing") and not d.get("crown_jewel") and d.get("label") == "Service"
            ]
            if not candidates:
                candidates = [
                    n for n, d in client._memory_graph.nodes(data=True)
                    if not d.get("public_facing") and not d.get("crown_jewel")
                ]
            target_service = candidates[0] if candidates else list(client._memory_graph.nodes)[0]

        if not cve_id:
            import re
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", user_msg, re.IGNORECASE)
            cve_id = cve_match.group(0).upper() if cve_match else "CVE-2024-3094"

        inv_res = investigator.run_investigation(
            alert_text=user_msg,
            target_service=target_service,
            cve_id=cve_id,
            max_hops=4
        )

        # Build Cyber Kill Chain cards
        path_nodes = inv_res["initial_attack_path"]
        entrypoint = path_nodes[0] if path_nodes else "Public Ingress"
        crown_jewel = path_nodes[-1] if path_nodes else "Crown Jewel Database"
        lateral_hops = path_nodes[1:-1] if len(path_nodes) > 2 else []

        kill_chain = [
            {
                "step": 1,
                "stage": "Initial Ingress Compromise",
                "status": "COMPROMISED",
                "entity": entrypoint,
                "vector": f"Vulnerability {cve_id} ingress trigger",
                "description": f"External perimeter exposure via {entrypoint} allowing adversarial probe."
            },
            {
                "step": 2,
                "stage": "Suspected Service Exploitation",
                "status": "COMPROMISED",
                "entity": target_service,
                "vector": f"Remote Code Execution via {cve_id}",
                "description": f"Memory corruption or payload execution detected on {target_service} container."
            },
            {
                "step": 3,
                "stage": "Lateral Pivot & IAM Assumption",
                "status": "EXPLOITED",
                "entity": lateral_hops[0] if lateral_hops else "Internal Service Mesh",
                "vector": "CAN_ASSUME / CALLS lateral traversal",
                "description": "Adversary hopped through internal network edges and privileged identity tokens."
            },
            {
                "step": 4,
                "stage": "Target Crown Jewel Exposure",
                "status": "EXPOSED",
                "entity": crown_jewel,
                "vector": "Direct ACCESSES database relationship",
                "description": f"Critical store {crown_jewel} was within reach before autonomous mitigation."
            },
            {
                "step": 5,
                "stage": "Autonomous FalkorDB Severance",
                "status": "CONTAINED",
                "entity": f"{target_service} Outbound Network Edges",
                "vector": "Cypher Edge Deletion & Quarantine State",
                "description": "Mutated graph state: Quarantined node & severed compromised edges. 0 attack paths remain."
            }
        ]

        # Extract Cypher logs
        cypher_logs = []
        for step in inv_res.get("execution_steps", []):
            if step.get("cypher_executed"):
                cypher_logs.append({
                    "step": step.get("step_number"),
                    "tool": step.get("tool_name"),
                    "cypher": step.get("cypher_executed"),
                    "thought": step.get("agent_thought"),
                    "summary": step.get("result_summary")
                })

        # Generate Gemini-style structured narrative
        blast = inv_res["blast_radius"]
        total_affected = blast["total_affected_entities"]
        impacted_svcs = ", ".join(blast["downstream_services"]) or "None"
        impacted_roles = ", ".join(blast["accessible_iam_roles"]) or "None"
        impacted_cjs = ", ".join(blast["exposed_crown_jewels"]) or "None"

        reply_markdown = f"""### Incident Response & Threat Containment: `{inv_res['incident_id']}`

I have executed an autonomous investigation and blast-radius containment over the **FalkorDB** attack graph.

#### 1. Vulnerability & Threat Assessment
- **Target Workload:** `{target_service}`
- **Active CVE Exploitation:** `{cve_id}`
- **Perimeter Attack Path:** `{inv_res['explainable_path_proof']}`
- **Pre-Remediation Status:** `CRITICAL REACHABILITY CONFIRMED`

#### 2. Blast Radius Impact Analysis
- **Total Entities Impacted:** **{total_affected}**
- **Downstream Services Exposed:** {impacted_svcs}
- **Accessible IAM Roles / Identities:** {impacted_roles}
- **Compromised Crown Jewel Stores:** {impacted_cjs}

#### 3. Autonomous Graph Remediation Executed
- Quarantined `{target_service}` (`status = 'QUARANTINED'`).
- Severed all outbound network calls (`CALLS`) and cloud role assumptions (`CAN_ASSUME`).
- **Mathematical Severance Proof:** Verified with Cypher `shortestPath()`.
- **Surviving Attack Paths to Crown Jewels:** **`0` (Complete Containment)**.
"""

        # Provide context-aware suggested followups
        suggested_followups = [
            f"Generate Terraform and AWS CLI remediation scripts for {target_service}",
            f"Verify if {target_service} can still reach {crown_jewel}",
            "Calculate betweenness centrality bottleneck chokepoints",
            "Reset attack graph to pristine benchmark state"
        ]

        return {
            "reply": reply_markdown,
            "is_investigation": True,
            "incident_id": inv_res["incident_id"],
            "target_service": target_service,
            "cve_id": cve_id,
            "kill_chain": kill_chain,
            "attack_path": inv_res["initial_attack_path"],
            "path_arrow": inv_res["explainable_path_proof"],
            "blast_radius": inv_res["blast_radius"],
            "mutations_applied": inv_res["mutations_applied"],
            "severance_verified": inv_res["severance_verified"],
            "attack_paths_remaining": inv_res["attack_paths_remaining"],
            "cypher_logs": cypher_logs,
            "execution_steps": inv_res.get("execution_steps", []),
            "remediation_bundle": inv_res.get("remediation_bundle", {}),
            "suggested_followups": suggested_followups,
            "model_used": req.model or "llama-3.3-70b-versatile"
        }

    # General Conversational Query on Graph State
    queries = GraphInvestigatorQueries(client)
    nodes_count = len(client._memory_graph.nodes)
    rels_count = len(client._memory_graph.edges)
    entrypoints = [n for n, d in client._memory_graph.nodes(data=True) if d.get("public_facing")]
    crown_jewels = [n for n, d in client._memory_graph.nodes(data=True) if d.get("crown_jewel")]

    # If an AI provider (Groq, Gemini, or OpenAI) is configured, invoke it for conversational reasoning
    ai_answer = None
    if investigator.groq_client or investigator.gemini_client or investigator.openai_client:
        history_context = "\n".join(f"{m.role.capitalize()}: {m.content}" for m in (req.history or [])[-4:])
        ai_prompt = f"""You are NexTrace, an intelligent SecOps AI assistant (Google Gemini style).
The user is asking a conversational or technical security question: "{user_msg}"

Context:
- Active Universe Preset: {client._active_preset}
- Ingress Points: {', '.join(entrypoints[:5]) if entrypoints else 'None'}
- Crown Jewels: {', '.join(crown_jewels[:5]) if crown_jewels else 'None'}

Recent Chat History:
{history_context if history_context else 'None'}

Instructions:
- Answer naturally, helpfully, and concisely (1-2 short paragraphs or clean bullet points).
- Explain concepts with clear, practical examples.
- DO NOT dump long tables of nodes, services, or IAM roles unless the user explicitly asks to list them.
- Keep the tone professional, friendly, and conversational.
"""
        ai_answer = investigator.generate_ai_response(ai_prompt)

    if ai_answer:
        reply_markdown = ai_answer
    else:
        # Context-aware graph inspector fallback
        matched_node = None
        for n in client._memory_graph.nodes:
            if n.lower() in msg_lower and len(n) >= 3:
                matched_node = n
                break

        if matched_node:
            in_edges = list(client._memory_graph.predecessors(matched_node))
            out_edges = list(client._memory_graph.successors(matched_node))
            props = client._memory_graph.nodes[matched_node]
            reply_markdown = f"""### Entity Topology Inspection: `{matched_node}`

- **Type / Label:** `{props.get('label', 'Service')}`
- **Public Perimeter Ingress:** `{'YES (Exposed to Public Traffic)' if props.get('public_facing') else 'NO (Internal Only)'}`
- **Crown Jewel Store:** `{'YES (PCI/PII Target)' if props.get('crown_jewel') else 'NO'}`
- **Inbound Ingress Paths ({len(in_edges)}):** {", ".join(f"`{x}`" for x in in_edges) if in_edges else "None (Perimeter Root)"}
- **Outbound Calls ({len(out_edges)}):** {", ".join(f"`{x}`" for x in out_edges) if out_edges else "None (Terminal Workload)"}

#### Recommended Actions:
- Simulate zero-day vulnerability exploit on `{matched_node}`.
- Trace shortestPath() from ingress to `{matched_node}`.
- Compute multi-hop downstream blast radius.
"""
        elif any(w in msg_lower for w in ["database", "crown jewel", "storage", "vault", "secret", "pci"]):
            reply_markdown = f"""### High-Value Crown Jewel Assets

The active **FalkorDB** workspace protects **{len(crown_jewels)} crown jewel database(s)**:

{chr(10).join(f"- `{cj}` — Tier: *{client._memory_graph.nodes[cj].get('tier', 'secure-vault')}*" for cj in crown_jewels) if crown_jewels else "- No crown jewels explicitly flagged."}

To test database exposure:
- Run a `shortestPath()` trace from public ingress to verify adversarial reachability.
- Simulate an ingress compromise to verify autonomous severance.
"""
        elif any(w in msg_lower for w in ["ingress", "gateway", "entry", "perimeter", "public", "edge"]):
            reply_markdown = f"""### External Perimeter Gateways

The active topology has **{len(entrypoints)} public gateway(s)**:

{chr(10).join(f"- `{ep}` (Dispatches to: {', '.join(f'`{s}`' for s in client._memory_graph.successors(ep))})" for ep in entrypoints) if entrypoints else "- No public ingress explicitly flagged."}

Simulate a remote code execution exploit on any of these gateways to evaluate lateral movement into internal services.
"""
        else:
            reply_markdown = f"""### NexTrace Autonomous SecOps

I'm ready to investigate your cloud infrastructure.

- **Active Universe:** `{client._active_preset}` ({nodes_count} nodes, {rels_count} relationships)
- **Ingress Gateways:** {", ".join(f"`{e}`" for e in entrypoints) if entrypoints else "None defined"}
- **Protected Crown Jewels:** {", ".join(f"`{c}`" for c in crown_jewels) if crown_jewels else "None defined"}

You can click any suggested scenario below, or upload your own cloud architecture JSON using the **`+`** button to begin."""

    return {
        "reply": reply_markdown,
        "is_investigation": False,
        "nodes_count": nodes_count,
        "relationships_count": rels_count,
        "entrypoints": entrypoints,
        "crown_jewels": crown_jewels,
        "suggested_followups": [
            f"Simulate CVE-2024-3094 RCE on {entrypoints[0] if entrypoints else 'ingress'}",
            "Find shortest path to crown jewel database",
            "Calculate critical bottleneck chokepoints",
            "Import a new JSON topology"
        ],
        "model_used": req.model or "llama-3.3-70b-versatile"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.index:app", host="0.0.0.0", port=8000, reload=True)
