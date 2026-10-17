# 🛡️ NexTrace — Backend API & Autonomous Graph Agent

> **Hackathon Track:** Agents That Act on Connected Data  
> **Database:** FalkorDB (Cypher Graph Database + Built-in `shortestPath()` Algorithm)  
> **Protocol:** Model Context Protocol (MCP) JSON-RPC  
> **LLM Providers:** Groq (`llama-3.3-70b-versatile`), Google Gemini (`gemini-1.5-flash`), OpenAI (`gpt-4o`)  
> **Backend Repository:** [Subhojit534/NexTrace_Backend](https://github.com/Subhojit534/NexTrace_Backend)  
> **Frontend Repository:** [Subhojit534/NexTrace](https://github.com/Subhojit534/NexTrace)  

The NexTrace Backend is a high-performance FastAPI service that pairs large language models with FalkorDB through the **Model Context Protocol (MCP)**. Instead of treating graph data as passive text, the agent actively queries connected cloud infrastructure topologies, traces shortest attack paths, mutates graph states (quarantines workloads and severs malicious edges), and mathematically proves that attack paths to crown-jewel databases are eliminated.

---

## 🏗️ Architecture Overview

```
                                  ┌────────────────────────┐
                                  │      Client / UI       │
                                  └───────────┬────────────┘
                                              │ HTTP / JSON
                                              ▼
                                  ┌────────────────────────┐
                                  │   FastAPI Endpoints    │
                                  │   (/api/chat, etc.)    │
                                  └───────────┬────────────┘
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    │                                                   │
                    ▼                                                   ▼
       ┌─────────────────────────┐                         ┌─────────────────────────┐
       │   Groq / Gemini LLM     │                         │   MCP Server & Tools    │
       │  (Autonomous Reasoning) │◄───[tools/list & call]──┤  (backend/mcp/server.py)│
       └─────────────────────────┘                         └────────────┬────────────┘
                                                                        │
                                                                        ▼
                                                           ┌─────────────────────────┐
                                                           │     FalkorDB Client     │
                                                           │  (shortestPath, Cypher) │
                                                           └─────────────────────────┘
```

---

## 📊 Graph Data Model

NexTrace represents an enterprise cloud attack surface as a connected property graph inside FalkorDB:

### Node Types

| Node Label | Description | Key Attributes |
| :--- | :--- | :--- |
| **`Service`** | Microservice workload or API gateway | `name`, `tier`, `public_facing` (bool), `status` (`HEALTHY` \| `QUARANTINED`), `quarantine_reason` |
| **`IAMRole`** | Identity and Access Management identity | `name`, `privilege_level` (`LOW` \| `READONLY` \| `PRIVILEGED` \| `ADMIN`) |
| **`Database`** | Data persistence store or vault | `name`, `crown_jewel` (bool), `classification` (`INTERNAL` \| `CONFIDENTIAL` \| `RESTRICTED`) |
| **`Vulnerability`** | CVE or library security flaw | `name`, `cve_id`, `cvss_score`, `severity` (`CRITICAL` \| `HIGH`) |

### Edge Relationships

| Relationship | Start Node ➔ End Node | Meaning |
| :--- | :--- | :--- |
| **`[:CALLS]`** | `(Service) ➔ (Service)` | Microservice network dependency (gRPC/HTTP) |
| **`[:CAN_ASSUME]`** | `(Service) ➔ (IAMRole)` | Service workload is authorized to assume an IAM identity |
| **`[:ACCESSES]`** | `(IAMRole/Service) ➔ (Database)` | Read/Write access to a data store |
| **`[:DEPENDS_ON]`** | `(Service) ➔ (Vulnerability)` | Workload is bundled with a vulnerable package |

---

## 📁 Downloadable Architecture Topologies

NexTrace includes **7 realistic cloud architecture benchmarks** that can be seeded into FalkorDB or downloaded via the API:

| File Name | Nodes | Edges | Real-World Scenario |
| :--- | :---: | :---: | :--- |
| **`fintech_enterprise.json`** | **34** | **36** | Tier-0/1 banking architecture with PCI payment vaults and customer databases. Includes zero-day CVE-2024-3094 on `AuthService`. |
| **`google_online_boutique.json`** | **28** | **35** | Official Google Cloud microservices architecture with `CreditCardVault`. |
| **`aws_cloud_iam.json`** | **21** | **24** | Multi-hop IAM privilege escalation chain from EC2 to Cloud Admin. |
| **`opentelemetry_astronomy_shop.json`** | **12** | **11** | Polyglot CNCF benchmark tracing edge Envoy ingress to payment vaults. |
| **`sockshop_microservices.json`** | **12** | **11** | Cloud-native Kubernetes eCommerce architecture with Traefik router. |
| **`netflix_microservices_topology.json`** | **9** | **7** | Enterprise Netflix stack modeling Zuul gateway and Cassandra databases. |
| **`azure_cloud_infrastructure.json`** | **7** | **6** | Multi-tier Azure enterprise topology with Azure Front Door and Key Vault HSM. |

### API Download Commands
```bash
# Download any sample JSON from the running backend:
curl -O http://localhost:8000/api/samples/fintech_enterprise.json
curl -O http://localhost:8000/api/samples/google_online_boutique.json
curl -O http://localhost:8000/api/samples/aws_cloud_iam.json
curl -O http://localhost:8000/api/samples/opentelemetry_astronomy_shop.json
curl -O http://localhost:8000/api/samples/sockshop_microservices.json
curl -O http://localhost:8000/api/samples/netflix_microservices_topology.json
curl -O http://localhost:8000/api/samples/azure_cloud_infrastructure.json
```

---

## 🧠 Cypher Queries & Graph Algorithms

### 1. Multi-Hop Blast-Radius Traversal
Discovers all microservices, assumable IAM roles, and databases within 1 to 4 hops downstream of a compromised node:
```cypher
MATCH path = (s {name: $service_name})-[:CALLS|DEPENDS_ON|CAN_ASSUME|ACCESSES*1..4]->(target)
RETURN [n in nodes(path) | n.name] AS node_sequence,
       length(path) AS depth,
       target.name AS target_name,
       labels(target)[0] AS target_type,
       target.crown_jewel AS is_crown_jewel
```

### 2. Built-in Shortest Attack Path (`shortestPath()`)
Evaluates active attack exposure routes from public ingress points to crown-jewel databases:
```cypher
MATCH (entry:Service {public_facing: true}), (crown:Database {crown_jewel: true})
MATCH path = shortestPath((entry)-[:CALLS|CAN_ASSUME|ACCESSES*..10]->(crown))
RETURN [n in nodes(path) | n.name] AS node_sequence, length(path) AS hops
```

### 3. Critical Bottleneck Chokepoint Analysis
Calculates intermediate chokepoints between public entrypoints and crown jewels based on attack-path frequency:
```cypher
MATCH (entry:Service {public_facing: true}), (crown:Database {crown_jewel: true})
MATCH path = (entry)-[:CALLS|CAN_ASSUME|ACCESSES*..8]->(crown)
UNWIND nodes(path)[1..-1] AS bottleneck
RETURN bottleneck.name AS node_name, count(path) AS traversing_attack_paths
ORDER BY traversing_attack_paths DESC
LIMIT 5
```

### 4. Autonomous State Mutation (Quarantine)
Isolates a compromised workload by mutating node properties directly in FalkorDB:
```cypher
MATCH (s:Service {name: $service_name})
SET s.status = 'QUARANTINED',
    s.quarantine_reason = $reason,
    s.quarantined_at = timestamp()
RETURN s.name, s.status
```

### 5. Autonomous Edge Severance
Cuts malicious lateral communication or privilege escalation paths:
```cypher
MATCH (a {name: $from_service})-[r:CALLS|CAN_ASSUME]->(b)
DELETE r
RETURN count(r) AS severed_count
```

### 6. Path Severance Verification
Re-runs `shortestPath()` across the mutated graph to mathematically prove that **zero active attack paths** remain between the public internet and crown jewels.

---

## 🔌 Model Context Protocol (MCP) Tools

NexTrace exposes standardized tools defined under the official Model Context Protocol (MCP) JSON-RPC specification:

| MCP Tool Name | Description | Parameters |
| :--- | :--- | :--- |
| **`mcp_query_blast_radius`** | Multi-hop downstream discovery (1–4 hops) | `service_name` (str), `max_hops` (int) |
| **`mcp_trace_attack_shortest_path`** | Executes `shortestPath()` from ingress to crown jewels | `entrypoint` (str), `target_crown_jewel` (str), `through_service` (str) |
| **`mcp_quarantine_service`** | Mutates node state to `QUARANTINED` in FalkorDB | `service_name` (str), `reason` (str) |
| **`mcp_sever_compromised_edge`** | Deletes compromised communication / IAM edges | `from_service` (str), `to_target` (str), `reason` (str) |
| **`mcp_verify_path_severance`** | Mathematically proves reachability is eliminated | `entrypoint` (str), `target_crown_jewel` (str) |
| **`mcp_get_graph_summary`** | Summarizes current node/relationship topology | none |

---

## 🛠️ Local Setup Instructions

### 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Optional: Local FalkorDB instance running on Docker:
  ```bash
  docker run -p 6379:6379 -it --rm falkordb/falkordb:latest
  ```
  *(Note: NexTrace includes an automatic in-memory graph mirror, so it functions seamlessly even if an external FalkorDB instance is not running).*

### 2. Clone & Install Dependencies
```bash
git clone https://github.com/Subhojit534/NexTrace_Backend.git
cd NexTrace_Backend

python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Environment Variables (`.env`)
Create a `.env` file from `.env.example`:
```env
# LLM Provider Keys (at least one is recommended)
GROQ_API_KEY=gsk_your_groq_api_key_here
GROQ_MODEL=llama-3.3-70b-versatile

# (Optional) Alternative LLM Providers
GEMINI_API_KEY=your_gemini_api_key
OPENAI_API_KEY=your_openai_api_key

# FalkorDB Database Configuration
FALKORDB_HOST=localhost
FALKORDB_PORT=6379
FALKORDB_PASSWORD=
FALKORDB_GRAPH_NAME=nextrace_security_graph
```

### 4. Start the API Server
```bash
python -m uvicorn api.index:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at: **`http://localhost:8000/docs`**.

---

## 🚀 Deploy to Vercel (Serverless)

1. Push your repository to GitHub.
2. In the **Vercel Dashboard**, click **Add New Project** and select `Subhojit534/NexTrace_Backend`.
3. Vercel automatically detects `vercel.json` and configures the Python serverless runtime on `api/index.py`.
4. In **Settings** ➔ **Environment Variables**, add:
   - `GROQ_API_KEY`
   - `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_PASSWORD` (if using FalkorDB Cloud)
5. Click **Deploy**.

---

## 📡 REST API Endpoints Reference

| Method | Endpoint | Description |
| :---: | :--- | :--- |
| `GET` | `/api/health` | Service health, FalkorDB connection status, active preset |
| `GET` | `/api/models` | List of supported AI models (Groq, Gemini, OpenAI) |
| `GET` | `/api/presets` | Available pre-built architecture benchmarks |
| `GET` | `/api/presets/{preset_id}` | Detailed node & edge breakdown for a benchmark |
| `GET` | `/api/samples/{filename}` | Downloadable architecture JSON file |
| `POST` | `/api/seed` | Seeds benchmark or uploaded custom architecture JSON |
| `POST` | `/api/test-connection` | Tests live connectivity & latency to a FalkorDB cluster |
| `POST` | `/api/chat` | Main conversational agent endpoint with multi-turn memory |
| `POST` | `/api/investigate` | Direct programmatic 5-step autonomous investigation pipeline |
