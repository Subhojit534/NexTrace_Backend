# 🛡️ NexTrace Backend API (FastAPI + FalkorDB + Vercel Serverless)

Standalone serverless FastAPI backend for the NexTrace Autonomous Cloud Security Investigator.

## Features
- **Vercel Serverless Ready**: Configured with `vercel.json` and `api/index.py` entrypoint.
- **Dynamic Credentials**: Supports per-request FalkorDB credentials (Host, Port, Username, Password, SSL) and LLM keys (Groq, Gemini, OpenAI) via headers or payload.
- **Graph Algorithms & Cypher**: Powered by FalkorDB client with built-in fallback to in-memory graph mirror.
- **REST Endpoints**:
  - `GET /api/health`: Health status & FalkorDB connection state.
  - `GET /api/models`: Supported AI models list.
  - `GET /api/presets`: Available architecture benchmark topologies.
  - `GET /api/presets/{preset_id}`: Topology details.
  - `GET /api/samples/{filename}`: Downloadable sample JSON files.
  - `POST /api/seed`: Seeds preset or custom JSON graph into FalkorDB.
  - `POST /api/test-connection`: Tests connectivity to a FalkorDB cluster.
  - `POST /api/investigate`: Runs 5-step autonomous investigation pipeline.
  - `POST /api/chat`: Gemini-style conversational agent endpoint with kill-chain steps and explainable path proofs.

## Deploy to Vercel
1. Create a GitHub repository with the contents of this `backend/` folder.
2. In Vercel Dashboard, click **Add New Project** and select this repo.
3. (Optional) Set environment variables: `GROQ_API_KEY`, `FALKORDB_HOST`, `FALKORDB_PORT`, `FALKORDB_PASSWORD`.
4. Click **Deploy**. Note your deployed URL (e.g., `https://your-backend.vercel.app`).

## Local Development
```bash
pip install -r requirements.txt
python -m uvicorn api.index:app --host 0.0.0.0 --port 8000 --reload
```
API docs available at `http://localhost:8000/docs`.
