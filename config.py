import os
from pathlib import Path
from dotenv import load_dotenv

# Load local .env if present
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip()

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost").strip()
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_GRAPH = os.getenv("FALKORDB_GRAPH", "NexTraceCloud").strip()
FALKORDB_PASSWORD = os.getenv("FALKORDB_PASSWORD", "").strip() or None
FALKORDB_USERNAME = os.getenv("FALKORDB_USERNAME", "").strip() or None
FALKORDB_SSL = os.getenv("FALKORDB_SSL", "false").strip().lower() in ("true", "1", "yes")
FALKORDB_BROWSER_URL = os.getenv("FALKORDB_BROWSER_URL", "http://localhost:3000").strip()

# Agent Config
DEFAULT_MAX_HOPS = 4
DEFAULT_AGENT_TEMPERATURE = 0.1
