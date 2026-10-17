"""
NexTrace Serverless Entrypoint Fallback for Vercel.
Re-exports the FastAPI app, application, and handler from api.index.
"""
from api.index import app, application, handler

__all__ = ["app", "application", "handler"]
