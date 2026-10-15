"""
Model Context Protocol (MCP) Server for NexTrace.
Provides JSON-RPC protocol compliance and direct integration endpoints for LLM agents.
"""

import json
import logging
from typing import Any, Dict, List
from mcp.tools import MCP_TOOL_DEFINITIONS, execute_mcp_tool

logger = logging.getLogger(__name__)


class MCPServer:
    """Standardized MCP Server exposing FalkorDB Cloud Security investigation tools."""

    def __init__(self, name: str = "nextrace-falkordb-security-mcp", version: str = "1.0.0"):
        self.name = name
        self.version = version

    def list_tools(self) -> List[Dict[str, Any]]:
        """Returns the registered MCP tool definitions (tools/list)."""
        return MCP_TOOL_DEFINITIONS

    def call_tool(self, tool_name: str, arguments: Dict[str, Any], queries_engine: Any = None) -> Dict[str, Any]:
        """Executes an MCP tool call and returns standard MCP response (tools/call)."""
        try:
            result = execute_mcp_tool(tool_name, arguments, queries_engine=queries_engine)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2)
                    }
                ],
                "isError": False,
                "raw_result": result
            }
        except Exception as e:
            logger.error("MCP tool execution error on %s: %s", tool_name, e)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Error executing tool {tool_name}: {str(e)}"
                    }
                ],
                "isError": True,
                "raw_result": {"error": str(e)}
            }

    def handle_json_rpc(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Processes a standard JSON-RPC 2.0 message."""
        method = request_payload.get("method")
        msg_id = request_payload.get("id", 1)
        params = request_payload.get("params", {})

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.list_tools()}
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            call_res = self.call_tool(tool_name, args)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": call_res
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method {method} not found"}
            }


# Singleton server instance
_mcp_server = MCPServer()

def get_mcp_server() -> MCPServer:
    return _mcp_server
