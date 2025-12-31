"""
Event Mill MCP Server

A modular MCP server for SOC log analysis with AI-powered investigation capabilities.
Tool implementations are organized in the tools/ package for easier maintenance.
"""

import os
import logging
import google.genai as genai
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from google.cloud import storage
from typing import Optional

# Load environment variables from .env file
load_dotenv()

# Configure logging to avoid interfering with MCP stdio communication
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/soc_mcp_server.log')
    ]
)

# Initialize the MCP Server
mcp = FastMCP("GCS SOC Log Server")

# Initialize Gemini Client
gemini_client = None
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    try:
        gemini_client = genai.Client()
    except Exception as e:
        logging.error(f"Failed to initialize Gemini client: {e}")
        gemini_client = None
else:
    logging.warning("GEMINI_API_KEY not set. AI analysis features will be disabled.")

# Initialize GCS Client
try:
    gcs_key_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if gcs_key_path:
        storage_client = storage.Client.from_service_account_json(gcs_key_path)
    else:
        logging.error("GOOGLE_APPLICATION_CREDENTIALS not set. GCS access will fail.")
        storage_client = None
except Exception as e:
    logging.error(f"Failed to initialize GCS client: {e}")
    storage_client = None

# Configured Bucket (Optional)
DEFAULT_BUCKET = os.getenv("GCS_LOG_BUCKET")

def _get_bucket(bucket_name: Optional[str] = None) -> Optional[str]:
    """Helper to resolve which bucket to use."""
    if DEFAULT_BUCKET:
        return DEFAULT_BUCKET
    return bucket_name

# Register all tools from the tools package
from tools import register_all_tools
register_all_tools(mcp, storage_client, gemini_client, _get_bucket)

if __name__ == "__main__":
    # Check if we are running in Cloud Run mode (via env var) or standard local mode
    if os.getenv("MCP_TRANSPORT") == "sse":
        # Run as an SSE server (HTTP)
        import uvicorn
        port = int(os.getenv("PORT", "8080"))
        mcp.run(transport="sse")
    else:
        # Run as a stdio server (default for local AI clients)
        mcp.run()
