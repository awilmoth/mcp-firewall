#!/usr/bin/env python3
import os
import sys
import json
from fastapi import FastAPI
import uvicorn
from pydantic import BaseModel

# Debug function
def debug_to_stdio(message):
    """Print debug message to stdout for Smithery to capture"""
    print(f"DEBUG: {message}", flush=True)
    sys.stdout.flush()

# Create a minimal FastAPI app
debug_to_stdio("Creating minimal FastAPI app for Smithery")
app = FastAPI(
    title="MCP Firewall",
    description="Firewall with rules engine for filtering text when using LLMs",
    version="1.0.0"
)

# Define models
class TextRequest(BaseModel):
    text: str

class ProcessResponse(BaseModel):
    processed_text: str
    matches: list

# Sample rules
RULES = [
    {
        "id": "ssn",
        "name": "SSN",
        "description": "US Social Security Number",
        "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
        "replacement": "<SSN>",
        "enabled": True
    },
    {
        "id": "cc",
        "name": "Credit Card",
        "description": "Credit Card Number",
        "pattern": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "replacement": "<CREDIT_CARD>",
        "enabled": True
    }
]

# Define API endpoints
@app.get("/")
async def root():
    debug_to_stdio("Root endpoint called")
    return {
        "name": "MCP Firewall",
        "version": "1.0.0",
        "description": "Firewall with rules engine for filtering text when using LLMs"
    }

@app.get("/health")
async def health():
    debug_to_stdio("Health check endpoint called")
    return {"status": "ok", "version": "1.0.0"}

@app.post("/process")
async def process_endpoint(text_request: TextRequest):
    """Process text through the firewall rules engine."""
    debug_to_stdio(f"Process endpoint called with {len(text_request.text)} characters")
    return {
        "processed_text": text_request.text,
        "matches": []
    }

@app.get("/rules")
async def get_rules_endpoint():
    """Get all firewall rules."""
    debug_to_stdio("Get rules endpoint called")
    return {"rules": RULES}

# Endpoint for Smithery tool scanning
@app.post("/tools")
async def tools_list():
    debug_to_stdio("Tools endpoint called for Smithery scanning")
    return {
        "tools": [
            {
                "name": "process_text",
                "description": "Process text through the firewall rules engine",
                "parameters": {
                    "text": {
                        "type": "string",
                        "description": "The text to process"
                    }
                }
            },
            {
                "name": "get_rules",
                "description": "Gets all firewall rules",
                "parameters": {}
            }
        ]
    }

# Run the server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 6366))
    debug_to_stdio(f"Starting minimal MCP Firewall on port {port}")
    
    try:
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=port,
            log_level="info"
        )
    except Exception as e:
        debug_to_stdio(f"Error starting server: {e}")