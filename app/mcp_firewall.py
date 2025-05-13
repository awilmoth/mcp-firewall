#!/usr/bin/env python3
import os
import sys
import logging
import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

# Setup logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'firewall.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MCPFirewall")

# Debug function for stdout
def debug_to_stdio(message):
    """Print debug message to stdout for Docker logs"""
    print(f"DEBUG: {message}", flush=True)
    sys.stdout.flush()

# Initialize FastAPI and MCP
try:
    from fastapi import FastAPI, Request, HTTPException
    import uvicorn
    from mcp.server.fastmcp import FastMCP
    from pydantic import BaseModel
    logger.info("Successfully imported required libraries")
except ImportError as e:
    logger.error(f"Failed to import required libraries: {e}")
    try:
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "mcp", "pydantic"], check=True)
        from fastapi import FastAPI, Request, HTTPException
        import uvicorn
        from mcp.server.fastmcp import FastMCP
        from pydantic import BaseModel
        logger.info("Successfully installed required libraries")
    except Exception as e:
        logger.error(f"Failed to install required libraries: {e}")
        sys.exit(1)

# Models for API requests/responses
class TextRequest(BaseModel):
    text: str

class ProcessResponse(BaseModel):
    processed_text: str
    matches: List[Dict[str, Any]]

class RuleBase(BaseModel):
    name: str
    pattern: str
    replacement: str = "<REDACTED>"
    description: str = ""
    enabled: bool = True

class RuleResponse(BaseModel):
    id: str
    name: str
    pattern: str
    replacement: str
    description: str
    enabled: bool

class RulesResponse(BaseModel):
    rules: List[RuleResponse]

# Default rules storage
DEFAULT_RULES = [
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
    },
    {
        "id": "email",
        "name": "Email",
        "description": "Email Address",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "replacement": "<EMAIL>",
        "enabled": True
    },
    {
        "id": "phone",
        "name": "Phone",
        "description": "Phone Number",
        "pattern": r"\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
        "replacement": "<PHONE>",
        "enabled": True
    },
    {
        "id": "password",
        "name": "Password",
        "description": "Password values in text",
        "pattern": r"(?i)password[=:]\s*\S+",
        "replacement": "<PASSWORD>",
        "enabled": True
    },
    {
        "id": "api_key",
        "name": "API Key",
        "description": "API keys and tokens",
        "pattern": r"(?i)(api[_-]?key|access[_-]?token|token|secret)[=:]\s*\S+",
        "replacement": "<API_KEY>",
        "enabled": True
    }
]

# Initialize rules list but don't load them yet (lazy loading)
rules = []
rules_loaded = False

# Rule persistence file
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'rules.json')
os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)

def save_rules():
    """Save rules to file"""
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(rules, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving rules: {e}")

def load_rules():
    """Load rules from file"""
    global rules, rules_loaded
    
    # Don't reload if already loaded
    if rules_loaded:
        return
        
    try:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                loaded_rules = json.load(f)
                if loaded_rules:
                    rules = loaded_rules
                    logger.info(f"Loaded {len(rules)} rules from {RULES_FILE}")
                    rules_loaded = True
                    return
    except Exception as e:
        logger.error(f"Error loading rules: {e}")
    
    # If file doesn't exist or there's an error, use default rules
    rules = DEFAULT_RULES.copy()
    logger.info(f"Using {len(rules)} default rules")
    save_rules()  # Save default rules
    rules_loaded = True

def ensure_rules_loaded():
    """Ensure rules are loaded before using them"""
    global rules_loaded
    if not rules_loaded:
        logger.info("Lazy loading rules")
        debug_to_stdio("Lazy loading rules from file or defaults")
        load_rules()
        debug_to_stdio(f"Loaded {len(rules)} rules successfully")

def process_text_impl(text: str) -> Dict:
    """Implementation of text processing with firewall rules"""
    ensure_rules_loaded()
    
    if not text:
        return {"processed_text": "", "matches": []}

    processed = text
    matches = []

    # Apply each rule
    for rule in rules:
        if not rule["enabled"]:
            continue

        try:
            pattern = re.compile(rule["pattern"])
            rule_matches = list(pattern.finditer(processed))

            # Process matches in reverse to avoid offset issues
            for match in reversed(rule_matches):
                original = match.group(0)
                replacement = rule["replacement"]

                # Add to matches
                matches.append({
                    "original": original,
                    "replacement": replacement,
                    "rule_name": rule["name"],
                    "rule_id": rule["id"]
                })

                # Replace in text
                start, end = match.span()
                processed = processed[:start] + replacement + processed[end:]
        except Exception as e:
            logger.error(f"Error applying rule {rule['name']}: {e}")

    return {
        "processed_text": processed,
        "matches": matches
    }

def get_rules_impl() -> Dict[str, List]:
    """Get all rules"""
    ensure_rules_loaded()
    return {"rules": rules}

def add_rule_impl(rule_data: Dict) -> Dict:
    """Add a new rule"""
    ensure_rules_loaded()
    
    rule_id = rule_data.get("id", f"{rule_data.get('name', 'rule').lower().replace(' ', '_')}_{len(rules)}")
    
    # Check if rule with same ID already exists
    if any(r["id"] == rule_id for r in rules):
        rule_id = f"{rule_id}_{len(rules)}"
    
    new_rule = {
        "id": rule_id,
        "name": rule_data.get("name", "Custom Rule"),
        "description": rule_data.get("description", ""),
        "pattern": rule_data.get("pattern", ""),
        "replacement": rule_data.get("replacement", "<REDACTED>"),
        "enabled": rule_data.get("enabled", True)
    }
    rules.append(new_rule)
    save_rules()
    return {"success": True, "rule": new_rule}

def update_rule_impl(rule_id: str, updates: Dict) -> Dict:
    """Update a rule"""
    ensure_rules_loaded()
    
    for i, rule in enumerate(rules):
        if rule["id"] == rule_id:
            for key, value in updates.items():
                if key in rule and key != "id":  # Don't allow changing ID
                    rule[key] = value
            save_rules()
            return {"success": True, "rule": rule}
    
    return {"error": f"Rule {rule_id} not found"}

def delete_rule_impl(rule_id: str) -> Dict:
    """Delete a rule"""
    ensure_rules_loaded()
    
    global rules
    before_count = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) < before_count:
        save_rules()
        return {"success": True}
    else:
        return {"error": f"Rule {rule_id} not found"}

def reset_rules_impl() -> Dict:
    """Reset rules to defaults"""
    ensure_rules_loaded()
    
    global rules
    rules = DEFAULT_RULES.copy()
    save_rules()
    return {"success": True, "message": f"Reset to {len(rules)} default rules"}

# Define tools information that will be used for discovery
TOOLS = [
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
    },
    {
        "name": "add_rule",
        "description": "Adds a new firewall rule",
        "parameters": {
            "name": {
                "type": "string",
                "description": "Name of the rule"
            },
            "pattern": {
                "type": "string",
                "description": "Regex pattern to match"
            },
            "replacement": {
                "type": "string",
                "description": "Text to replace matches with"
            },
            "description": {
                "type": "string",
                "description": "Description of the rule"
            },
            "enabled": {
                "type": "boolean",
                "description": "Whether the rule is enabled"
            }
        }
    },
    {
        "name": "update_rule",
        "description": "Updates an existing firewall rule",
        "parameters": {
            "rule_id": {
                "type": "string",
                "description": "ID of the rule to update"
            }
        }
    },
    {
        "name": "delete_rule",
        "description": "Deletes a firewall rule",
        "parameters": {
            "rule_id": {
                "type": "string",
                "description": "ID of the rule to delete"
            }
        }
    },
    {
        "name": "reset_rules",
        "description": "Resets rules to defaults",
        "parameters": {}
    }
]

# Create FastAPI app and MCP server with minimal configuration
try:
    debug_to_stdio("Creating FastAPI app and MCP server")
    from fastapi.middleware.cors import CORSMiddleware
    from starlette.middleware.base import BaseHTTPMiddleware
    
    # Custom middleware for logging all requests
    class RequestLoggingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            # Get client IP and request details
            client_host = request.client.host if request.client else "unknown"
            method = request.method
            url = str(request.url)
            
            # Log the request
            request_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.getpid()}"
            debug_to_stdio(f"REQUEST {request_id}: {method} {url} from {client_host}")
            
            # Try to get request body for debugging
            body = None
            if method in ["POST", "PUT", "PATCH"]:
                try:
                    # Create a copy of the request to read the body
                    body_bytes = await request.body()
                    # Log first 1000 chars only to avoid huge logs
                    if body_bytes:
                        try:
                            body = body_bytes.decode('utf-8')[:1000]
                            debug_to_stdio(f"REQUEST BODY {request_id}: {body}")
                        except UnicodeDecodeError:
                            debug_to_stdio(f"REQUEST BODY {request_id}: [Binary data]")
                except Exception as e:
                    debug_to_stdio(f"Error reading request body: {e}")
            
            try:
                # Pass the request to the next middleware/route handler
                response = await call_next(request)
                
                # Log the response status
                debug_to_stdio(f"RESPONSE {request_id}: {response.status_code}")
                
                return response
            except Exception as e:
                debug_to_stdio(f"ERROR {request_id}: {str(e)}")
                raise
    
    app = FastAPI(
        title="MCP Firewall",
        description="Firewall with rules engine for filtering text when using LLMs",
        version="1.0.0",
        # Disable docs to reduce complexity
        docs_url=None,
        redoc_url=None
    )
    
    # Add request logging middleware
    app.add_middleware(RequestLoggingMiddleware)
    
    # Add CORS middleware to allow requests from any origin
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Simplified MCP server setup
    mcp_server = FastMCP(
        app=app,
        metadata={
            "name": "MCP Firewall",
            "description": "Firewall with rules engine for filtering text when using LLMs",
            "version": "1.0.0",
            "protocolVersion": "2.0"
        }
    )
    debug_to_stdio("Successfully created FastAPI app and MCP server")
except Exception as e:
    debug_to_stdio(f"Error creating FastAPI app or MCP server: {e}")
    sys.exit(1)  # Exit if we can't even create the server

# Define MCP tools with lazy loading
@mcp_server.tool()
def process_text(text: str) -> Dict:
    """Process text through the firewall rules engine.

    Args:
        text: The text to process

    Returns:
        A dictionary with processed text and matches
    """
    logger.info(f"Processing text with {len(text)} characters")
    return process_text_impl(text)

@mcp_server.tool()
def get_rules() -> Dict:
    """Get all firewall rules.

    Returns:
        A dictionary with all rules
    """
    logger.info("Getting all rules")
    return get_rules_impl()

@mcp_server.tool()
def add_rule(name: str, pattern: str, replacement: str = "<REDACTED>",
            description: str = "", enabled: bool = True) -> Dict:
    """Add a new firewall rule.

    Args:
        name: Name of the rule
        pattern: Regex pattern to match
        replacement: Text to replace matches with
        description: Description of the rule
        enabled: Whether the rule is enabled

    Returns:
        Success status and the new rule
    """
    logger.info(f"Adding new rule: {name}")
    rule_data = {
        "name": name,
        "pattern": pattern,
        "replacement": replacement,
        "description": description,
        "enabled": enabled
    }
    return add_rule_impl(rule_data)

@mcp_server.tool()
def update_rule(rule_id: str, name: Optional[str] = None, pattern: Optional[str] = None,
               replacement: Optional[str] = None, description: Optional[str] = None,
               enabled: Optional[bool] = None) -> Dict:
    """Update an existing firewall rule.

    Args:
        rule_id: ID of the rule to update
        name: New name for the rule
        pattern: New regex pattern
        replacement: New replacement text
        description: New description
        enabled: New enabled status

    Returns:
        Success status and the updated rule
    """
    logger.info(f"Updating rule: {rule_id}")
    updates = {}
    if name is not None: updates["name"] = name
    if pattern is not None: updates["pattern"] = pattern
    if replacement is not None: updates["replacement"] = replacement
    if description is not None: updates["description"] = description
    if enabled is not None: updates["enabled"] = enabled
    
    return update_rule_impl(rule_id, updates)

@mcp_server.tool()
def delete_rule(rule_id: str) -> Dict:
    """Delete a firewall rule.

    Args:
        rule_id: ID of the rule to delete

    Returns:
        Success status
    """
    logger.info(f"Deleting rule: {rule_id}")
    return delete_rule_impl(rule_id)

@mcp_server.tool()
def reset_rules() -> Dict:
    """Reset rules to defaults.
    
    Returns:
        Success status
    """
    logger.info("Resetting rules to defaults")
    return reset_rules_impl()

# Define API endpoints
@app.get("/")
async def root():
    debug_to_stdio("Root endpoint called")
    return {
        "name": "MCP Firewall",
        "version": "1.0.0",
        "description": "Firewall with rules engine for filtering text when using LLMs",
        "protocolVersion": "2.0"
    }

@app.get("/api")
async def api_root():
    debug_to_stdio("API root endpoint called")
    return {
        "name": "MCP Firewall", 
        "version": "1.0.0",
        "protocolVersion": "2.0"
    }

@app.get("/api/v1")
async def api_v1():
    debug_to_stdio("API v1 endpoint called")
    return {
        "name": "MCP Firewall", 
        "version": "1.0.0",
        "protocolVersion": "2.0"
    }

# Endpoint for Smithery tool scanning
@app.post("/tools")
@app.get("/tools")
async def tools_list():
    debug_to_stdio("Tools endpoint called for Smithery scanning")
    return {
        "tools": TOOLS,
        "protocolVersion": "2.0",
        "name": "MCP Firewall",
        "version": "1.0.0",
        "description": "Firewall with rules engine for filtering text when using LLMs"
    }

# Add another direct endpoint for tools
@app.post("/api/tools")
@app.get("/api/tools")
async def api_tools_list():
    debug_to_stdio("API tools endpoint called")
    return {
        "tools": TOOLS,
        "protocolVersion": "2.0"
    }

# Dedicated JSON-RPC endpoint
@app.post("/jsonrpc")
async def jsonrpc_specific_endpoint(request: Request):
    debug_to_stdio("Dedicated JSON-RPC endpoint called")
    return await jsonrpc_endpoint(request)

# Add alternative API endpoints for API clients
@app.post("/api/jsonrpc")
async def api_jsonrpc_endpoint(request: Request):
    debug_to_stdio("API JSON-RPC endpoint called")
    return await jsonrpc_endpoint(request)

# Add Smithery-specific endpoints based on conventions
@app.post("/smithery/jsonrpc")
@app.post("/smithery/api")
async def smithery_jsonrpc_endpoint(request: Request):
    debug_to_stdio("Smithery-specific JSON-RPC endpoint called")
    return await jsonrpc_endpoint(request)

@app.get("/smithery/info")
async def smithery_info():
    debug_to_stdio("Smithery info endpoint called")
    return {
        "name": "MCP Firewall",
        "version": "1.0.0",
        "description": "Firewall with rules engine for filtering text when using LLMs",
        "protocolVersion": "2.0",
        "capabilities": {
            "toolDiscovery": True,
            "toolExecution": True
        },
        "tools": TOOLS
    }

@app.get("/smithery/health")
async def smithery_health():
    debug_to_stdio("Smithery health endpoint called")
    return {
        "status": "healthy",
        "version": "1.0.0",
        "protocolVersion": "2.0"
    }

# CRITICAL: Specifically required for Smithery compatibility
# The /mcp endpoint MUST be available for Smithery deployments
@app.get("/mcp")
@app.post("/mcp")
@app.delete("/mcp")
async def mcp_endpoint(request: Request):
    debug_to_stdio(f"MCP endpoint called with method: {request.method}")
    
    # Check for config parameter
    config = request.query_params.get("config", None)
    if config:
        try:
            import base64
            import json
            decoded_config = base64.b64decode(config).decode('utf-8')
            debug_to_stdio(f"Received config: {decoded_config}")
            
            # If this is an initialization request, handle it immediately
            if "initialize" in decoded_config.lower():
                try:
                    config_json = json.loads(decoded_config)
                    debug_to_stdio(f"Parsed config JSON: {config_json}")
                    
                    # Return successful initialization response
                    return {
                        "jsonrpc": "2.0",
                        "id": config_json.get("id", "1"),
                        "result": {
                            "protocolVersion": "2.0",
                            "capabilities": {
                                "toolDiscovery": True,
                                "toolExecution": True
                            },
                            "serverInfo": {
                                "name": "MCP Firewall",
                                "version": "1.0.0",
                                "description": "Firewall with rules engine for filtering text when using LLMs"
                            }
                        }
                    }
                except json.JSONDecodeError:
                    debug_to_stdio("Failed to parse config as JSON")
        except Exception as e:
            debug_to_stdio(f"Error processing config: {e}")
    
    # Handle based on HTTP method
    if request.method == "GET":
        # Return tool discovery info
        return {
            "protocolVersion": "2.0",
            "tools": TOOLS,
            "name": "MCP Firewall",
            "version": "1.0.0",
            "description": "Firewall with rules engine for filtering text when using LLMs"
        }
    elif request.method == "POST":
        # Handle as JSON-RPC request
        return await jsonrpc_endpoint(request)
    else:  # DELETE
        # Handle connection termination
        debug_to_stdio("DELETE request to /mcp - terminating connection")
        return {
            "status": "connection_closed",
            "message": "Connection terminated successfully"
        }

@app.get("/api/v2")
@app.post("/api/v2")
async def api_v2(request: Request):
    debug_to_stdio("API v2 endpoint called")
    if request.method == "POST":
        return await jsonrpc_endpoint(request)
    return {
        "name": "MCP Firewall",
        "version": "1.0.0",
        "protocolVersion": "2.0",
        "apiVersion": "2.0",
        "tools": TOOLS
    }

# Direct tool execution endpoint for simpler clients
@app.post("/execute/{tool_name}")
async def execute_tool(tool_name: str, request: Request):
    debug_to_stdio(f"Execute endpoint called for tool: {tool_name}")
    try:
        body = await request.json()
        debug_to_stdio(f"Execute request body: {body}")
        
        # Check if the tool exists
        tool_exists = False
        for tool in TOOLS:
            if tool["name"] == tool_name:
                tool_exists = True
                break
                
        if not tool_exists:
            debug_to_stdio(f"Tool not found: {tool_name}")
            return {
                "error": {
                    "code": -32601,
                    "message": f"Tool not found: {tool_name}"
                }
            }
        
        # Process based on tool name
        if tool_name == "process_text":
            text = body.get("text", "")
            result = process_text_impl(text)
            return result
            
        elif tool_name == "get_rules":
            result = get_rules_impl()
            return result
            
        elif tool_name == "add_rule":
            result = add_rule_impl(body)
            return result
            
        elif tool_name == "update_rule":
            rule_id = body.get("rule_id", "")
            updates = {k: v for k, v in body.items() if k != "rule_id"}
            result = update_rule_impl(rule_id, updates)
            return result
            
        elif tool_name == "delete_rule":
            rule_id = body.get("rule_id", "")
            result = delete_rule_impl(rule_id)
            return result
            
        elif tool_name == "reset_rules":
            result = reset_rules_impl()
            return result
            
        else:
            return {
                "error": {
                    "code": -32601,
                    "message": f"Tool not implemented: {tool_name}"
                }
            }
    
    except Exception as e:
        debug_to_stdio(f"Error executing tool {tool_name}: {e}")
        import traceback
        debug_to_stdio(traceback.format_exc())
        return {
            "error": {
                "code": -32700,
                "message": f"Execution error: {str(e)}"
            }
        }

@app.get("/health")
async def health():
    debug_to_stdio("Health check endpoint called")
    # Perform a basic check that rules can be loaded
    try:
        ensure_rules_loaded()
        rule_count = len(rules)
        return {
            "status": "ok",
            "name": "MCP Firewall",
            "version": "1.0.0",
            "protocolVersion": "2.0",
            "rule_count": rule_count,
            "rules_loaded": rules_loaded,
            "endpoints": [
                "/", 
                "/api",
                "/api/v1",
                "/api/v2",
                "/tools",
                "/api/tools",
                "/jsonrpc",
                "/api/jsonrpc",
                "/smithery/jsonrpc",
                "/smithery/api",
                "/smithery/info",
                "/smithery/health",
                "/execute/{tool_name}",
                "/health",
                "/mcp"
            ],
            "protocols_supported": ["MCP", "JSON-RPC 2.0"],
            "tools_supported": [tool["name"] for tool in TOOLS],
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        debug_to_stdio(f"Health check failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "name": "MCP Firewall",
            "version": "1.0.0",
            "protocolVersion": "2.0",
            "timestamp": datetime.now().isoformat()
        }

# Helper functions for JSON-RPC handling
def create_jsonrpc_response(result=None, error=None, id="1"):
    """Create a JSON-RPC 2.0 response"""
    response = {
        "jsonrpc": "2.0",
        "id": id
    }
    
    if result is not None:
        response["result"] = result
    
    if error is not None:
        response["error"] = error
    
    return response

# JSON-RPC endpoint for Smithery
@app.post("/")
async def jsonrpc_endpoint(request: Request):
    debug_to_stdio("JSON-RPC endpoint called")
    try:
        data = await request.json()
        debug_to_stdio(f"Received JSON-RPC request: {data}")
        
        # Check if this is a JSON-RPC request
        if "jsonrpc" in data and "method" in data:
            jsonrpc_version = data.get("jsonrpc", "2.0")
            method = data.get("method", "")
            params = data.get("params", {})
            request_id = data.get("id", "1")
            
            debug_to_stdio(f"JSON-RPC method: {method}")
            
            # Handle discovery methods - support multiple variations of names 
            if method in ["discovery", "getServerInfo", "listTools", "getMetadata", "getProtocolInfo"]:
                debug_to_stdio(f"Handling discovery request with method: {method}")
                discovery_result = {
                    "protocolVersion": "2.0",
                    "capabilities": {
                        "toolDiscovery": True,
                        "toolExecution": True
                    },
                    "serverInfo": {
                        "name": "MCP Firewall",
                        "version": "1.0.0",
                        "description": "Firewall with rules engine for filtering text when using LLMs"
                    },
                    "tools": TOOLS
                }
                
                return create_jsonrpc_response(result=discovery_result, id=request_id)
            
            # Handle smithery-specific discovery method by returning full tool list
            elif method == "smithery.discovery":
                debug_to_stdio("Handling smithery.discovery request")
                # Smithery format with protocol version 2.0
                smithery_result = {
                    "protocolVersion": "2.0",
                    "tools": TOOLS,
                    "name": "MCP Firewall",
                    "version": "1.0.0",
                    "description": "Firewall with rules engine for filtering text when using LLMs"
                }
                
                return create_jsonrpc_response(result=smithery_result, id=request_id)
                
            # Handle initialize method (required by Smithery)
            elif method == "initialize":
                debug_to_stdio("Handling initialize request")
                config = params.get("config", {})
                debug_to_stdio(f"Initialize with config: {config}")
                
                # Return successful initialization response
                initialize_result = {
                    "protocolVersion": "2.0",
                    "capabilities": {
                        "toolDiscovery": True,
                        "toolExecution": True
                    },
                    "serverInfo": {
                        "name": "MCP Firewall",
                        "version": "1.0.0",
                        "description": "Firewall with rules engine for filtering text when using LLMs"
                    }
                }
                
                return create_jsonrpc_response(result=initialize_result, id=request_id)
            
            # Handle process_text method
            elif method == "process_text":
                text = params.get("text", "")
                result = process_text_impl(text)
                return create_jsonrpc_response(result=result, id=request_id)
            
            # Handle get_rules method
            elif method == "get_rules":
                result = get_rules_impl()
                return create_jsonrpc_response(result=result, id=request_id)
            
            # Handle other known methods
            elif method == "add_rule":
                name = params.get("name", "")
                pattern = params.get("pattern", "")
                replacement = params.get("replacement", "<REDACTED>")
                description = params.get("description", "")
                enabled = params.get("enabled", True)
                
                result = add_rule_impl({
                    "name": name,
                    "pattern": pattern,
                    "replacement": replacement,
                    "description": description,
                    "enabled": enabled
                })
                
                return create_jsonrpc_response(result=result, id=request_id)
            
            elif method == "update_rule":
                rule_id = params.get("rule_id", "")
                updates = {}
                
                if "name" in params: updates["name"] = params["name"]
                if "pattern" in params: updates["pattern"] = params["pattern"]
                if "replacement" in params: updates["replacement"] = params["replacement"]
                if "description" in params: updates["description"] = params["description"]
                if "enabled" in params: updates["enabled"] = params["enabled"]
                
                result = update_rule_impl(rule_id, updates)
                return create_jsonrpc_response(result=result, id=request_id)
            
            elif method == "delete_rule":
                rule_id = params.get("rule_id", "")
                result = delete_rule_impl(rule_id)
                return create_jsonrpc_response(result=result, id=request_id)
            
            elif method == "reset_rules":
                result = reset_rules_impl()
                return create_jsonrpc_response(result=result, id=request_id)
            
            # Handle unknown methods
            else:
                debug_to_stdio(f"Unknown JSON-RPC method: {method}")
                return create_jsonrpc_response(
                    error={
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    },
                    id=request_id
                )
        
        # If it's not a JSON-RPC request but has a "tools" key, respond with tools list
        elif "tools" in data:
            debug_to_stdio("Handling direct tools request")
            return {
                "tools": TOOLS,
                "protocolVersion": "2.0"
            }
            
        # If it's not a JSON-RPC request, try to handle as tool discovery
        debug_to_stdio("Handling non-JSON-RPC request as tool discovery")
        return {
            "tools": TOOLS,
            "protocolVersion": "2.0",
            "name": "MCP Firewall",
            "version": "1.0.0",
            "description": "Firewall with rules engine for filtering text when using LLMs"
        }
    
    except Exception as e:
        debug_to_stdio(f"Error processing JSON-RPC request: {e}")
        import traceback
        debug_to_stdio(traceback.format_exc())
        return create_jsonrpc_response(
            error={
                "code": -32700,
                "message": f"Parse error: {str(e)}"
            },
            id="1"
        )

@app.post("/process", response_model=ProcessResponse)
async def process_endpoint(text_request: TextRequest):
    """Process text through the firewall rules engine."""
    logger.info(f"Process endpoint called with {len(text_request.text)} characters")
    return process_text_impl(text_request.text)

@app.get("/rules", response_model=RulesResponse)
async def get_rules_endpoint():
    """Get all firewall rules."""
    logger.info("Get rules endpoint called")
    return get_rules_impl()

@app.post("/rules", response_model=RuleResponse)
async def add_rule_endpoint(rule: RuleBase):
    """Add a new firewall rule."""
    logger.info(f"Add rule endpoint called for {rule.name}")
    result = add_rule_impl(rule.model_dump())
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result["rule"]

@app.put("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule_endpoint(rule_id: str, rule: RuleBase):
    """Update an existing firewall rule."""
    logger.info(f"Update rule endpoint called for {rule_id}")
    result = update_rule_impl(rule_id, rule.model_dump())
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result["rule"]

@app.delete("/rules/{rule_id}")
async def delete_rule_endpoint(rule_id: str):
    """Delete a firewall rule."""
    logger.info(f"Delete rule endpoint called for {rule_id}")
    result = delete_rule_impl(rule_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"success": True}

@app.post("/rules/reset")
async def reset_rules_endpoint():
    """Reset firewall rules to defaults."""
    logger.info("Reset rules endpoint called")
    return reset_rules_impl()

# Add backwards compatibility endpoint
@app.post("/redact")
async def redact_endpoint_legacy(text_request: TextRequest):
    """Legacy endpoint that redirects to the process endpoint."""
    logger.info(f"Legacy redact endpoint called with {len(text_request.text)} characters")
    result = process_text_impl(text_request.text)
    # Convert processed_text key to redacted_text for backward compatibility
    if "processed_text" in result:
        result["redacted_text"] = result.pop("processed_text")
    return result

# Debug function that uses stdio to communicate issues
def debug_to_stdio(message):
    """Print debug message to stdout for Smithery to capture"""
    print(f"DEBUG: {message}", flush=True)
    sys.stdout.flush()

# Ensure rules are loaded on startup for faster response
def preload_rules():
    global rules, rules_loaded
    try:
        debug_to_stdio("Preloading rules at startup")
        # Default to an empty list if loading fails
        rules = []

        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                loaded_rules = json.load(f)
                if loaded_rules:
                    rules = loaded_rules
                    debug_to_stdio(f"Successfully preloaded {len(rules)} rules from file")
                    rules_loaded = True
                    return

        # If no rules file, use default rules
        rules = DEFAULT_RULES.copy()
        debug_to_stdio(f"Preloaded {len(rules)} default rules")
        rules_loaded = True
    except Exception as e:
        debug_to_stdio(f"Error preloading rules: {e}")
        # Continue with empty rules if there's an error
        rules = []
        rules_loaded = True

# Run the server
if __name__ == "__main__":
    # Check environment for port
    import os
    port = int(os.environ.get("PORT", "6366"))
    
    # Check if standard port 80 is requested
    if os.environ.get("USE_PORT_80", "").lower() in ("1", "true", "yes"):
        port = 80
        debug_to_stdio("Using standard web port 80 as requested")
        
    debug_to_stdio(f"Starting MCP Firewall on port {port}")

    # Preload rules to avoid issues with lazy loading
    preload_rules()

    try:
        # Use different settings for Uvicorn to improve stability
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=port,
            log_level="info",
            timeout_keep_alive=120,  # Longer keep-alive
            workers=1  # Single worker for simplicity
        )
    except Exception as e:
        debug_to_stdio(f"Error starting server: {e}")