#!/usr/bin/env python3
import os
import sys
import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

# Setup minimal logging to file
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'firewall.log'))
    ]
)
logger = logging.getLogger("MCPFirewall")

# Initialize FastAPI and MCP
from fastapi import FastAPI, Request, HTTPException
import uvicorn
from pydantic import BaseModel

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
    is_regex: bool = True

class RuleResponse(BaseModel):
    id: str
    name: str
    pattern: str
    replacement: str
    description: str
    enabled: bool
    is_regex: bool = True

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
        "enabled": True,
        "is_regex": True
    },
    {
        "id": "cc",
        "name": "Credit Card",
        "description": "Credit Card Number",
        "pattern": r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        "replacement": "<CREDIT_CARD>",
        "enabled": True,
        "is_regex": True
    },
    {
        "id": "email",
        "name": "Email",
        "description": "Email Address",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "replacement": "<EMAIL>",
        "enabled": True,
        "is_regex": True
    },
    {
        "id": "phone",
        "name": "Phone",
        "description": "Phone Number",
        "pattern": r"\b(?:\+\d{1,2}\s)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
        "replacement": "<PHONE>",
        "enabled": True,
        "is_regex": True
    },
    {
        "id": "password",
        "name": "Password",
        "description": "Password values in text",
        "pattern": r"(?i)password[=:]\s*\S+",
        "replacement": "<PASSWORD>",
        "enabled": True,
        "is_regex": True
    },
    {
        "id": "api_key",
        "name": "API Key",
        "description": "API keys and tokens",
        "pattern": r"(?i)(api[_-]?key|access[_-]?token|token|secret)[=:]\s*\S+",
        "replacement": "<API_KEY>",
        "enabled": True,
        "is_regex": True
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
                    rules_loaded = True
                    return
    except Exception as e:
        logger.error(f"Error loading rules: {e}")
    
    # If file doesn't exist or there's an error, use default rules
    rules = DEFAULT_RULES.copy()
    save_rules()  # Save default rules
    rules_loaded = True

def ensure_rules_loaded():
    """Ensure rules are loaded before using them"""
    global rules_loaded
    if not rules_loaded:
        load_rules()

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
            # Check if this is a regex pattern or plain text
            is_regex = rule.get("is_regex", True)  # Default to regex for backward compatibility
            
            if is_regex:
                # Process as regex pattern
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
            else:
                # Process as plain text pattern
                pattern = rule["pattern"]
                
                # Use a simple string replacement for plain text
                if pattern in processed:
                    # Find all occurrences
                    start_idx = 0
                    plain_matches = []
                    
                    while True:
                        start_idx = processed.find(pattern, start_idx)
                        if start_idx == -1:
                            break
                        plain_matches.append((start_idx, start_idx + len(pattern)))
                        start_idx += 1
                    
                    # Process matches in reverse to avoid offset issues
                    for start, end in reversed(plain_matches):
                        original = processed[start:end]
                        replacement = rule["replacement"]
                        
                        # Add to matches
                        matches.append({
                            "original": original,
                            "replacement": replacement,
                            "rule_name": rule["name"],
                            "rule_id": rule["id"]
                        })
                        
                        # Replace in text
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
        "enabled": rule_data.get("enabled", True),
        "is_regex": rule_data.get("is_regex", True)  # Default to regex for backward compatibility
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
        },
        "inputSchema": {
            "type": "object",
            "required": ["text"],
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to process"
                }
            }
        }
    },
    {
        "name": "get_rules",
        "description": "Gets all firewall rules",
        "parameters": {},
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
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
                "description": "Pattern to match (can be regex or plain text based on is_regex parameter)"
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
            },
            "is_regex": {
                "type": "boolean",
                "description": "Whether the pattern is a regex (True) or plain text (False)"
            }
        },
        "inputSchema": {
            "type": "object",
            "required": ["name", "pattern"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name of the rule"
                },
                "pattern": {
                    "type": "string",
                    "description": "Pattern to match (can be regex or plain text based on is_regex parameter)"
                },
                "replacement": {
                    "type": "string",
                    "description": "Text to replace matches with",
                    "default": "<REDACTED>"
                },
                "description": {
                    "type": "string",
                    "description": "Description of the rule",
                    "default": ""
                },
                "enabled": {
                    "type": "boolean",
                    "description": "Whether the rule is enabled",
                    "default": True
                },
                "is_regex": {
                    "type": "boolean",
                    "description": "Whether the pattern is a regex (True) or plain text (False)",
                    "default": True
                }
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
        },
        "inputSchema": {
            "type": "object",
            "required": ["rule_id"],
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "ID of the rule to update"
                },
                "name": {
                    "type": "string",
                    "description": "New name for the rule"
                },
                "pattern": {
                    "type": "string",
                    "description": "New pattern (can be regex or plain text based on is_regex parameter)"
                },
                "replacement": {
                    "type": "string",
                    "description": "New replacement text"
                },
                "description": {
                    "type": "string",
                    "description": "New description"
                },
                "enabled": {
                    "type": "boolean",
                    "description": "New enabled status"
                },
                "is_regex": {
                    "type": "boolean",
                    "description": "Whether the pattern is a regex (True) or plain text (False)"
                }
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
        },
        "inputSchema": {
            "type": "object",
            "required": ["rule_id"],
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "ID of the rule to delete"
                }
            }
        }
    },
    {
        "name": "reset_rules",
        "description": "Resets rules to defaults",
        "parameters": {},
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

# Create FastAPI app with minimal configuration
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="MCP Firewall",
    description="Firewall with rules engine for filtering text when using LLMs",
    version="1.0.0",
    docs_url=None,
    redoc_url=None
)

# Add CORS middleware to allow requests from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS", "PUT", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Origin", "User-Agent"],
)

# MCP server setup
from mcp.server.fastmcp import FastMCP

mcp_server = FastMCP(
    app=app,
    metadata={
        "name": "MCP Firewall",
        "description": "Firewall with rules engine for filtering text when using LLMs",
        "version": "1.0.0",
        "protocolVersion": "2024-11-05"  # Updated to correct protocol version
    }
)

# Define MCP tools
@mcp_server.tool()
def process_text(text: str) -> Dict:
    """Process text through the firewall rules engine."""
    return process_text_impl(text)

@mcp_server.tool()
def get_rules() -> Dict:
    """Get all firewall rules."""
    return get_rules_impl()

@mcp_server.tool()
def add_rule(name: str, pattern: str, replacement: str = "<REDACTED>",
            description: str = "", enabled: bool = True, is_regex: bool = True) -> Dict:
    """Add a new firewall rule."""
    rule_data = {
        "name": name,
        "pattern": pattern,
        "replacement": replacement,
        "description": description,
        "enabled": enabled,
        "is_regex": is_regex
    }
    return add_rule_impl(rule_data)

@mcp_server.tool()
def update_rule(rule_id: str, name: Optional[str] = None, pattern: Optional[str] = None,
               replacement: Optional[str] = None, description: Optional[str] = None,
               enabled: Optional[bool] = None, is_regex: Optional[bool] = None) -> Dict:
    """Update an existing firewall rule."""
    updates = {}
    if name is not None: updates["name"] = name
    if pattern is not None: updates["pattern"] = pattern
    if replacement is not None: updates["replacement"] = replacement
    if description is not None: updates["description"] = description
    if enabled is not None: updates["enabled"] = enabled
    if is_regex is not None: updates["is_regex"] = is_regex
    
    return update_rule_impl(rule_id, updates)

@mcp_server.tool()
def delete_rule(rule_id: str) -> Dict:
    """Delete a firewall rule."""
    return delete_rule_impl(rule_id)

@mcp_server.tool()
def reset_rules() -> Dict:
    """Reset rules to defaults."""
    return reset_rules_impl()

# Helper function for JSON-RPC responses
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

# CRITICAL: Specifically required for Smithery compatibility
# The /mcp endpoint MUST be available for Smithery deployments
@app.get("/mcp")
@app.post("/mcp")
@app.delete("/mcp")
async def mcp_endpoint(request: Request):
    # Check for config parameter
    config = request.query_params.get("config", None)
    if config:
        try:
            import base64
            import json
            decoded_config = base64.b64decode(config).decode('utf-8')
            
            # If this is an initialization request, handle it immediately
            if "initialize" in decoded_config.lower():
                try:
                    config_json = json.loads(decoded_config)
                    
                    # Return successful initialization response
                    return {
                        "jsonrpc": "2.0",
                        "id": config_json.get("id", "1"),
                        "result": {
                            "protocolVersion": "2024-11-05",
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
                    pass
        except Exception:
            pass
    
    # Handle based on HTTP method
    if request.method == "GET":
        # Return tool discovery info
        return {
            "protocolVersion": "2024-11-05",
            "tools": TOOLS,
            "name": "MCP Firewall",
            "version": "1.0.0",
            "description": "Firewall with rules engine for filtering text when using LLMs"
        }
    elif request.method == "POST":
        # Handle POST request
        try:
            body_bytes = await request.body()
            if not body_bytes:
                return {"error": "Empty request body"}
                
            # Parse the JSON request
            try:
                body_str = body_bytes.decode('utf-8')
                import json
                json_data = json.loads(body_str)
                
                # Check if this is a direct tools/list request
                if json_data.get("method") == "tools/list":
                    return {
                        "jsonrpc": "2.0",
                        "id": json_data.get("id", "1"),
                        "result": {
                            "tools": TOOLS,
                            "protocolVersion": "2024-11-05"
                        }
                    }
                    
                # Otherwise handle normally through JSON-RPC endpoint
                return await jsonrpc_endpoint(request)
            except json.JSONDecodeError as e:
                return {"error": f"Invalid JSON: {str(e)}"}
        except Exception as e:
            return {"error": f"Server error: {str(e)}"}
    else:  # DELETE
        # Handle connection termination
        return {
            "status": "connection_closed",
            "message": "Connection terminated successfully"
        }

# JSON-RPC endpoint
@app.post("/")
async def jsonrpc_endpoint(request: Request):
    try:
        data = await request.json()
        
        # Handle direct tool invocations (no jsonrpc wrapper)
        if "invoke" in data and "name" in data:
            tool_name = data.get("name", "")
            tool_params = {}
            request_id = "direct_invoke"
            
            # Execute the appropriate tool
            if tool_name == "process_text":
                text = data.get("text", "")
                result = process_text_impl(text)
                return result
            elif tool_name == "get_rules":
                result = get_rules_impl()
                return result
            elif tool_name == "add_rule":
                result = add_rule_impl(data)
                return result["rule"] if "rule" in result else result
            elif tool_name == "update_rule":
                rule_id = data.get("rule_id", "")
                updates = {k: v for k, v in data.items() if k != "rule_id" and k != "invoke" and k != "name"}
                result = update_rule_impl(rule_id, updates)
                return result["rule"] if "rule" in result else result
            elif tool_name == "delete_rule":
                rule_id = data.get("rule_id", "")
                result = delete_rule_impl(rule_id)
                return result
            elif tool_name == "reset_rules":
                result = reset_rules_impl()
                return result
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        
        # Check if this is a JSON-RPC request
        if "jsonrpc" in data and "method" in data:
            method = data.get("method", "")
            params = data.get("params", {})
            request_id = data.get("id", "1")
            
            # Handle discovery methods
            if method in ["discovery", "getServerInfo", "listTools", "getMetadata", "getProtocolInfo"]:
                discovery_result = {
                    "protocolVersion": "2024-11-05",
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
            
            # Handle tools/list method
            elif method == "smithery.discovery" or method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": TOOLS,
                        "protocolVersion": "2024-11-05"
                    }
                }
                
            # Handle tools/call method
            elif method == "tools/call":
                tool_name = params.get("name", "")
                tool_params = params.get("parameters", {})
                
                # Execute the appropriate tool
                if tool_name == "process_text":
                    text = tool_params.get("text", "")
                    result = process_text_impl(text)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "get_rules":
                    result = get_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "add_rule":
                    result = add_rule_impl(tool_params)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "update_rule":
                    rule_id = tool_params.get("rule_id", "")
                    updates = {k: v for k, v in tool_params.items() if k != "rule_id"}
                    result = update_rule_impl(rule_id, updates)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "delete_rule":
                    rule_id = tool_params.get("rule_id", "")
                    result = delete_rule_impl(rule_id)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "reset_rules":
                    result = reset_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id)
                else:
                    return create_jsonrpc_response(
                        error={
                            "code": -32601,
                            "message": f"Unknown tool: {tool_name}"
                        },
                        id=request_id
                    )
                
            # Handle initialize method
            elif method == "initialize":
                initialize_result = {
                    "protocolVersion": "2024-11-05",
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
            
            # Handle runnable/run method
            elif method == "runnable/run":
                tool_name = params.get("runnable", {}).get("name", "")
                tool_input = params.get("input", {})
                
                # Execute the appropriate tool
                if tool_name == "process_text":
                    text = tool_input.get("text", "")
                    result = process_text_impl(text)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "get_rules":
                    result = get_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "add_rule":
                    result = add_rule_impl(tool_input)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "update_rule":
                    rule_id = tool_input.get("rule_id", "")
                    updates = {k: v for k, v in tool_input.items() if k != "rule_id"}
                    result = update_rule_impl(rule_id, updates)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "delete_rule":
                    rule_id = tool_input.get("rule_id", "")
                    result = delete_rule_impl(rule_id)
                    return create_jsonrpc_response(result=result, id=request_id)
                elif tool_name == "reset_rules":
                    result = reset_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id)
                else:
                    return create_jsonrpc_response(
                        error={
                            "code": -32601,
                            "message": f"Unknown tool: {tool_name}"
                        },
                        id=request_id
                    )
                    
            # Handle process_text method
            elif method == "process_text":
                text = params.get("text", "")
                result = process_text_impl(text)
                return create_jsonrpc_response(result=result, id=request_id)
            
            # Other tool methods
            elif method == "get_rules":
                result = get_rules_impl()
                return create_jsonrpc_response(result=result, id=request_id)
            elif method == "add_rule":
                result = add_rule_impl(params)
                return create_jsonrpc_response(result=result, id=request_id)
            elif method == "update_rule":
                rule_id = params.get("rule_id", "")
                updates = {k: v for k, v in params.items() if k != "rule_id"}
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
                return create_jsonrpc_response(
                    error={
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    },
                    id=request_id
                )
        
        # Default tool discovery response
        return {
            "tools": TOOLS,
            "protocolVersion": "2024-11-05",
            "name": "MCP Firewall",
            "version": "1.0.0",
            "description": "Firewall with rules engine for filtering text when using LLMs"
        }
    
    except Exception as e:
        return create_jsonrpc_response(
            error={
                "code": -32700,
                "message": f"Parse error: {str(e)}"
            },
            id="1"
        )

# REST API endpoints
@app.post("/process", response_model=ProcessResponse)
async def process_endpoint(text_request: TextRequest):
    """Process text through the firewall rules engine."""
    return process_text_impl(text_request.text)

@app.get("/rules", response_model=RulesResponse)
async def get_rules_endpoint():
    """Get all firewall rules."""
    return get_rules_impl()

@app.post("/rules", response_model=RuleResponse)
async def add_rule_endpoint(rule: RuleBase):
    """Add a new firewall rule."""
    result = add_rule_impl(rule.model_dump())
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result["rule"]

@app.put("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule_endpoint(rule_id: str, rule: RuleBase):
    """Update an existing firewall rule."""
    result = update_rule_impl(rule_id, rule.model_dump())
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result["rule"]

@app.delete("/rules/{rule_id}")
async def delete_rule_endpoint(rule_id: str):
    """Delete a firewall rule."""
    result = delete_rule_impl(rule_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return {"success": True}

@app.post("/rules/reset")
async def reset_rules_endpoint():
    """Reset firewall rules to defaults."""
    return reset_rules_impl()

@app.get("/health")
async def health():
    """Health check endpoint."""
    try:
        ensure_rules_loaded()
        rule_count = len(rules)
        return {
            "status": "ok",
            "name": "MCP Firewall",
            "version": "1.0.0",
            "protocolVersion": "2024-11-05",
            "rule_count": rule_count
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "name": "MCP Firewall",
            "version": "1.0.0",
            "protocolVersion": "2024-11-05"
        }

# Direct tool access endpoints
@app.post("/get_rules")
async def get_rules_direct():
    """Direct access to get_rules tool."""
    return get_rules_impl()

@app.post("/process_text")
async def process_text_direct(text_request: dict):
    """Direct access to process_text tool."""
    text = text_request.get("text", "")
    return process_text_impl(text)

@app.post("/add_rule")
async def add_rule_direct(rule_data: dict):
    """Direct access to add_rule tool."""
    result = add_rule_impl(rule_data)
    return result["rule"] if "rule" in result else result

@app.post("/update_rule")
async def update_rule_direct(update_data: dict):
    """Direct access to update_rule tool."""
    rule_id = update_data.get("rule_id", "")
    updates = {k: v for k, v in update_data.items() if k != "rule_id"}
    result = update_rule_impl(rule_id, updates)
    return result["rule"] if "rule" in result else result

@app.post("/delete_rule")
async def delete_rule_direct(delete_data: dict):
    """Direct access to delete_rule tool."""
    rule_id = delete_data.get("rule_id", "")
    return delete_rule_impl(rule_id)

@app.post("/reset_rules")
async def reset_rules_direct():
    """Direct access to reset_rules tool."""
    return reset_rules_impl()

# Ensure rules are loaded on startup
def preload_rules():
    global rules, rules_loaded
    try:
        # Default to an empty list if loading fails
        rules = []

        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                loaded_rules = json.load(f)
                if loaded_rules:
                    rules = loaded_rules
                    rules_loaded = True
                    return

        # If no rules file, use default rules
        rules = DEFAULT_RULES.copy()
        rules_loaded = True
    except Exception:
        # Continue with empty rules if there's an error
        rules = []
        rules_loaded = True

# Run the server
if __name__ == "__main__":
    # Check environment for port
    port = int(os.environ.get("PORT", "6366"))
    
    # Check if standard port 80 is requested
    if os.environ.get("USE_PORT_80", "").lower() in ("1", "true", "yes"):
        port = 80
        
    # Preload rules
    preload_rules()

    # Run server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        timeout_keep_alive=120,
        workers=1
    )