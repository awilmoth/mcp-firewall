#!/usr/bin/env python3
import os
import sys
import json
import re
import sqlite3
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

# Database file - use environment variable if provided, otherwise use default path
DB_PATH = os.environ.get("DB_PATH", None)
if DB_PATH:
    DB_FILE = DB_PATH
    DB_DIR = os.path.dirname(DB_FILE)
else:
    DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
    DB_FILE = os.path.join(DB_DIR, 'firewall.db')

os.makedirs(DB_DIR, exist_ok=True)
logger.info(f"Using database at: {DB_FILE}")

def init_db():
    """Initialize the SQLite database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Create rules table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            pattern TEXT NOT NULL,
            replacement TEXT,
            enabled INTEGER NOT NULL,
            is_regex INTEGER NOT NULL
        )
        ''')
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

def save_rules():
    """Save rules to SQLite database"""
    try:
        init_db()
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Clear the existing rules
        cursor.execute("DELETE FROM rules")
        
        # Insert all current rules
        for rule in rules:
            cursor.execute(
                "INSERT INTO rules (id, name, description, pattern, replacement, enabled, is_regex) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    rule["id"],
                    rule["name"],
                    rule.get("description", ""),
                    rule["pattern"],
                    rule.get("replacement", "<REDACTED>"),
                    1 if rule.get("enabled", True) else 0,
                    1 if rule.get("is_regex", True) else 0
                )
            )
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error saving rules to database: {e}")

def load_rules():
    """Load rules from SQLite database"""
    global rules, rules_loaded
    
    # Don't reload if already loaded
    if rules_loaded:
        return
    
    try:
        init_db()
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Use dictionary-like rows
        cursor = conn.cursor()
        
        # Check if any rules exist
        cursor.execute("SELECT COUNT(*) FROM rules")
        count = cursor.fetchone()[0]
        
        if count > 0:
            # Load rules from database
            cursor.execute("SELECT * FROM rules")
            loaded_rules = []
            
            for row in cursor.fetchall():
                loaded_rules.append({
                    "id": row["id"],
                    "name": row["name"],
                    "description": row["description"],
                    "pattern": row["pattern"],
                    "replacement": row["replacement"],
                    "enabled": bool(row["enabled"]),
                    "is_regex": bool(row["is_regex"])
                })
            
            if loaded_rules:
                rules = loaded_rules
                rules_loaded = True
                conn.close()
                return
        
        conn.close()
    except Exception as e:
        logger.error(f"Error loading rules from database: {e}")
    
    # If no rules in database or error, use default rules
    rules = DEFAULT_RULES.copy()
    save_rules()  # Save default rules to database
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

    try:
        # Return quickly for very large inputs to avoid timeouts
        if len(text) > 200000:  # 200k characters
            return {
                "processed_text": text[:100] + "... [TEXT TRUNCATED, TOO LARGE TO PROCESS]",
                "matches": [],
                "warning": "Input text exceeds maximum processing size (200K characters)"
            }
        
        # For large but processable inputs, limit CPU usage
        if len(text) > 50000:  # 50k characters
            # Only apply critical rules to large inputs
            critical_rule_ids = ["ssn", "cc", "password", "api_key"]
            filtered_rules = [r for r in rules if r["id"] in critical_rule_ids and r["enabled"]]
            if filtered_rules:
                logger.info(f"Processing large text ({len(text)} chars) with limited rule set ({len(filtered_rules)} rules)")
                # Use filtered rules for processing
                processed = text
                matches = []
                
                # Pre-compile all regex patterns for better performance
                compiled_rules = []
                for rule in filtered_rules:
                    if not rule["enabled"]:
                        continue
                        
                    is_regex = rule.get("is_regex", True)
                    if is_regex:
                        try:
                            compiled_pattern = re.compile(rule["pattern"])
                            compiled_rules.append((rule, compiled_pattern))
                        except re.error:
                            logger.error(f"Invalid regex pattern in rule {rule['name']}: {rule['pattern']}")
                            continue
                    else:
                        compiled_rules.append((rule, None))  # None indicates plain text
                
                # Process all rules - duplicated from main processing logic but faster
                # for large inputs since we're only using a subset of rules
                for rule, compiled_pattern in compiled_rules:
                    # Add timeout check for long-running operations
                    is_regex = rule.get("is_regex", True)
                    
                    try:
                        if is_regex and compiled_pattern:
                            # Process as regex pattern - use pre-compiled pattern
                            rule_matches = list(compiled_pattern.finditer(processed))
                            
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
                            
                            # Only process if pattern exists
                            if pattern and pattern in processed:
                                # Find all occurrences more efficiently
                                start_idx = 0
                                plain_matches = []
                                
                                while True:
                                    start_idx = processed.find(pattern, start_idx)
                                    if start_idx == -1:
                                        break
                                    plain_matches.append((start_idx, start_idx + len(pattern)))
                                    start_idx += len(pattern)  # More efficient than +1
                                
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
                        logger.error(f"Error applying rule {rule['name']} to large text: {e}")
                        continue  # Continue with the next rule
                
                # Return optimized result
                return {
                    "processed_text": processed,
                    "matches": matches,
                    "optimized": True,
                    "rule_count": len(filtered_rules)
                }
        
        # Make a copy to avoid mutating the input
        processed = text
        matches = []
        
        # Pre-compile all regex patterns for better performance
        compiled_rules = []
        for rule in rules:
            if not rule["enabled"]:
                continue
                
            is_regex = rule.get("is_regex", True)
            if is_regex:
                try:
                    compiled_pattern = re.compile(rule["pattern"])
                    compiled_rules.append((rule, compiled_pattern))
                except re.error:
                    logger.error(f"Invalid regex pattern in rule {rule['name']}: {rule['pattern']}")
                    continue
            else:
                compiled_rules.append((rule, None))  # None indicates plain text

        # Process all rules
        for rule, compiled_pattern in compiled_rules:
            is_regex = rule.get("is_regex", True)
            
            try:
                if is_regex and compiled_pattern:
                    # Process as regex pattern - use pre-compiled pattern
                    rule_matches = list(compiled_pattern.finditer(processed))
                    
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
                    
                    # Optimized string replacement for plain text
                    if pattern in processed:
                        # Find all occurrences more efficiently
                        start_idx = 0
                        plain_matches = []
                        
                        while True:
                            start_idx = processed.find(pattern, start_idx)
                            if start_idx == -1:
                                break
                            plain_matches.append((start_idx, start_idx + len(pattern)))
                            start_idx += len(pattern)  # More efficient than +1
                        
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
                continue  # Continue with the next rule

        return {
            "processed_text": processed,
            "matches": matches
        }
    except Exception as e:
        logger.error(f"Error processing text: {e}")
        return {
            "processed_text": text,
            "matches": [],
            "error": str(e)
        }

def get_rules_impl() -> Dict[str, List]:
    """Get all rules"""
    ensure_rules_loaded()
    return {"rules": rules}

def add_rule_impl(rule_data: Dict) -> Dict:
    """Add a new rule"""
    ensure_rules_loaded()
    
    # Validate required parameters
    if not rule_data.get("name") and not rule_data.get("pattern"):
        logger.error(f"Invalid rule data, missing required fields: {json.dumps(rule_data)}")
        return {"error": "Missing required fields: name and pattern"}
    
    # Generate rule ID from name or a default
    rule_name = rule_data.get("name", "Custom Rule")
    rule_id = rule_data.get("id", f"{rule_name.lower().replace(' ', '_')}_{len(rules)}")
    
    # Check if rule with same ID already exists
    if any(r["id"] == rule_id for r in rules):
        rule_id = f"{rule_id}_{len(rules)}"
    
    # Get pattern - default to an empty string but log a warning
    pattern = rule_data.get("pattern", "")
    if not pattern:
        logger.warning(f"Adding rule with empty pattern: {rule_name}")
    
    new_rule = {
        "id": rule_id,
        "name": rule_name,
        "description": rule_data.get("description", ""),
        "pattern": pattern,
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

# Configure timeouts and other settings for better performance
mcp_server = FastMCP(
    app=app,
    metadata={
        "name": "MCP Firewall",
        "description": "Firewall with rules engine for filtering text when using LLMs",
        "version": "1.0.0",
        "protocolVersion": "2024-11-05"  # Updated to correct protocol version
    },
    # Significantly increase timeout to avoid client timeouts
    timeout=120.0,
    # Add other configuration options
    enable_metrics=False
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

# Constants for response formats
RESPONSE_FORMAT_DEFAULT = "default"
RESPONSE_FORMAT_CLAUDE = "claude"

# Helper function for JSON-RPC responses
def create_jsonrpc_response(result=None, error=None, id="1", format_type=RESPONSE_FORMAT_DEFAULT):
    """Create a JSON-RPC 2.0 response"""
    response = {
        "jsonrpc": "2.0",
        "id": id
    }
    
    if result is not None:
        if format_type == RESPONSE_FORMAT_CLAUDE:
            # Claude AI Tool Result format requires a text field
            if isinstance(result, dict):
                if "processed_text" in result:
                    # For process_text results
                    response["result"] = {
                        "text": f"Processed text: {result['processed_text']}",
                        "original_result": result
                    }
                elif "rule" in result:
                    # For rule operations
                    rule_name = result.get("rule", {}).get("name", "rule")
                    response["result"] = {
                        "text": f"Rule '{rule_name}' operation completed successfully.",
                        "original_result": result
                    }
                elif "rules" in result:
                    # For rules listing
                    num_rules = len(result.get("rules", []))
                    response["result"] = {
                        "text": f"Retrieved {num_rules} rules.",
                        "original_result": result
                    }
                else:
                    # For other operations
                    response["result"] = {
                        "text": f"Operation completed successfully.",
                        "original_result": result
                    }
            else:
                # Non-dict results
                response["result"] = {
                    "text": f"Operation completed with result: {result}",
                    "original_result": result
                }
        else:
            # Default format - return the result as is
            response["result"] = result
    
    if error is not None:
        response["error"] = error
    
    return response

# Helper function to determine response format based on request headers/params
def get_response_format(request):
    """Determine what response format to use based on request headers or params"""
    # Check for format in query params
    format_param = request.query_params.get("format", RESPONSE_FORMAT_DEFAULT)
    if format_param.lower() == "claude":
        return RESPONSE_FORMAT_CLAUDE
    
    # Check for custom headers
    response_format = request.headers.get("X-Response-Format", RESPONSE_FORMAT_DEFAULT)
    if response_format.lower() == "claude":
        return RESPONSE_FORMAT_CLAUDE
        
    # Check for User-Agent containing Claude
    user_agent = request.headers.get("User-Agent", "").lower()
    if "claude" in user_agent:
        return RESPONSE_FORMAT_CLAUDE
    
    # Default format
    return RESPONSE_FORMAT_DEFAULT

# Helper endpoint specifically for Claude API format
@app.post("/claude_format")
async def claude_format_endpoint(request: Request):
    """Special endpoint that formats responses in the Claude AI Tool Result format"""
    try:
        data = await request.json()
        method = data.get("method", "")
        params = data.get("params", {})
        request_id = data.get("id", "1")
        
        logger.info(f"Claude format request: {json.dumps(data)}")
        
        # Process text method
        if method == "process_text" or params.get("name") == "process_text":
            # Extract text from different possible formats
            text = ""
            if "text" in params:
                text = params["text"]
            elif "arguments" in params and "text" in params["arguments"]:
                text = params["arguments"]["text"]
            elif "parameters" in params and "text" in params["parameters"]:
                text = params["parameters"]["text"]
            
            # Process the text
            result = process_text_impl(text)
            
            # Format in Claude's expected format with text field
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "text": f"Processed text: {result['processed_text']}",
                    "original_result": result
                }
            }
        else:
            # For other methods, use standard response
            return create_jsonrpc_response(
                error={
                    "code": -32601,
                    "message": f"Method not supported in Claude format: {method}"
                },
                id=request_id
            , format_type=response_format)
    except Exception as e:
        logger.error(f"Error in Claude format endpoint: {str(e)}")
        return create_jsonrpc_response(
            error={
                "code": -32700,
                "message": f"Parse error: {str(e, format_type=response_format)}"
            },
            id="1"
        )

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
        logger.info(f"JSON-RPC request: {json.dumps(data)}")
        
        # Determine response format
        response_format = get_response_format(request)
        
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
                return create_jsonrpc_response(result=discovery_result, id=request_id, format_type=response_format)
            
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
                # Check both parameters and arguments fields
                if "parameters" in params:
                    tool_params = params.get("parameters", {})
                elif "arguments" in params:
                    tool_params = params.get("arguments", {})
                else:
                    tool_params = {}
                
                logger.info(f"tools/call method: {tool_name}, params: {json.dumps(tool_params)}")
                
                # Execute the appropriate tool
                if tool_name == "process_text":
                    text = tool_params.get("text", "")
                    logger.info(f"Processing text: {text[:50]}{'...' if len(text) > 50 else ''}")
                    result = process_text_impl(text)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "get_rules":
                    result = get_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "add_rule":
                    logger.info(f"Adding rule with params: {json.dumps(tool_params)}")
                    result = add_rule_impl(tool_params)
                    logger.info(f"Add rule result: {json.dumps(result)}")
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "update_rule":
                    rule_id = tool_params.get("rule_id", "")
                    updates = {k: v for k, v in tool_params.items() if k != "rule_id"}
                    result = update_rule_impl(rule_id, updates)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "delete_rule":
                    rule_id = tool_params.get("rule_id", "")
                    result = delete_rule_impl(rule_id)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "reset_rules":
                    result = reset_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                else:
                    return create_jsonrpc_response(
                        error={
                            "code": -32601,
                            "message": f"Unknown tool: {tool_name}"
                        },
                        id=request_id
                    , format_type=response_format)
                
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
                return create_jsonrpc_response(result=initialize_result, id=request_id, format_type=response_format)
            
            # Handle runnable/run method
            elif method == "runnable/run":
                tool_name = params.get("runnable", {}).get("name", "")
                tool_input = params.get("input", {}) or params.get("arguments", {})
                
                logger.info(f"runnable/run method: {tool_name}, input: {json.dumps(tool_input)}")
                
                # Execute the appropriate tool
                if tool_name == "process_text":
                    text = tool_input.get("text", "")
                    result = process_text_impl(text)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "get_rules":
                    result = get_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "add_rule":
                    result = add_rule_impl(tool_input)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "update_rule":
                    rule_id = tool_input.get("rule_id", "")
                    updates = {k: v for k, v in tool_input.items() if k != "rule_id"}
                    result = update_rule_impl(rule_id, updates)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "delete_rule":
                    rule_id = tool_input.get("rule_id", "")
                    result = delete_rule_impl(rule_id)
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                elif tool_name == "reset_rules":
                    result = reset_rules_impl()
                    return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
                else:
                    return create_jsonrpc_response(
                        error={
                            "code": -32601,
                            "message": f"Unknown tool: {tool_name}"
                        },
                        id=request_id
                    , format_type=response_format)
                    
            # Handle process_text method
            elif method == "process_text":
                text = params.get("text", "")
                result = process_text_impl(text)
                return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
            
            # Other tool methods
            elif method == "get_rules":
                result = get_rules_impl()
                return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
            elif method == "add_rule":
                result = add_rule_impl(params)
                return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
            elif method == "update_rule":
                rule_id = params.get("rule_id", "")
                updates = {k: v for k, v in params.items() if k != "rule_id"}
                result = update_rule_impl(rule_id, updates)
                return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
            elif method == "delete_rule":
                rule_id = params.get("rule_id", "")
                result = delete_rule_impl(rule_id)
                return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
            elif method == "reset_rules":
                result = reset_rules_impl()
                return create_jsonrpc_response(result=result, id=request_id, format_type=response_format)
            
            # Handle unknown methods
            else:
                return create_jsonrpc_response(
                    error={
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    },
                    id=request_id
                , format_type=response_format)
        
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
                "message": f"Parse error: {str(e, format_type=response_format)}"
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

# Special endpoint for processing large text with minimal timeout risk
@app.post("/process_large")
async def process_large_endpoint(text_request: TextRequest):
    """Process large text with optimized settings to avoid timeouts."""
    if not text_request.text:
        return {"processed_text": "", "matches": []}
    
    text = text_request.text
    # Set a hard limit on input size
    if len(text) > 500000:  # 500k characters
        return {
            "processed_text": text[:100] + "... [TEXT TRUNCATED, TOO LARGE TO PROCESS]",
            "matches": [],
            "error": "Input exceeds absolute maximum size (500K characters)"
        }
    
    # Apply only critical rules to improve performance
    critical_rule_ids = ["ssn", "cc", "password", "api_key"]
    global rules
    original_rules = rules.copy()
    
    # Filter to critical rules only
    filtered_rules = [r for r in original_rules if r["id"] in critical_rule_ids and r["enabled"]]
    rules = filtered_rules
    
    # Process with optimized rules
    result = process_text_impl(text)
    
    # Restore original rules
    rules = original_rules
    
    # Add metadata to the result
    result["optimized"] = True
    result["rules_applied"] = len(filtered_rules)
    
    return result

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

# SQLite database utilities
@app.get("/db/info")
async def db_info():
    """Get information about the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get the list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Get the count of rules
        cursor.execute("SELECT COUNT(*) FROM rules")
        rule_count = cursor.fetchone()[0]
        
        # Get the schema
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='rules'")
        schema = cursor.fetchone()[0]
        
        # Get database file size
        import os
        db_size = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
        
        return {
            "database_file": DB_FILE,
            "tables": tables,
            "rule_count": rule_count,
            "schema": schema,
            "size_bytes": db_size
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        if 'conn' in locals():
            conn.close()

@app.post("/db/query")
async def db_query(query_data: dict):
    """Execute a read-only SQL query on the database."""
    sql = query_data.get("query", "")
    
    # Safety check - only allow SELECT queries
    sql_lower = sql.lower().strip()
    if not sql_lower.startswith("select"):
        return {"error": "Only SELECT queries are allowed"}
    
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(sql)
        results = [dict(row) for row in cursor.fetchall()]
        
        return {"results": results, "count": len(results)}
    except Exception as e:
        return {"error": str(e)}
    finally:
        if 'conn' in locals():
            conn.close()
            
@app.get("/db/backup")
async def db_backup():
    """Create a backup of the current rules as JSON."""
    ensure_rules_loaded()
    
    try:
        backup_file = os.path.join(DB_DIR, f"rules_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(backup_file, 'w') as f:
            json.dump(rules, f, indent=2)
            
        return {
            "success": True,
            "backup_file": backup_file,
            "rule_count": len(rules)
        }
    except Exception as e:
        return {"error": str(e)}

# Ensure rules are loaded on startup
def preload_rules():
    """Preload rules from database at startup"""
    global rules, rules_loaded
    try:
        # Initialize the database
        init_db()
        
        # Load rules
        load_rules()
    except Exception as e:
        logger.error(f"Error preloading rules: {e}")
        # Default to empty rules if all else fails
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

    # Run server with optimized settings
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        timeout_keep_alive=120,
        workers=1,
        # Increase timeouts to avoid MCP client timeouts
        timeout_graceful_shutdown=30,
        limit_concurrency=100,
        # Increase these limits for large requests
        limit_max_requests=0,
        backlog=2048
    )