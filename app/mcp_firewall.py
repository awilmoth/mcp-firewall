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

# Create FastAPI app and MCP server
app = FastAPI(title="MCP Firewall",
              description="Firewall with rules engine for filtering text when using LLMs",
              version="1.0.0")

mcp_server = FastMCP(
    app=app,
    metadata={
        "name": "MCP Firewall",
        "description": "Firewall with rules engine for filtering text when using LLMs",
        "version": "1.0.0"
    }
)

# Do NOT initialize rules here - we'll do it lazily

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
    return {
        "name": "MCP Firewall",
        "version": "1.0.0",
        "description": "Firewall with rules engine for filtering text when using LLMs"
    }

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}

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

# Run the server
if __name__ == "__main__":
    port = 6366
    logger.info(f"Starting MCP Firewall on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)