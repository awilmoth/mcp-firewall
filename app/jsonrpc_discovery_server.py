#!/usr/bin/env python3
"""
Combined JSON-RPC 2.0 and Smithery discovery-compatible HTTP server.
"""
import http.server
import socketserver
import json
import sys
import os

# Debug function
def debug(message):
    """Print debug message to stdout for Smithery to capture"""
    print(f"DEBUG: {message}", flush=True)
    sys.stdout.flush()

# Define port
PORT = int(os.environ.get("PORT", 6366))

# Define tools
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
    }
]

# Server metadata
SERVER_INFO = {
    "name": "MCP Firewall",
    "version": "1.0.0",
    "description": "Firewall with rules engine for filtering text when using LLMs"
}

# Create a JSON-RPC 2.0 response
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

# Parse a JSON-RPC 2.0 request
def parse_jsonrpc_request(data):
    """Parse a JSON-RPC 2.0 request"""
    try:
        request = json.loads(data.decode('utf-8'))
        return {
            "jsonrpc": request.get("jsonrpc", "2.0"),
            "method": request.get("method", ""),
            "params": request.get("params", {}),
            "id": request.get("id", "1")
        }
    except Exception as e:
        debug(f"Error parsing JSON-RPC request: {e}")
        return {
            "jsonrpc": "2.0",
            "method": "",
            "params": {},
            "id": "1"
        }

class JSONRPCDiscoveryHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler with JSON-RPC 2.0 and discovery support"""
    
    # Override log_message to use our debug function
    def log_message(self, format, *args):
        debug(f"{self.address_string()} - {format % args}")
    
    def _set_headers(self, content_type="application/json"):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def _send_jsonrpc_response(self, result=None, error=None, id="1"):
        """Send a JSON-RPC 2.0 response"""
        response = create_jsonrpc_response(result, error, id)
        self._set_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS pre-flight checks"""
        debug("OPTIONS request received")
        self._set_headers()
        self.wfile.write(b'{}')
    
    def do_GET(self):
        """Handle GET requests"""
        debug(f"GET request received: {self.path}")
        
        # Health check endpoint - not JSON-RPC
        if self.path == "/health":
            self._set_headers()
            response = {"status": "ok", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
            return
        
        # For all other GET requests, respond with JSON-RPC discovery
        discovery_result = {
            "protocolVersion": "1.0",
            "capabilities": {
                "toolDiscovery": True,
                "toolExecution": True
            },
            "serverInfo": SERVER_INFO,
            "tools": TOOLS
        }
        
        self._send_jsonrpc_response(result=discovery_result, id="discovery")
    
    def do_POST(self):
        """Handle POST requests"""
        debug(f"POST request received: {self.path}")
        
        # Get request body
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        # Parse as JSON-RPC 2.0 request
        request = parse_jsonrpc_request(post_data)
        debug(f"Parsed JSON-RPC request: {request}")
        
        method = request["method"]
        params = request["params"]
        req_id = request["id"]
        
        # Health check endpoint - not JSON-RPC
        if self.path == "/health":
            self._set_headers()
            response = {"status": "ok", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
            return
        
        # Handle specific methods
        if method == "getServerInfo" or method == "discovery":
            debug("Handling discovery/getServerInfo request")
            discovery_result = {
                "protocolVersion": "1.0",
                "capabilities": {
                    "toolDiscovery": True,
                    "toolExecution": True
                },
                "serverInfo": SERVER_INFO,
                "tools": TOOLS
            }
            self._send_jsonrpc_response(result=discovery_result, id=req_id)
            return
        
        # Process text method
        if method == "process_text" or self.path.endswith("/process_text"):
            text = params.get("text", "")
            debug(f"Processing text: {text[:30]}...")
            
            result = {
                "processed_text": text,
                "matches": []
            }
            
            self._send_jsonrpc_response(result=result, id=req_id)
            return
        
        # Get rules method
        if method == "get_rules" or self.path.endswith("/get_rules"):
            debug("Getting rules")
            
            result = {
                "rules": []
            }
            
            self._send_jsonrpc_response(result=result, id=req_id)
            return
        
        # For any other request, return discovery information
        debug("Returning discovery info for unknown method/path")
        discovery_result = {
            "protocolVersion": "1.0",
            "capabilities": {
                "toolDiscovery": True,
                "toolExecution": True
            },
            "serverInfo": SERVER_INFO,
            "tools": TOOLS
        }
        self._send_jsonrpc_response(result=discovery_result, id=req_id)

# Main server function
def run_server():
    """Run the HTTP server"""
    # Print environment variables
    debug("Environment variables:")
    for key, value in sorted(os.environ.items()):
        debug(f"  {key}={value}")
    
    debug(f"Starting JSON-RPC discovery server on port {PORT}")
    
    # Avoid "Address already in use" error
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        # Create server
        httpd = socketserver.TCPServer(("0.0.0.0", PORT), JSONRPCDiscoveryHandler)
        debug(f"Server created successfully, listening on 0.0.0.0:{PORT}")
        
        # Print sample response
        sample_response = create_jsonrpc_response(
            result={
                "protocolVersion": "1.0",
                "capabilities": {
                    "toolDiscovery": True,
                    "toolExecution": True
                },
                "serverInfo": SERVER_INFO,
                "tools": TOOLS
            },
            id="1"
        )
        debug(f"Sample JSON-RPC discovery response: {json.dumps(sample_response, indent=2)}")
        
        # Print available endpoints
        debug("Available endpoints:")
        debug("  GET /health - Health check")
        debug("  GET /* - JSON-RPC discovery response")
        debug("  POST /* - Handles JSON-RPC requests")
        
        # Start server
        debug("Starting server - ready to accept connections")
        httpd.serve_forever()
    except Exception as e:
        debug(f"Error starting server: {e}")
        debug(f"Exception details: {str(e.__class__.__name__)}: {str(e)}")
        import traceback
        debug(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    run_server()