#!/usr/bin/env python3
"""
JSON-RPC 2.0 compatible HTTP server for Smithery deployment.
This server follows the JSON-RPC 2.0 specification that Smithery expects.
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

class JSONRPCHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler with JSON-RPC 2.0 support"""
    
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
        response = {
            "jsonrpc": "2.0",
            "id": id
        }
        
        if result is not None:
            response["result"] = result
        
        if error is not None:
            response["error"] = error
        
        self._set_headers()
        self.wfile.write(json.dumps(response).encode())
    
    def _parse_jsonrpc_request(self, data):
        """Parse a JSON-RPC 2.0 request and return method, params, and id"""
        try:
            request = json.loads(data.decode('utf-8'))
            debug(f"Parsed JSON-RPC request: {request}")
            
            # Default values
            method = request.get("method", "")
            params = request.get("params", {})
            id = request.get("id", "1")
            
            return method, params, id
        except Exception as e:
            debug(f"Error parsing JSON-RPC request: {e}")
            return "", {}, "1"
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS pre-flight checks"""
        debug("OPTIONS request received")
        self._set_headers()
        self.wfile.write(b'{}')
    
    def do_GET(self):
        """Handle GET requests"""
        debug(f"GET request received: {self.path}")
        
        # Health check endpoint
        if self.path == "/health":
            self._set_headers()
            response = {"status": "ok", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
            return
        
        # For all other GET requests, respond with a JSON-RPC success with tools
        self._send_jsonrpc_response(
            result={"tools": TOOLS},
            id="1"
        )
    
    def do_POST(self):
        """Handle POST requests with JSON-RPC 2.0 support"""
        debug(f"POST request received: {self.path}")
        
        # Get request body (if any)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        # Special case for /health endpoint
        if self.path == "/health":
            self._set_headers()
            response = {"status": "ok", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
            return
        
        # Parse JSON-RPC request
        method, params, req_id = self._parse_jsonrpc_request(post_data)
        debug(f"Parsed method: {method}, params: {params}, id: {req_id}")
        
        # Process text endpoint
        if method == "process_text" or self.path.endswith("/process_text"):
            text = params.get("text", "")
            debug(f"Processing text: {text[:30]}...")
            
            result = {
                "processed_text": text,
                "matches": []
            }
            
            self._send_jsonrpc_response(result=result, id=req_id)
            return
        
        # Get rules endpoint
        if method == "get_rules" or self.path.endswith("/get_rules"):
            debug("Getting rules")
            
            result = {
                "rules": []
            }
            
            self._send_jsonrpc_response(result=result, id=req_id)
            return
        
        # Default case: return list of tools
        debug("Returning tools list by default")
        self._send_jsonrpc_response(
            result={"tools": TOOLS},
            id=req_id
        )

# Main server function
def run_server():
    """Run the HTTP server with JSON-RPC 2.0 support"""
    # Print all environment variables to help debugging
    debug("Environment variables:")
    for key, value in sorted(os.environ.items()):
        debug(f"  {key}={value}")
    
    debug(f"Starting JSON-RPC 2.0 server on port {PORT}")
    debug(f"Available tools: {json.dumps(TOOLS)}")
    
    # Avoid "Address already in use" error
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        # Create server
        httpd = socketserver.TCPServer(("0.0.0.0", PORT), JSONRPCHandler)
        debug(f"Server created successfully, listening on 0.0.0.0:{PORT}")
        
        # Print out available endpoints for debugging
        debug("Available endpoints:")
        debug("  GET /health - Health check")
        debug("  POST /tools - Tools list (JSON-RPC 2.0)")
        debug("  POST /process_text - Process text (JSON-RPC 2.0)")
        
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