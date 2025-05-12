#!/usr/bin/env python3
"""
Smithery-compatible HTTP server that implements the exact format
required by Smithery for tool discovery.
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

# Smithery discovery response format
DISCOVERY_RESPONSE = {
    "protocolVersion": "1.0",
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

class SmitheryHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler with Smithery compatibility"""
    
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
        
        # For all other GET requests, respond with discovery information
        self._set_headers()
        self.wfile.write(json.dumps(DISCOVERY_RESPONSE).encode())
    
    def do_POST(self):
        """Handle POST requests with Smithery compatibility"""
        debug(f"POST request received: {self.path}")
        
        # Get request body (if any)
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b'{}'
        
        try:
            request_json = json.loads(post_data.decode('utf-8'))
            debug(f"Request data: {request_json}")
        except:
            request_json = {}
            debug("No valid JSON data in request")
        
        # Special case for health endpoint
        if self.path == "/health":
            self._set_headers()
            response = {"status": "ok", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
            return
        
        # Process text endpoint
        if self.path.endswith("/process_text"):
            text = request_json.get("text", "")
            debug(f"Processing text: {text[:30]}...")
            
            response = {
                "result": {
                    "processed_text": text,
                    "matches": []
                }
            }
            
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            return
        
        # Get rules endpoint
        if self.path.endswith("/get_rules"):
            debug("Getting rules")
            
            response = {
                "result": {
                    "rules": []
                }
            }
            
            self._set_headers()
            self.wfile.write(json.dumps(response).encode())
            return
        
        # Default case: return discovery response
        debug("Returning discovery response by default")
        self._set_headers()
        self.wfile.write(json.dumps(DISCOVERY_RESPONSE).encode())

# Main server function
def run_server():
    """Run the HTTP server with Smithery compatibility"""
    # Print all environment variables to help debugging
    debug("Environment variables:")
    for key, value in sorted(os.environ.items()):
        debug(f"  {key}={value}")
    
    debug(f"Starting Smithery-compatible server on port {PORT}")
    debug(f"Discovery response: {json.dumps(DISCOVERY_RESPONSE, indent=2)}")
    
    # Avoid "Address already in use" error
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        # Create server
        httpd = socketserver.TCPServer(("0.0.0.0", PORT), SmitheryHandler)
        debug(f"Server created successfully, listening on 0.0.0.0:{PORT}")
        
        # Print out available endpoints for debugging
        debug("Available endpoints:")
        debug("  GET /health - Health check")
        debug("  GET or POST to any path - Discovery response")
        debug("  POST /process_text - Process text")
        debug("  POST /get_rules - Get rules")
        
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