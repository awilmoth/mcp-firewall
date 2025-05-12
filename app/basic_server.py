#!/usr/bin/env python3
"""
Ultra-minimal HTTP server for Smithery deployment that doesn't use any external libraries.
This should work even if FastAPI or other dependencies are causing issues.
"""
import http.server
import socketserver
import json
import sys
import os

# Debug function
def debug(message):
    """Print debug message to stdout"""
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

class BasicHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP request handler with GET and POST methods"""
    
    def _set_headers(self, content_type="application/json"):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        debug(f"GET request received: {self.path}")
        
        if self.path == "/" or self.path == "":
            # Root path - return basic info
            self._set_headers()
            response = {
                "name": "MCP Firewall",
                "version": "1.0.0",
                "description": "Firewall with rules engine for filtering text when using LLMs"
            }
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == "/health":
            # Health check
            self._set_headers()
            response = {"status": "ok", "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == "/rules":
            # Get rules
            self._set_headers()
            response = {"rules": []}
            self.wfile.write(json.dumps(response).encode())
        
        else:
            # Unknown path
            self.send_response(404)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())
    
    def do_POST(self):
        """Handle POST requests"""
        debug(f"POST request received: {self.path}")
        
        # Get request body
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            request_json = json.loads(post_data.decode('utf-8'))
            debug(f"Request data: {request_json}")
        except:
            request_json = {}
            debug("No valid JSON data in request")
        
        if self.path == "/tools":
            # Return tools list for Smithery
            self._set_headers()
            response = {"tools": TOOLS}
            self.wfile.write(json.dumps(response).encode())
        
        elif self.path == "/process":
            # Process text
            self._set_headers()
            text = request_json.get("text", "")
            response = {
                "processed_text": text,
                "matches": []
            }
            self.wfile.write(json.dumps(response).encode())
        
        else:
            # Unknown path
            self.send_response(404)
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

# Main server function
def run_server():
    """Run the HTTP server"""
    debug(f"Starting basic HTTP server on port {PORT}")
    
    # Avoid "Address already in use" error
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        # Create server
        httpd = socketserver.TCPServer(("0.0.0.0", PORT), BasicHandler)
        debug("Server created successfully")
        
        # Start server
        debug("Starting server - ready to accept connections")
        httpd.serve_forever()
    except Exception as e:
        debug(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_server()