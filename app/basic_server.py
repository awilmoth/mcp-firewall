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

    # Override log_message to use our debug function
    def log_message(self, format, *args):
        debug(f"{self.address_string()} - {format % args}")

    def _set_headers(self, content_type="application/json"):
        self.send_response(200)
        self.send_header('Content-type', content_type)
        self.send_header('Access-Control-Allow-Origin', '*')  # Allow CORS
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_OPTIONS(self):
        """Handle OPTIONS requests for CORS pre-flight checks"""
        self._set_headers()
        self.wfile.write(b'{}')
    
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

        elif self.path == "/tools" or self.path.startswith("/tools/") or self.path.startswith("/tool/"):
            # Return tools list for Smithery (GET method)
            debug("Serving tools list via GET")
            self._set_headers()
            response = {"tools": TOOLS}
            self.wfile.write(json.dumps(response).encode())

        elif self.path.startswith("/mcp/") or self.path.startswith("/protocol") or self.path.startswith("/execute/"):
            # Handle MCP protocol endpoints via GET
            debug(f"MCP protocol endpoint called via GET: {self.path}")
            self._set_headers()
            response = {"tools": TOOLS, "version": "1.0.0"}
            self.wfile.write(json.dumps(response).encode())

        else:
            # For any other path, serve the tools list anyway to help Smithery
            debug(f"Unknown GET path: {self.path} - defaulting to tools info")
            self._set_headers()
            response = {"tools": TOOLS}
            self.wfile.write(json.dumps(response).encode())
    
    def do_POST(self):
        """Handle POST requests"""
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

        # Handle various tool endpoints - use startswith to match paths more flexibly
        if self.path == "/tools" or self.path.startswith("/tools/") or self.path.startswith("/tool/"):
            # Return tools list for Smithery
            debug("Serving tools list")
            self._set_headers()
            response = {"tools": TOOLS}
            self.wfile.write(json.dumps(response).encode())

        elif self.path == "/process" or self.path == "/process_text" or self.path == "/execute/process_text":
            # Process text endpoint
            debug("Process text endpoint called")
            self._set_headers()
            text = request_json.get("text", "")
            response = {
                "processed_text": text,
                "matches": []
            }
            self.wfile.write(json.dumps(response).encode())

        elif self.path == "/protocol" or self.path.startswith("/mcp/") or self.path.startswith("/execute/"):
            # Handle MCP protocol endpoints
            debug(f"MCP protocol endpoint called: {self.path}")
            self._set_headers()
            # Return a simple compatible response with tools list
            response = {
                "tools": TOOLS,
                "version": "1.0.0"
            }
            self.wfile.write(json.dumps(response).encode())

        else:
            # For any other path, assume it's looking for tools
            debug(f"Unknown path: {self.path} - defaulting to tools list")
            self._set_headers()
            response = {"tools": TOOLS}
            self.wfile.write(json.dumps(response).encode())

# Main server function
def run_server():
    """Run the HTTP server"""
    # Print all environment variables to help debugging
    debug("Environment variables:")
    for key, value in os.environ.items():
        debug(f"  {key}={value}")

    debug(f"Starting basic HTTP server on port {PORT}")
    debug(f"Available tools: {json.dumps(TOOLS)}")

    # Avoid "Address already in use" error
    socketserver.TCPServer.allow_reuse_address = True

    try:
        # Create server
        httpd = socketserver.TCPServer(("0.0.0.0", PORT), BasicHandler)
        debug(f"Server created successfully, listening on 0.0.0.0:{PORT}")

        # Print out available endpoints for debugging
        debug("Available endpoints:")
        debug("  GET / - Basic info")
        debug("  GET /health - Health check")
        debug("  GET /tools - Tools list")
        debug("  POST /tools - Tools list")
        debug("  POST /process - Process text")

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