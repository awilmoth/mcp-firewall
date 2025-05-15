#!/usr/bin/env python3
import re

# Define search pattern for return statements with create_jsonrpc_response
pattern = r'return create_jsonrpc_response\(([^)]*)\)'

# Read mcp_firewall.py
with open('app/mcp_firewall.py', 'r') as f:
    content = f.read()

# Replace with format_type parameter added
modified = re.sub(
    pattern, 
    r'return create_jsonrpc_response(\1, format_type=response_format)', 
    content
)

# Write back the modified file
with open('app/mcp_firewall.py', 'w') as f:
    f.write(modified)

print("Updated all create_jsonrpc_response calls")