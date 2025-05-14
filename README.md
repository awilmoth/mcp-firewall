# MCP Firewall

A Model Control Protocol (MCP) compatible service that provides a text filtering firewall with a powerful rules engine. Protect your data and enforce policies when using Large Language Models like Claude.

## Overview

MCP Firewall acts as a filtering layer with a rules engine that processes text data before sending it to LLMs. It can identify patterns, enforce policies, and transform text content according to customizable rules. It integrates seamlessly with Claude and other MCP-compatible LLMs.

## Features

- **Powerful Rules Engine** for text processing:
  - Pattern matching with regular expressions or plain text
  - Default rules for sensitive information (SSN, Credit Cards, etc.)
  - Customizable replacements and transformations
  - Rule-based policy enforcement
  - Easily add your own custom rules
- **REST API** for direct integration with any application
- **MCP Protocol Support** for seamless integration with Claude and other LLMs
- **Customizable Rules** that can be added, updated, or deleted via API
- **Persistent Storage** of rules across restarts using SQLite database
- **Enhanced Docker Support**:
  - Lightweight container with minimal dependencies
  - Volume mounts for persistent data storage
  - Easy deployment with the included deploy_docker.sh script
- **Smithery Compatible** for enterprise deployment

## Quick Start

### Using Docker

```bash
# Clone the repository
git clone https://github.com/awilmoth/mcp-firewall.git
cd mcp-firewall

# Build the Docker image
docker build -t mcp-firewall .

# Run the container with persistent storage
docker run -d -p 6366:6366 \
  -v $HOME/mcp-firewall-data:/data \
  -v $HOME/mcp-firewall-logs:/logs \
  --name mcp-firewall mcp-firewall

# Alternatively, use the deployment script
./deploy_docker.sh

# Test text processing
curl -X POST http://localhost:6366/process \
  -H "Content-Type: application/json" \
  -d '{"text":"My SSN is 123-45-6789 and my email is test@example.com"}'
```

### Python Installation

```bash
# Clone the repository
git clone https://github.com/awilmoth/mcp-firewall.git
cd mcp-firewall

# Install dependencies
pip install -r requirements.txt

# Run the server
python app/mcp_firewall.py
```

## API Endpoints

### Text Processing

- `POST /process` - Process text through the firewall rules engine
  - Request: `{"text": "text to process"}`
  - Response: `{"processed_text": "processed text", "matches": [...]}`

- `POST /redact` - Legacy endpoint that redirects to process (for backwards compatibility)

### Rules Management

- `GET /rules` - Get all firewall rules
- `POST /rules` - Add a new firewall rule
  - Request: `{"name": "Rule Name", "pattern": "regex pattern", "replacement": "<REPLACEMENT>", "description": "Description", "enabled": true, "is_regex": true}`
- `PUT /rules/{rule_id}` - Update a firewall rule
- `DELETE /rules/{rule_id}` - Delete a firewall rule
- `POST /rules/reset` - Reset firewall rules to defaults

### System

- `GET /health` - Check service health
- `GET /` - Service information

## Claude Integration

To integrate with Claude, configure the `.mcp.json` file to point to the MCP Firewall server:

```json
{
  "mcpServers": {
    "mcp_firewall": {
      "url": "http://localhost:6366",
      "transport": "http",
      "timeout_ms": 60000,
      "protocol_version": "2024-11-05",
      "tools": [
        "process_text",
        "get_rules",
        "add_rule",
        "update_rule",
        "delete_rule",
        "reset_rules"
      ]
    }
  }
}
```

## Smithery Deployment

MCP Firewall can be deployed to Smithery for enterprise use:

```bash
# Deploy to Smithery
./deploy_to_smithery.sh
```

## Docker Deployment

For more control over your Docker deployment, use the included script:

```bash
# Deploy with custom settings
./deploy_docker.sh --port 8080 --data-dir /path/to/data --logs-dir /path/to/logs

# Show all available options
./deploy_docker.sh --help
```

## Database Features

MCP Firewall uses SQLite for persistent storage of rules:

- **Automatic Initialization**: Database is created and populated with default rules if not present
- **Persistent Storage**: Rules survive container restarts when using volume mounts
- **Database Tools**:
  - View database info: `GET /db/info`
  - Run read-only queries: `POST /db/query`
  - Create backups: `GET /db/backup`

## Custom Rules

You can add custom firewall rules via the API. MCP Firewall supports both regex and plain text pattern matching:

```bash
# Add a regex rule for AWS keys
curl -X POST http://localhost:6366/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AWS Key",
    "pattern": "AKIA[0-9A-Z]{16}",
    "replacement": "<AWS_KEY>",
    "description": "AWS Access Key ID",
    "is_regex": true
  }'

# Add a plain text rule
curl -X POST http://localhost:6366/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Company Name",
    "pattern": "Acme Corporation",
    "replacement": "<COMPANY>",
    "description": "Replace company name",
    "is_regex": false
  }'
```

Plain text rules can be more efficient for exact string matches, while regex provides more flexibility for pattern matching.

## Programmatic Usage

You can use MCP Firewall programmatically in Python applications:

```python
import requests

def process_text(text):
    response = requests.post(
        "http://localhost:6366/process",
        json={"text": text}
    )
    result = response.json()
    return result["processed_text"]

# Example usage
processed = process_text("My credit card is 4111-1111-1111-1111")
print(processed)  # "My credit card is <CREDIT_CARD>"
```

## JSON-RPC Support

MCP Firewall supports the JSON-RPC 2.0 protocol for tool discovery and execution:

```bash
# List available tools
curl -X POST http://localhost:6366/ \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list","jsonrpc":"2.0","id":1}'

# Execute a tool
curl -X POST http://localhost:6366/ \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/call","params":{"name":"process_text","arguments":{"text":"Test text"}},"jsonrpc":"2.0","id":2}'
```

## Security and Usage Considerations

MCP Firewall provides a flexible rules engine for text processing but has some considerations:

- Support for both regex patterns and plain text matching, each with different performance characteristics
- The effectiveness depends on the quality and comprehensiveness of your rules
- Processing very large texts (>100K characters) is limited to prevent timeouts
- All rules are validated before adding to prevent empty or invalid patterns
- For security use cases, it should be part of a broader security strategy

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.