# MCP Firewall

A Model Control Protocol (MCP) compatible service that provides text redaction capabilities for sensitive information. Protect your data when using Large Language Models like Claude.

## Overview

MCP Firewall acts as a filtering layer that automatically redacts sensitive data patterns before sending text to LLMs, helping to prevent data leakage. It integrates seamlessly with Claude and other MCP-compatible LLMs.

## Features

- **Automatic Redaction** of sensitive information:
  - Social Security Numbers (SSN) 
  - Credit Card Numbers
  - Email Addresses
  - Phone Numbers
  - API Keys
  - Passwords
  - Easily add your own custom patterns
- **REST API** for direct integration with any application
- **MCP Protocol Support** for seamless integration with Claude and other LLMs
- **Customizable Rules** that can be added, updated, or deleted via API
- **Persistent Storage** of rules across restarts
- **Lightweight Docker Container** for easy deployment
- **Smithery Compatible** for enterprise deployment

## Quick Start

### Using Docker

```bash
# Clone the repository
git clone https://github.com/awilmoth/mcp-firewall.git
cd mcp-firewall

# Build the Docker image
docker build -t mcp-firewall .

# Run the container
docker run -d -p 6366:6366 --name mcp-firewall mcp-firewall

# Test redaction
curl -X POST http://localhost:6366/redact \
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

### Redaction

- `POST /redact` - Redact sensitive information from text
  - Request: `{"text": "text to redact"}`
  - Response: `{"redacted_text": "redacted text", "matches": [...]}`

### Rules Management

- `GET /rules` - Get all rules
- `POST /rules` - Add a new rule
  - Request: `{"name": "Rule Name", "pattern": "regex pattern", "replacement": "<REPLACEMENT>", "description": "Description", "enabled": true}`
- `PUT /rules/{rule_id}` - Update a rule
- `DELETE /rules/{rule_id}` - Delete a rule
- `POST /rules/reset` - Reset rules to defaults

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
      "protocol_version": "execute",
      "tools": [
        "redact_text",
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

## Custom Rules

You can add custom redaction rules via the API:

```bash
# Add a new rule for AWS keys
curl -X POST http://localhost:6366/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AWS Key",
    "pattern": "AKIA[0-9A-Z]{16}",
    "replacement": "<AWS_KEY>",
    "description": "AWS Access Key ID"
  }'
```

## Programmatic Usage

You can use MCP Firewall programmatically in Python applications:

```python
import requests

def redact_sensitive_info(text):
    response = requests.post(
        "http://localhost:6366/redact",
        json={"text": text}
    )
    result = response.json()
    return result["redacted_text"]

# Example usage
redacted = redact_sensitive_info("My credit card is 4111-1111-1111-1111")
print(redacted)  # "My credit card is <CREDIT_CARD>"
```

## Security Considerations

MCP Firewall helps protect sensitive information but has limitations:

- It relies on regex patterns that may not catch all variations of sensitive data
- New patterns of sensitive data may require adding new rules
- It should be part of a broader security strategy, not the sole protection

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.