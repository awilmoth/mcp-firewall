# Integrating MCP Firewall with Claude

This guide explains how to integrate MCP Firewall with Claude to protect sensitive information in your prompts.

## Overview

MCP Firewall works as a preprocessing layer for your Claude interactions, automatically redacting sensitive information like:

- Social Security Numbers
- Credit Card Numbers
- Email Addresses
- Phone Numbers
- API Keys
- Passwords
- Any custom patterns you define

## Setup

### 1. Configure MCP Firewall

Ensure MCP Firewall is running and accessible. You can run it locally or as a Docker container:

```bash
# Run as Docker container
docker run -d -p 6366:6366 --name mcp-firewall mcp-firewall
```

### 2. Create `.mcp.json` Configuration

Create a `.mcp.json` file in your Claude project directory with the following content:

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

### 3. Configure Claude to Use MCP Firewall

For Claude CLI:

```bash
claude --mcp-servers=mcp_firewall
```

For Claude API, include the MCP configuration in your API request.

## Usage Examples

### Basic Usage

When you send a prompt to Claude, sensitive information will be automatically redacted:

**Original Prompt:**
```
My SSN is 123-45-6789 and my credit card number is 4111-1111-1111-1111.
Can you analyze this customer data?
```

**What Claude Receives:**
```
My SSN is <SSN> and my credit card number is <CREDIT_CARD>.
Can you analyze this customer data?
```

### Managing Rules with Claude

You can use Claude to manage the redaction rules:

**Get Current Rules:**
```
What rules are currently configured in the MCP Firewall?
```

**Add a New Rule:**
```
Add a rule to redact Bitcoin wallet addresses in prompts.
```

**Update a Rule:**
```
Update the email redaction rule to use <REDACTED_EMAIL> instead of <EMAIL>.
```

**Reset Rules:**
```
Reset all redaction rules to defaults.
```

## Troubleshooting

If the MCP Firewall isn't working correctly, check:

1. Is the MCP Firewall server running? 
   ```bash
   curl http://localhost:6366/health
   ```

2. Is your `.mcp.json` file correctly configured?

3. Did you specify the MCP server when starting Claude?

4. Check the MCP Firewall logs for errors:
   ```bash
   docker logs mcp-firewall
   ```

## Security Considerations

- MCP Firewall adds an important layer of protection but is not foolproof
- Regular expressions might not catch all variants of sensitive information
- Always review prompts before sending to ensure sensitive information is redacted
- Regularly update your rules to cover new types of sensitive information