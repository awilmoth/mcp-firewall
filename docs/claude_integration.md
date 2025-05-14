# Integrating MCP Firewall with Claude

This guide explains how to integrate MCP Firewall with Claude to process text through its rules engine.

## Overview

MCP Firewall works as a preprocessing layer for your Claude interactions, using its rules engine to process text according to defined patterns and policies. By default, it comes with rules for sensitive information like:

- Social Security Numbers
- Credit Card Numbers
- Email Addresses
- Phone Numbers
- API Keys
- Passwords

You can customize existing rules or add your own to implement any text processing policy your application requires.

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

### 3. Configure Claude to Use MCP Firewall

For Claude CLI:

```bash
claude --mcp-servers=mcp_firewall
```

For Claude API, include the MCP configuration in your API request.

## Usage Examples

### Basic Usage

When you send a prompt to Claude, text will be automatically processed through your rules:

**Original Prompt:**
```
My SSN is 123-45-6789 and my credit card number is 4111-1111-1111-1111.
Can you analyze this customer data?
```

**What Claude Receives (with default rules):**
```
My SSN is <SSN> and my credit card number is <CREDIT_CARD>.
Can you analyze this customer data?
```

### Managing Rules with Claude

You can use Claude to manage the firewall rules:

**Get Current Rules:**
```
What rules are currently configured in the MCP Firewall?
```

**Add a New Rule:**
```
Add a rule to process Bitcoin wallet addresses in prompts.
```

**Update a Rule:**
```
Update the email rule to use <EMAIL_ADDRESS> instead of <EMAIL>.
```

**Reset Rules:**
```
Reset all firewall rules to defaults.
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

## Usage Considerations

- MCP Firewall's rules engine adds a powerful layer of text processing
- Regular expressions have limitations in pattern matching capabilities
- The effectiveness of the firewall depends on the quality of your rules
- Regularly update your rules to improve detection and processing
- For sensitive information protection, review prompts before sending to ensure proper processing