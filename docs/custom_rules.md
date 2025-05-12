# Creating Custom Redaction Rules for MCP Firewall

This guide explains how to create custom redaction rules for MCP Firewall to protect specific types of sensitive information.

## Rule Components

Each redaction rule has the following components:

- **ID**: Unique identifier (auto-generated if not provided)
- **Name**: Human-readable name
- **Pattern**: Regular expression to match sensitive information
- **Replacement**: Text to replace matches with (e.g., `<CREDIT_CARD>`)
- **Description**: What the rule is for
- **Enabled**: Whether the rule is active

## Adding Rules via API

You can add rules using the REST API:

```bash
curl -X POST http://localhost:6366/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AWS Key",
    "pattern": "AKIA[0-9A-Z]{16}",
    "replacement": "<AWS_KEY>",
    "description": "AWS Access Key ID"
  }'
```

## Adding Rules via MCP

If you're using Claude with MCP Firewall, you can use MCP tools to add rules:

```
add_rule(
    name="AWS Key",
    pattern="AKIA[0-9A-Z]{16}",
    replacement="<AWS_KEY>",
    description="AWS Access Key ID"
)
```

## Common Rule Patterns

Here are some example patterns for common sensitive information:

### Cloud Credentials

#### AWS Access Key
```
"pattern": "AKIA[0-9A-Z]{16}"
```

#### AWS Secret Key
```
"pattern": "[0-9a-zA-Z/+]{40}"
```

#### Google API Key
```
"pattern": "AIza[0-9A-Za-z\\-_]{35}"
```

### Crypto

#### Bitcoin Address
```
"pattern": "\\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\\b"
```

#### Ethereum Address
```
"pattern": "0x[a-fA-F0-9]{40}"
```

### Database Connection Strings

#### MySQL
```
"pattern": "mysql:\\/\\/\\S+:\\S+@\\S+\\/\\S+"
```

#### PostgreSQL
```
"pattern": "postgres:\\/\\/\\S+:\\S+@\\S+\\/\\S+"
```

### Tokens

#### JWT
```
"pattern": "eyJ[a-zA-Z0-9_-]{5,}\\.eyJ[a-zA-Z0-9_-]{5,}\\.[a-zA-Z0-9_-]{5,}"
```

#### OAuth Token
```
"pattern": "ya29\\.[0-9A-Za-z\\-_]+"
```

## Testing Rules

After adding a rule, you can test it by sending text to the redaction endpoint:

```bash
curl -X POST http://localhost:6366/redact \
  -H "Content-Type: application/json" \
  -d '{
    "text": "My AWS key is AKIAIOSFODNN7EXAMPLE"
  }'
```

## Best Practices

1. **Balance precision and recall**
   - Too specific: May miss variations
   - Too general: May cause false positives

2. **Test thoroughly** with different variations

3. **Start with enabled=false** for testing in production

4. **Use descriptive replacements** like `<AWS_KEY>` instead of generic `<REDACTED>`

5. **Document your rules** for future reference

6. **Update regularly** as new types of sensitive information emerge

## Example Rule Set

Here's a comprehensive set of rules you might want to implement:

```json
[
  {
    "name": "SSN",
    "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    "replacement": "<SSN>",
    "description": "US Social Security Number"
  },
  {
    "name": "Credit Card",
    "pattern": "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b",
    "replacement": "<CREDIT_CARD>",
    "description": "Credit Card Number"
  },
  {
    "name": "Email",
    "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
    "replacement": "<EMAIL>",
    "description": "Email Address"
  },
  {
    "name": "Phone",
    "pattern": "\\b(?:\\+\\d{1,2}\\s)?\\(?\\d{3}\\)?[\\s.-]?\\d{3}[\\s.-]?\\d{4}\\b",
    "replacement": "<PHONE>",
    "description": "Phone Number"
  },
  {
    "name": "Password",
    "pattern": "(?i)password[=:]\\s*\\S+",
    "replacement": "<PASSWORD>",
    "description": "Password values in text"
  },
  {
    "name": "API Key",
    "pattern": "(?i)(api[_-]?key|access[_-]?token|token|secret)[=:]\\s*\\S+",
    "replacement": "<API_KEY>",
    "description": "API keys and tokens"
  },
  {
    "name": "AWS Key",
    "pattern": "AKIA[0-9A-Z]{16}",
    "replacement": "<AWS_KEY>",
    "description": "AWS Access Key ID"
  },
  {
    "name": "IP Address",
    "pattern": "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b",
    "replacement": "<IP_ADDRESS>",
    "description": "IPv4 address"
  }
]
```