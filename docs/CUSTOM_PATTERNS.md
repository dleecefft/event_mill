# Custom GROK Patterns Guide

Event Mill allows you to extend the built-in GROK patterns with custom regex patterns specific to your organization's log formats, internal applications, and proprietary record structures.

## Quick Start

1. Open `custom_patterns.py` in the Event Mill directory
2. Add your pattern to the `CUSTOM_GROK_PATTERNS` dictionary
3. Restart Event Mill to load the new patterns
4. Use your pattern with the `analyze` command

## Pattern Requirements

| Requirement | Description |
|-------------|-------------|
| **Name** | UPPERCASE with underscores (e.g., `MYAPP_TXID`) |
| **Regex** | Must have exactly ONE capture group `()` |
| **Capture Group** | Defines what value gets extracted and counted |

## Adding Custom Patterns

Edit `custom_patterns.py`:

```python
CUSTOM_GROK_PATTERNS = {
    # Extract transaction IDs like "TXN-12345678"
    "MYAPP_TXID": r"TXN-(\d{8})",
    
    # Extract custom error codes like "ERR:A001"
    "MYAPP_ERRCODE": r"ERR:([A-Z]\d{3})",
    
    # Extract internal user IDs like "uid=jsmith"
    "INTERNAL_UID": r"uid=(\w+)",
}
```

## Usage in Event Mill

```bash
# Use your custom pattern
⚙ mill> analyze MYAPP_TXID app.log mybucket

# List all available patterns (built-in + custom)
⚙ mill> patterns_custom

# For complex one-off patterns, use analyze_rex
⚙ mill> analyze_rex "your-regex-here" file.log bucket
```

## Built-in Patterns Reference

Event Mill includes these built-in patterns:

| Pattern | Description | Example Match |
|---------|-------------|---------------|
| `IP` / `IPV4` | IPv4 addresses | `192.168.1.100` |
| `IPV6` | IPv6 addresses | `2001:db8::1` |
| `MAC` | MAC addresses | `00:1A:2B:3C:4D:5E` |
| `EMAIL` | Email addresses | `user@example.com` |
| `UUID` | UUIDs | `550e8400-e29b-41d4-a716-446655440000` |
| `HTTPSTATUS` | HTTP status codes | `200`, `404`, `500` |
| `HTTPMETHOD` | HTTP methods | `GET`, `POST`, `DELETE` |
| `LOGLEVEL` | Log levels | `INFO`, `ERROR`, `WARN` |
| `USER` | User identifiers | `user=admin` |
| `USERNAME` | Username fields | `username=jsmith` |
| `PORT` | Port numbers | `:8080`, `:443` |
| `PATH` | URL paths | `/api/v1/users` |
| `TIMESTAMP` | ISO timestamps | `2025-01-15T14:30:00` |
| `DATE` | Dates | `2025-01-15` |
| `TIME` | Times | `14:30:00` |
| `INT` | Integers | `12345` |
| `NUMBER` | Numbers (with decimals) | `123.45` |
| `WORD` | Single words | `error` |
| `HOSTNAME` | Hostnames | `server01.example.com` |
| `SID` | Windows Security IDs | `S-1-5-21-...` |

## Example Custom Patterns

### Transaction/Request Tracking

```python
# Correlation IDs (common in microservices)
"CORRELATION_ID": r"correlation[_-]?id[=:\s]+([a-f0-9-]{36})",

# Request IDs (Stripe-style)
"REQUEST_ID": r"req_([a-zA-Z0-9]{16})",

# Trace IDs (OpenTelemetry)
"TRACE_ID": r"trace[_-]?id[=:\s]+([a-f0-9]{32})",
```

### Internal Application Identifiers

```python
# Custom error codes
"MYAPP_ERROR": r"\[E(\d{4})\]",

# Service names
"SERVICE_NAME": r"service[=:\s]+(\w+)",

# Module identifiers
"MODULE_ID": r"\[([A-Z]{3}-\d{3})\]",
```

### User/Account Management

```python
# Employee IDs
"EMPLOYEE_ID": r"emp[_-]?(\d{6})",

# Account numbers
"ACCOUNT_ID": r"acct[_-]?id[=:\s]+(\d{10})",

# Session tokens
"SESSION_TOKEN": r"session[=:\s]+([a-f0-9]{32})",
```

### Infrastructure/DevOps

```python
# Kubernetes pod names
"K8S_POD": r"pod[=:\s]+([a-zA-Z0-9-]+)",

# Docker container IDs
"CONTAINER_ID": r"container[=:\s]+([a-f0-9]{12})",

# VLAN IDs
"VLAN_ID": r"vlan[=:\s]+(\d{1,4})",
```

### Security/Compliance

```python
# Jira ticket IDs
"JIRA_TICKET": r"([A-Z]{2,5}-\d{1,6})",

# Case numbers
"CASE_NUMBER": r"case[=:\s]+(\d{8})",

# Policy IDs
"POLICY_ID": r"policy[=:\s]+([A-Z0-9_]+)",
```

## Pattern Validation

Event Mill automatically validates your patterns on startup:

- ✅ Patterns with exactly 1 capture group are loaded
- ⚠️ Patterns with 0 or 2+ capture groups show a warning
- ❌ Invalid regex syntax shows an error

Run `patterns_custom` to verify your patterns loaded correctly.

## Troubleshooting

### Pattern Not Found

```
Error: Unknown GROK pattern 'MYPATTERN'
```

**Solution**: Check that:
1. Pattern name is UPPERCASE in `custom_patterns.py`
2. You restarted Event Mill after adding the pattern
3. Pattern syntax is valid Python regex

### No Matches Found

```
No matches found for pattern 'MYPATTERN'
```

**Solution**: 
1. Test your regex on sample log lines first
2. Ensure the capture group `()` surrounds the value you want
3. Use `analyze_rex` to test the raw regex directly

### Multiple Capture Groups Error

```
⚠️ MYPATTERN: Expected 1 capture group, found 2
```

**Solution**: Use non-capturing groups `(?:...)` for grouping that shouldn't be extracted:

```python
# Wrong - 2 capture groups
"BAD_PATTERN": r"(error|warn): (\d+)",

# Correct - 1 capture group, 1 non-capturing
"GOOD_PATTERN": r"(?:error|warn): (\d+)",
```

## Best Practices

1. **Use descriptive names**: `MYAPP_TXID` not `TXN`
2. **Document your patterns**: Add comments explaining what each pattern matches
3. **Test before deploying**: Use `analyze_rex` to test regex before adding to custom patterns
4. **Version control**: Keep `custom_patterns.py` in your repo for team sharing
5. **Validate on startup**: Check `patterns_custom` output after changes

## Sharing Patterns

To share custom patterns across your team:

1. Add `custom_patterns.py` to version control
2. Document patterns in your team wiki
3. Use consistent naming conventions (e.g., `TEAMNAME_PATTERN`)

---

*For more information, see the main [Event Mill README](../README.md)*
