# Event Mill

**Grinding Events into Intelligence**

Event Mill is an open-source event record analysis platform supporting Security Operations and Detection Engineering teams. Analyze logs directly from Google Cloud Storage without ingesting them into a central SIEM.

## Features

- 🔍 **AI-Powered Analysis** - Gemini 3 Flash integration for intelligent log analysis
- 🎯 **GROK Pattern Extraction** - 25+ built-in patterns + custom pattern support
- 📊 **20 ECS Event Categories** - Aligned with Elastic Common Schema
- 🔗 **OpenTelemetry Mappings** - Semantic conventions for observability
- 🛡️ **Threat Intelligence** - AI-powered investigation with MITRE ATT&CK context
- ⚙️ **Modular Architecture** - Extensible tool system for easy customization
- 🔧 **Detection Engineering** - Generate GROK parsing templates for log pipelines

## Prerequisites

1. Python 3.10+
2. Google Cloud Service Account with Storage Object Viewer permissions
3. Gemini API Key (optional, for AI features): `export GEMINI_API_KEY=your-key`

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Set environment variables
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GEMINI_API_KEY=your-gemini-api-key  # Optional
export GCS_LOG_BUCKET=your-log-bucket      # Optional default bucket

# Run the CLI
python conversational_client.py
```

## Commands Reference

### 📂 Navigation
| Command | Description |
|---------|-------------|
| `buckets` | List available event stores |
| `ls [bucket/prefix]` | Browse logs in bucket or folder |
| `read <file> [bucket]` | Read log content (first 100 lines) |
| `meta <file> [bucket]` | Get file metadata |

### 🔍 Analysis
| Command | Description |
|---------|-------------|
| `search <query> <file> [bucket]` | Search for text in log file |
| `analyze <GROK> <file> [bucket] [--full]` | Extract using GROK patterns (IP, HTTPSTATUS, etc.) |
| `analyze_rex <regex> <file> [bucket] [--full]` | Expert mode with custom regex |
| `scan <file> [bucket] [--full]` | AI-powered pattern discovery |

### 🔎 Investigation (AI + Threat Intel)
| Command | Description |
|---------|-------------|
| `investigate <term> <file> [bucket] [--full]` | Deep-dive AI analysis with MITRE ATT&CK context |

### ⚙️ Detection Engineering
| Command | Description |
|---------|-------------|
| `templates <file> [bucket] [--grok]` | Generate GROK parsing templates |
| `patterns` | Show GROK patterns & OTel mappings |
| `patterns_custom` | List all analyze GROK patterns (built-in + custom) |

### 🤖 Natural Language
Just type naturally:
- *"Show me the top talkers from the web server logs"*
- *"Investigate suspicious activity from IP 192.168.1.100"*
- *"Find all authentication failures in the auth logs"*

## Examples

```bash
# List all buckets
⚙ mill> buckets

# Browse logs
⚙ mill> ls my-log-bucket/nginx

# Analyze top IPs using GROK pattern
⚙ mill> analyze IP access.log my-log-bucket

# Analyze HTTP status codes (full file)
⚙ mill> analyze HTTPSTATUS access.log my-log-bucket --full

# Expert regex mode
⚙ mill> analyze_rex "user=(\w+)" auth.log my-log-bucket

# AI-powered investigation
⚙ mill> investigate 192.168.1.100 access.log my-log-bucket

# Generate parsing templates
⚙ mill> templates access.log my-log-bucket --grok

# Natural language query
⚙ mill> show me top talkers from access.log
```

## GROK Patterns

### Built-in Patterns
| Pattern | Description |
|---------|-------------|
| `IP` / `IPV4` | IPv4 addresses |
| `IPV6` | IPv6 addresses |
| `MAC` | MAC addresses |
| `EMAIL` | Email addresses |
| `UUID` | UUIDs |
| `HTTPSTATUS` | HTTP status codes |
| `HTTPMETHOD` | HTTP methods |
| `LOGLEVEL` | Log levels (INFO, ERROR, etc.) |
| `USER` / `USERNAME` | User identifiers |
| `PORT` | Port numbers |
| `PATH` | URL paths (without query string) |
| `URI` | Full URI path (with query string) |
| `URIPATH` | URI path (alias for PATH) |
| `URL` | Full URL with scheme (http/https) |
| `TIMESTAMP` | ISO timestamps |
| `DATE` | Dates (YYYY-MM-DD) |
| `TIME` | Times (HH:MM:SS) |
| `INT` | Integers |
| `NUMBER` | Numbers (with decimals) |
| `WORD` | Single words |
| `HOSTNAME` | Hostnames |
| `SID` | Windows Security IDs |

### Custom Patterns
Add organization-specific patterns in `custom_patterns.py`:

```python
CUSTOM_GROK_PATTERNS = {
    "MYAPP_TXID": r"TXN-(\d{8})",
    "INTERNAL_UID": r"uid=(\w+)",
}
```

See [docs/CUSTOM_PATTERNS.md](docs/CUSTOM_PATTERNS.md) for detailed documentation.

### Usage with Claude Desktop / Windsurf

Add this to your MCP configuration file:

```json
{
  "mcpServers": {
    "event-mill": {
      "command": "python",
      "args": ["C:/path/to/gcs_soc_mcp/server.py"],
      "env": {
        "GOOGLE_APPLICATION_CREDENTIALS": "C:/path/to/service-account.json",
        "GEMINI_API_KEY": "your-api-key",
        "GCS_LOG_BUCKET": "your-default-bucket"
      }
    }
  }
}
```

## MCP Tools Available

### Navigation Tools
| Tool | Description |
|------|-------------|
| `list_buckets()` | List available GCS buckets |
| `list_logs(bucket_name, prefix)` | List files in a bucket or folder |
| `read_log_segment(file_name, bucket_name, offset_lines, line_limit)` | Read chunks of a log file |
| `get_log_metadata(file_name, bucket_name)` | Check file size and dates |

### Search Tools
| Tool | Description |
|------|-------------|
| `search_log(file_name, query, bucket_name, max_results)` | Search for text in log files |

### Analysis Tools
| Tool | Description |
|------|-------------|
| `analyze_log_grok(file_name, grok_pattern, bucket_name, limit, full_log)` | Extract patterns using GROK names |
| `analyze_log_regex(file_name, pattern, bucket_name, limit, full_log)` | Extract patterns using custom regex |
| `discover_log_patterns(file_name, bucket_name, sample_lines, full_log)` | Auto-detect log patterns with AI |

### Investigation Tools
| Tool | Description |
|------|-------------|
| `investigate_log(file_name, search_term, bucket_name, context_lines, full_log)` | AI-powered threat investigation |
| `soc_workflow(workflow_type, file_name, bucket_name, target)` | Common SOC analyst workflows |

### Template Tools
| Tool | Description |
|------|-------------|
| `generate_pattern_templates(file_name, bucket_name, sample_lines, max_templates, output_format)` | Generate GROK parsing templates |
| `get_parsing_patterns()` | Show GROK patterns and OTel mappings |

### AI-Powered Features
- **Gemini 3 Flash Integration**: Advanced threat intelligence analysis
- **Pattern Recognition**: Automatic log type identification
- **Security Recommendations**: Actionable next steps for analysts
- **MITRE ATT&CK Context**: Threat intelligence with attack technique mapping

### Pattern Template Generation
The `generate_pattern_templates` tool analyzes log files and generates structured parsing templates with:

- **Signature Mapping**: Abstracted patterns showing variable data positions
- **GROK Patterns**: Standard patterns for IPs, timestamps, HTTP methods, UUIDs, etc.
- **OpenTelemetry Mappings**: Field names follow semantic conventions
- **Event Classification**: 20 ECS categories (authentication, network, file, process, etc.)
- **Detection Logic**: Boolean expressions to identify each pattern type
- **AI Review**: Gemini reviews templates for accuracy and suggests improvements

Output formats:
- **Default (JSON)**: Human-readable with signature/example mapping for analysis
- **GROK (`--grok`)**: Machine-readable config for Logstash/Filebeat pipelines

## Architecture

Event Mill uses a modular architecture for easy maintenance and extension:

```
gcs_soc_mcp/
├── server.py                 # MCP server entry point (78 lines)
├── conversational_client_v2.py  # CLI with Event Mill branding
├── pattern_templates.py      # GROK patterns, OTel mappings, ECS categories
├── system_context.py         # AI prompts and system context
├── custom_patterns.py        # User-defined GROK patterns
├── tools/                    # Modular MCP tool implementations
│   ├── __init__.py          # Tool registration
│   ├── navigation.py        # Bucket/file navigation tools
│   ├── search.py            # Log search tools
│   ├── analysis.py          # Pattern analysis tools
│   ├── investigation.py     # AI investigation tools
│   └── templates.py         # Template generation tools
└── docs/                     # Documentation
    ├── CUSTOM_PATTERNS.md   # Custom pattern guide
    ├── DEPLOYMENT.md        # Remote deployment guide
    └── EXTENDING_TOOLS.md   # Tool development tutorial
```

## Deployment Options

### 1. Local / Cloud Shell (Stdio Mode)
Default mode - runs as a subprocess communicating via standard input/output.

```bash
python server.py
```

### 2. Docker with ttyd Web Terminal
Run Event Mill as a web-accessible terminal using [ttyd](https://github.com/tsl0922/ttyd).

```bash
# Set environment variables
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GEMINI_API_KEY=your-gemini-api-key
export GCS_LOG_BUCKET=your-log-bucket  # Optional
export TTYD_USERNAME=admin             # Optional, for basic auth
export TTYD_PASSWORD=changeme          # Optional, for basic auth

# Build and run
docker-compose up --build
```

Access the terminal at `http://localhost:7681`

**Important: UID Matching**

The Docker container runs as a non-privileged user. The UID specified in `docker-compose.yml` must match the OS UID of the user that owns your service account JSON key file:

```bash
# Check the UID of your key file owner
ls -n /path/to/service-account.json
# Example output: -rw------- 1 1002 1002 2358 Dec 29 17:58 service-account.json

# Update docker-compose.yml to match (default is 1000:1000)
user: "1002:1002"
```

If the UIDs don't match, the container won't be able to read the mounted credentials file.

### 3. Google Cloud Run (SSE Mode)
Deploy as a standalone HTTP service:

```bash
gcloud run deploy event-mill \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars MCP_TRANSPORT=sse,GEMINI_API_KEY=your-key
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed deployment instructions.

## Documentation

- [Custom GROK Patterns](docs/CUSTOM_PATTERNS.md) - Add organization-specific patterns
- [Deployment Guide](docs/DEPLOYMENT.md) - Remote server and Cloud Run deployment
- [Extending MCP Tools](docs/EXTENDING_TOOLS.md) - Tutorial for adding new tools

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

You are free to use, modify, and distribute this software. Attribution to the original Event Mill project is appreciated.

