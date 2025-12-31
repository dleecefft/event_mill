# Extending Event Mill MCP Tools

This guide explains how to add new MCP tools to Event Mill. The modular architecture makes it easy to extend functionality without modifying core files.

## Architecture Overview

Event Mill uses a modular tool system:

```
tools/
├── __init__.py          # Tool registration orchestrator
├── navigation.py        # Bucket/file navigation tools
├── search.py            # Log search tools
├── analysis.py          # Pattern analysis tools
├── investigation.py     # AI investigation tools
└── templates.py         # Template generation tools
```

Each module contains related tools and a `register_*_tools()` function that registers them with the MCP server.

## Quick Start: Adding a Simple Tool

### Step 1: Choose the Right Module

Add your tool to an existing module if it fits, or create a new module for a new category.

| Module | Purpose |
|--------|---------|
| `navigation.py` | File/bucket listing, reading, metadata |
| `search.py` | Text searching and filtering |
| `analysis.py` | Pattern extraction and counting |
| `investigation.py` | AI-powered analysis |
| `templates.py` | Template/config generation |

### Step 2: Add Your Tool Function

Open the appropriate module (e.g., `tools/analysis.py`) and add your tool inside the `register_*_tools()` function:

```python
def register_analysis_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register analysis tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func

    # ... existing tools ...

    @mcp.tool()
    def my_new_tool(file_name: str, bucket_name: str = "", my_param: str = "") -> str:
        """
        Short description of what this tool does.
        This docstring becomes the tool's description in MCP.
        
        Args:
            file_name: Path to the file in the bucket
            bucket_name: Optional bucket override
            my_param: Description of your parameter
        
        Returns:
            Description of what the tool returns
        """
        # Resolve bucket
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            # Your tool logic here
            result = "Your analysis result"
            
            return result

        except Exception as e:
            return f"Error in my_new_tool: {str(e)}"
```

### Step 3: Test Your Tool

Restart the MCP server and test via the CLI or MCP client:

```bash
# Restart server
python server.py

# Test via CLI (if you add a command)
python conversational_client_v2.py
```

## Creating a New Tool Module

For a completely new category of tools:

### Step 1: Create the Module File

Create `tools/my_category.py`:

```python
"""
My Category Tools - Description of this category

Tools:
- my_tool_1: Description
- my_tool_2: Description
"""

import logging


def register_my_category_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register my category tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def my_tool_1(file_name: str, bucket_name: str = "") -> str:
        """Tool description here."""
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."
        
        # Tool implementation
        return "Result"

    @mcp.tool()
    def my_tool_2(param: str) -> str:
        """Another tool description."""
        # Tool implementation
        return "Result"
```

### Step 2: Register in `__init__.py`

Update `tools/__init__.py`:

```python
from tools.navigation import register_navigation_tools
from tools.search import register_search_tools
from tools.analysis import register_analysis_tools
from tools.investigation import register_investigation_tools
from tools.templates import register_template_tools
from tools.my_category import register_my_category_tools  # Add import

def register_all_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register all MCP tools with the server."""
    global _gemini_client
    _gemini_client = gemini_client
    
    register_navigation_tools(mcp, storage_client, get_bucket_func)
    register_search_tools(mcp, storage_client, get_bucket_func)
    register_analysis_tools(mcp, storage_client, gemini_client, get_bucket_func)
    register_investigation_tools(mcp, storage_client, gemini_client, get_bucket_func)
    register_template_tools(mcp, storage_client, gemini_client, get_bucket_func)
    register_my_category_tools(mcp, storage_client, gemini_client, get_bucket_func)  # Add registration
```

## Common Patterns

### Reading Log Files (Streaming)

Use GCS streaming to handle large files efficiently:

```python
@mcp.tool()
def process_log(file_name: str, bucket_name: str = "") -> str:
    target_bucket = _get_bucket(bucket_name)
    bucket = _storage_client.bucket(target_bucket)
    blob = bucket.blob(file_name)
    
    results = []
    lines_processed = 0
    
    # Stream file content - never loads entire file into memory
    with blob.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            lines_processed += 1
            # Process each line
            if "error" in line.lower():
                results.append(line.strip())
            
            # Optional: limit processing
            if lines_processed >= 100000:
                break
    
    return f"Found {len(results)} errors in {lines_processed} lines"
```

### Using AI Analysis (Gemini)

Integrate Gemini for intelligent analysis:

```python
@mcp.tool()
def ai_analyze(file_name: str, question: str, bucket_name: str = "") -> str:
    target_bucket = _get_bucket(bucket_name)
    bucket = _storage_client.bucket(target_bucket)
    blob = bucket.blob(file_name)
    
    # Read sample of log
    sample_lines = []
    with blob.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= 100:  # Limit sample size
                break
            sample_lines.append(line.strip())
    
    if not _gemini_client:
        return "Error: Gemini API not configured. Set GEMINI_API_KEY."
    
    # Build prompt
    prompt = f"""Analyze these log entries and answer: {question}

LOG SAMPLE:
{chr(10).join(sample_lines)}

Provide a concise, actionable answer."""

    try:
        response = _gemini_client.models.generate_content(
            model='gemini-3-flash-preview',
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"AI analysis failed: {str(e)}"
```

### Pattern Extraction with Regex

Extract and count patterns:

```python
import re
from collections import Counter

@mcp.tool()
def extract_pattern(file_name: str, pattern: str, bucket_name: str = "", limit: int = 10) -> str:
    target_bucket = _get_bucket(bucket_name)
    bucket = _storage_client.bucket(target_bucket)
    blob = bucket.blob(file_name)
    
    counter = Counter()
    regex = re.compile(pattern)
    
    with blob.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            match = regex.search(line)
            if match:
                value = match.group(1) if match.groups() else match.group(0)
                counter[value] += 1
    
    # Format results
    output = [f"Top {limit} matches for pattern '{pattern}':"]
    for value, count in counter.most_common(limit):
        output.append(f"  {value}: {count}")
    
    return "\n".join(output)
```

### Generating Signatures

Abstract variable data into tokens for pattern recognition:

```python
import re

SIGNATURE_PATTERNS = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>"),
    (r"\d{4}-\d{2}-\d{2}", "<DATE>"),
    (r"\d{2}:\d{2}:\d{2}", "<TIME>"),
    (r"\b\d+\b", "<NUM>"),
]

def generate_signature(line: str) -> str:
    """Convert a log line into an abstracted signature."""
    signature = line
    for pattern, token in SIGNATURE_PATTERNS:
        signature = re.sub(pattern, token, signature)
    return signature
```

## Adding CLI Commands

To expose your tool in the conversational client, edit `conversational_client_v2.py`:

### Step 1: Add Command Handler

Find the command handling section and add your command:

```python
elif command == "mycommand":
    # Parse arguments
    if len(parts) < 2:
        print("Usage: mycommand <file> [bucket] [--flag]")
        continue
    
    file_name = parts[1]
    bucket_name = parts[2] if len(parts) > 2 and not parts[2].startswith("--") else ""
    use_flag = "--flag" in parts
    
    # Call MCP tool
    result = await session.call_tool("my_new_tool", {
        "file_name": file_name,
        "bucket_name": bucket_name,
        "my_param": "value" if use_flag else ""
    })
    print(result.content[0].text)
```

### Step 2: Update Help Text

Add your command to the help text:

```python
HELP_TEXT = """
...
### My Category
| Command | Description |
|---------|-------------|
| `mycommand <file> [bucket] [--flag]` | Description of my command |
...
"""
```

## Best Practices

### 1. Error Handling
Always wrap tool logic in try/except and return meaningful error messages:

```python
try:
    # Tool logic
except Exception as e:
    return f"Error in tool_name: {str(e)}"
```

### 2. Bucket Resolution
Always use the `_get_bucket()` helper to support default bucket configuration:

```python
target_bucket = _get_bucket(bucket_name)
if not target_bucket:
    return "Error: No bucket specified and GCS_LOG_BUCKET not set."
```

### 3. Client Validation
Check that required clients are initialized:

```python
if not _storage_client:
    return "Error: GCS Client not initialized."

if not _gemini_client:
    return "Error: Gemini API not configured."
```

### 4. Streaming for Large Files
Never load entire files into memory. Use `blob.open()` for streaming:

```python
# Good - streaming
with blob.open("r") as f:
    for line in f:
        process(line)

# Bad - loads entire file
content = blob.download_as_text()
```

### 5. Limit Output Size
Truncate long outputs to avoid overwhelming the client:

```python
MAX_OUTPUT_LINES = 100
if len(results) > MAX_OUTPUT_LINES:
    results = results[:MAX_OUTPUT_LINES]
    results.append(f"... and {total - MAX_OUTPUT_LINES} more")
```

### 6. Docstrings
Write clear docstrings - they become the tool's description in MCP:

```python
@mcp.tool()
def my_tool(param: str) -> str:
    """
    One-line summary of what this tool does.
    
    More detailed description if needed.
    
    Args:
        param: Description of the parameter
    
    Returns:
        Description of the return value
    """
```

## Testing

### Unit Testing Tools

Create `tests/test_tools.py`:

```python
import pytest
from unittest.mock import Mock, MagicMock

def test_my_tool():
    # Mock MCP server
    mcp = Mock()
    mcp.tool = lambda: lambda f: f  # Decorator that returns function unchanged
    
    # Mock GCS client
    storage_client = Mock()
    blob_mock = Mock()
    blob_mock.open.return_value.__enter__ = lambda s: iter(["line1", "line2"])
    blob_mock.open.return_value.__exit__ = Mock()
    storage_client.bucket.return_value.blob.return_value = blob_mock
    
    # Import and register tools
    from tools.my_category import register_my_category_tools
    register_my_category_tools(mcp, storage_client, None, lambda x: x or "test-bucket")
    
    # Test the tool
    # ...
```

### Integration Testing

Test with actual GCS access:

```bash
# Set up test environment
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
export GCS_LOG_BUCKET=test-bucket

# Run server and test manually
python server.py
```

## Example: Complete New Tool

Here's a complete example of adding a "count_lines" tool:

### 1. Add to `tools/analysis.py`:

```python
@mcp.tool()
def count_lines(file_name: str, bucket_name: str = "", pattern: str = "") -> str:
    """
    Count lines in a log file, optionally filtering by pattern.
    
    Args:
        file_name: Path to the file in the bucket
        bucket_name: Optional bucket override
        pattern: Optional regex pattern to filter lines
    
    Returns:
        Line count statistics
    """
    target_bucket = _get_bucket(bucket_name)
    if not target_bucket:
        return "Error: No bucket specified and GCS_LOG_BUCKET not set."

    if not _storage_client:
        return "Error: GCS Client not initialized."

    try:
        bucket = _storage_client.bucket(target_bucket)
        blob = bucket.blob(file_name)
        
        total_lines = 0
        matching_lines = 0
        regex = re.compile(pattern) if pattern else None
        
        with blob.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total_lines += 1
                if regex and regex.search(line):
                    matching_lines += 1
        
        if pattern:
            return f"Total lines: {total_lines}\nMatching '{pattern}': {matching_lines}"
        else:
            return f"Total lines: {total_lines}"

    except Exception as e:
        return f"Error counting lines: {str(e)}"
```

### 2. Add CLI command in `conversational_client_v2.py`:

```python
elif command == "count":
    if len(parts) < 2:
        print("Usage: count <file> [bucket] [--pattern <regex>]")
        continue
    
    file_name = parts[1]
    bucket_name = ""
    pattern = ""
    
    # Parse arguments
    i = 2
    while i < len(parts):
        if parts[i] == "--pattern" and i + 1 < len(parts):
            pattern = parts[i + 1]
            i += 2
        elif not parts[i].startswith("--"):
            bucket_name = parts[i]
            i += 1
        else:
            i += 1
    
    result = await session.call_tool("count_lines", {
        "file_name": file_name,
        "bucket_name": bucket_name,
        "pattern": pattern
    })
    print(result.content[0].text)
```

---

*For more information, see the main [Event Mill README](../README.md)*
