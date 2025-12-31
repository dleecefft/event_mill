"""
Template Tools - Pattern template generation

Tools:
- generate_pattern_templates: Generate GROK parsing templates
- get_parsing_patterns: Show GROK patterns and OTel mappings
"""

import re
import logging
from pattern_templates import PatternTemplateGenerator, GROK_PATTERNS, OTEL_FIELD_MAPPINGS


# Signature generation patterns (same as discover_log_patterns)
SIGNATURE_PATTERNS = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>"),
    (r"\d{4}-\d{2}-\d{2}", "<DATE>"),
    (r"\d{2}/\w{3}/\d{4}", "<DATE>"),
    (r"\d{2}:\d{2}:\d{2}", "<TIME>"),
    (r"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)", "<METHOD>"),
    (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<UUID>"),
    (r"\b\d+\b", "<NUM>"),
    (r"0x[0-9a-fA-F]+", "<HEX>"),
]


def _generate_signature(line: str) -> str:
    """Generate an abstracted signature from a log line by replacing variable data with tokens."""
    signature = line
    for pat, token in SIGNATURE_PATTERNS:
        signature = re.sub(pat, token, signature)
    return signature


def register_template_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register template tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def generate_pattern_templates(file_name: str, bucket_name: str = "", sample_lines: int = 10000, max_templates: int = 20, output_format: str = "json") -> str:
        """
        Analyzes log files and generates structured pattern templates with GROK-style extraction patterns.
        
        This tool reads a large sample of log lines, identifies distinct event types, and generates
        parsing templates with:
        - Detection logic to identify each pattern type
        - GROK-style extraction patterns for fields
        - OpenTelemetry semantic convention field mappings
        - Event classification (authentication, authorization, network, file, process, error, audit, web_access)
        
        Args:
            file_name: Path to the log file in the bucket
            bucket_name: Optional bucket override
            sample_lines: Number of lines to analyze (default 10000)
            max_templates: Maximum number of templates to generate (default 20)
            output_format: Output format - 'json' or 'grok' (default 'json')
        
        Returns:
            Structured pattern templates in the specified format
        """
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            # Read log lines
            lines = []
            lines_read = 0
            
            with blob.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        lines.append(line)
                        lines_read += 1
                        if lines_read >= sample_lines:
                            break
            
            if not lines:
                return "Error: File is empty or contains no readable text."
            
            # Generate templates using the pattern generator
            generator = PatternTemplateGenerator()
            templates = generator.analyze_logs(lines, max_templates)
            
            if not templates:
                return "No distinct patterns found in the log file."
            
            # Format output
            output = []
            output.append(f"--- Pattern Template Generation ---")
            output.append(f"Analyzed {lines_read} lines from {file_name}")
            output.append(f"Generated {len(templates)} pattern templates")
            output.append("")
            
            if output_format == "grok":
                output.append(generator.to_grok_config(templates))
            else:
                # JSON format with additional context
                for i, t in enumerate(templates, 1):
                    output.append("=" * 60)
                    output.append(f"TEMPLATE {i}: {t.template_name}")
                    output.append("=" * 60)
                    output.append(f"Template ID: {t.template_id}")
                    output.append(f"Category: {t.event_category}/{t.event_subtype}")
                    output.append(f"Confidence: {t.confidence_score:.0%}")
                    output.append(f"Sample Count: {t.sample_count}")
                    output.append("")
                    
                    # Generate signature (abstracted pattern) from sample line
                    if t.sample_lines:
                        sample = t.sample_lines[0]
                        signature = _generate_signature(sample)
                        output.append(f"Signature:")
                        output.append(f"  {signature[:200]}{'...' if len(signature) > 200 else ''}")
                        output.append("")
                        output.append(f"Example:")
                        output.append(f"  {sample[:200]}{'...' if len(sample) > 200 else ''}")
                        output.append("")
                    
                    output.append(f"Detection Logic:")
                    output.append(f"  {t.detection_logic}")
                    output.append("")
                    output.append(f"Extractions (field -> pattern -> OTel mapping):")
                    for field, pattern in t.extractions.items():
                        otel = t.otel_mappings.get(field, field)
                        output.append(f"  {field}:")
                        output.append(f"    Pattern: {pattern}")
                        output.append(f"    OTel:    {otel}")
                    output.append("")
            
            # Add AI analysis if available
            if _gemini_client and templates:
                try:
                    templates_json = generator.to_json(templates)
                    ai_prompt = f"""
You are a Senior Security Engineer reviewing auto-generated log parsing templates.

CONTEXT:
- These templates were generated from {lines_read} lines of exported log data in file '{file_name}'
- The templates use GROK patterns and OpenTelemetry semantic conventions

GENERATED TEMPLATES:
{templates_json}

TASK:
1. Review the generated templates for accuracy and completeness
2. Identify any missing extraction fields that would be valuable for security analysis
3. Suggest improvements to the detection logic
4. Recommend additional templates that might be needed based on the patterns seen
5. Note any potential parsing edge cases or ambiguities

Keep your response concise and actionable.
"""
                    response = _gemini_client.models.generate_content(
                        model='gemini-3-flash-preview',
                        contents=ai_prompt
                    )
                    
                    output.append("")
                    output.append("=" * 60)
                    output.append("🤖 AI TEMPLATE REVIEW")
                    output.append("=" * 60)
                    output.append(response.text)
                    
                except Exception as ai_e:
                    output.append(f"\n[AI Review Failed: {str(ai_e)}]")
            
            return "\n".join(output)
            
        except Exception as e:
            return f"Error generating pattern templates: {str(e)}"

    @mcp.tool()
    def get_parsing_patterns() -> str:
        """
        Returns available GROK patterns and OpenTelemetry field mappings for reference.
        
        Use this to understand what patterns are available for log parsing and
        how fields map to OpenTelemetry semantic conventions.
        """
        output = []
        
        output.append("=" * 60)
        output.append("AVAILABLE GROK PATTERNS")
        output.append("=" * 60)
        output.append("")
        
        # Group patterns by category
        categories = {
            "Network": ["IP", "IPV6", "MAC", "HOSTNAME", "PORT", "URI", "URIPATH"],
            "Timestamp": ["TIMESTAMP_ISO8601", "HTTPDATE", "SYSLOGTIMESTAMP", "DATESTAMP", "TIME"],
            "Identity": ["USERNAME", "USER", "EMAIL", "UUID"],
            "HTTP": ["HTTPMETHOD", "HTTPVERSION", "HTTPSTATUS", "USERAGENT"],
            "Numeric": ["INT", "NUMBER", "POSINT", "BYTES"],
            "Generic": ["WORD", "DATA", "GREEDYDATA", "QUOTEDSTRING", "NOTSPACE", "SPACE"],
            "Log": ["LOGLEVEL", "PID", "PROG"],
            "Windows": ["WINEVENTID", "SID"],
        }
        
        for category, patterns in categories.items():
            output.append(f"--- {category} ---")
            for p in patterns:
                if p in GROK_PATTERNS:
                    output.append(f"  %{{{p}}}: {GROK_PATTERNS[p][:60]}{'...' if len(GROK_PATTERNS[p]) > 60 else ''}")
            output.append("")
        
        output.append("=" * 60)
        output.append("OPENTELEMETRY FIELD MAPPINGS")
        output.append("=" * 60)
        output.append("")
        
        # Group mappings by category
        mapping_categories = {
            "Network": ["src_ip", "dst_ip", "src_port", "dst_port", "client_ip", "server_ip"],
            "HTTP": ["http_method", "http_status", "http_url", "http_path", "user_agent", "referer", "content_length", "response_size"],
            "User/Identity": ["user_id", "user_name", "user_email", "user_domain", "target_user", "effective_user"],
            "Authentication": ["auth_type", "auth_result", "session_id"],
            "Process": ["process_id", "process_name", "process_command", "parent_pid"],
            "Event": ["event_id", "event_type", "event_category", "event_action", "event_outcome"],
            "Error": ["error_type", "error_message", "exception_type", "exception_message", "stack_trace"],
            "Log": ["log_level", "log_logger", "log_file"],
            "Cloud/Container": ["cloud_provider", "cloud_region", "container_id", "container_name", "k8s_namespace", "k8s_pod"],
        }
        
        for category, fields in mapping_categories.items():
            output.append(f"--- {category} ---")
            for f in fields:
                if f in OTEL_FIELD_MAPPINGS:
                    output.append(f"  {f} -> {OTEL_FIELD_MAPPINGS[f]}")
            output.append("")
        
        return "\n".join(output)
