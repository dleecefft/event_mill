"""
Analysis Tools - Pattern analysis and discovery

Tools:
- analyze_log_grok: Extract patterns using GROK names
- analyze_log_regex: Extract patterns using custom regex
- discover_log_patterns: Auto-detect log patterns with AI
"""

import re
import logging
from collections import Counter, defaultdict


# GROK pattern aliases for the analyze tool (user-friendly names -> regex with capture group)
BUILTIN_GROK_PATTERNS = {
    "IP": r"((?:\d{1,3}\.){3}\d{1,3})",
    "IPV4": r"((?:\d{1,3}\.){3}\d{1,3})",
    "IPV6": r"((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})",
    "MAC": r"((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})",
    "EMAIL": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    "UUID": r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    "HTTPSTATUS": r"\s(\d{3})\s",
    "HTTPMETHOD": r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND)",
    "LOGLEVEL": r"(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|TRACE|NOTICE|ALERT|EMERG(?:ENCY)?)",
    "USER": r"user[=:\s]+[\"']?(\w+)[\"']?",
    "USERNAME": r"user(?:name)?[=:\s]+[\"']?(\w+)[\"']?",
    "PORT": r":(\d{1,5})\b",
    "PATH": r"(\/[^\s?#]*)",
    "URI": r"(\/[^\s]*)",  # Full URI path with query string
    "URIPATH": r"(\/[^\s?#]*)",  # URI path without query string (same as PATH)
    "URL": r"(https?:\/\/[^\s]+)",  # Full URL with scheme
    "TIMESTAMP": r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",
    "DATE": r"(\d{4}-\d{2}-\d{2})",
    "TIME": r"(\d{2}:\d{2}:\d{2})",
    "INT": r"(\d+)",
    "NUMBER": r"([+-]?\d+(?:\.\d+)?)",
    "WORD": r"(\b\w+\b)",
    "HOSTNAME": r"(\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*\.?\b)",
    "SID": r"(S-\d-\d+-(?:\d+-)*\d+)",
}

# Load custom patterns from custom_patterns.py if available
try:
    from custom_patterns import CUSTOM_GROK_PATTERNS
    ANALYZE_GROK_PATTERNS = {**BUILTIN_GROK_PATTERNS, **CUSTOM_GROK_PATTERNS}
    if CUSTOM_GROK_PATTERNS:
        logging.info(f"Loaded {len(CUSTOM_GROK_PATTERNS)} custom GROK patterns")
except ImportError:
    ANALYZE_GROK_PATTERNS = BUILTIN_GROK_PATTERNS
    logging.debug("No custom_patterns.py found, using builtin patterns only")


def register_analysis_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register analysis tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def analyze_log_grok(file_name: str, grok_pattern: str, bucket_name: str = "", limit: int = 10, full_log: bool = False, sample_lines: int = 50000) -> str:
        """
        Analyzes a log file using GROK pattern names instead of raw regex.
        This is the user-friendly version - use analyze_log_regex for custom regex patterns.
        
        Args:
            file_name: Path to the file in the bucket.
            grok_pattern: GROK pattern name to extract and count. Available patterns:
                          IP/IPV4, IPV6, MAC, EMAIL, UUID, HTTPSTATUS, HTTPMETHOD,
                          LOGLEVEL, USER, USERNAME, PORT, PATH, TIMESTAMP, DATE, TIME,
                          INT, NUMBER, WORD, HOSTNAME, SID
            bucket_name: Optional bucket override.
            limit: Number of top results to return (default 10).
            full_log: If True, process the entire log file. Otherwise, sample first N lines.
            sample_lines: Number of lines to sample if full_log is False (default 50000).
        
        Returns:
            Top N occurrences of the matched pattern with sample records for context.
        """
        # Convert GROK pattern name to regex
        pattern_upper = grok_pattern.upper()
        if pattern_upper not in ANALYZE_GROK_PATTERNS:
            available = ", ".join(sorted(ANALYZE_GROK_PATTERNS.keys()))
            return f"Error: Unknown GROK pattern '{grok_pattern}'. Available patterns:\n{available}"
        
        regex_pattern = ANALYZE_GROK_PATTERNS[pattern_upper]
        
        # Call the regex version with the converted pattern
        result = analyze_log_regex(file_name, regex_pattern, bucket_name, limit, full_log, sample_lines)
        
        # Prepend pattern info to result
        if not result.startswith("Error"):
            result = f"[GROK: {pattern_upper} → {regex_pattern}]\n\n" + result
        
        return result

    @mcp.tool()
    def analyze_log_regex(file_name: str, pattern: str, bucket_name: str = "", limit: int = 10, full_log: bool = False, sample_lines: int = 50000) -> str:
        """
        Analyzes a log file by extracting a specific attribute using a regex pattern and counting occurrences.
        This enables 'top talkers', 'most frequent errors', or 'activity by user' analysis.
        For simpler analysis, use analyze_log_grok with GROK pattern names.
        
        Args:
            file_name: Path to the file in the bucket.
            pattern: Regex pattern with ONE capture group to extract the value to count.
                     - IPv4: r"(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})"
                     - Status Code: r"\\s(\\d{3})\\s"
                     - User (Nginx): r"^[\\d\\.]+\\s+\\S+\\s+(\\S+)"
            bucket_name: Optional bucket override.
            limit: Number of top results to return (default 10).
            full_log: If True, process the entire log file. Otherwise, sample first N lines.
            sample_lines: Number of lines to sample if full_log is False (default 50000).
        """
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            counter = Counter()
            sample_records = defaultdict(list)  # Store up to 3 sample records per match value
            lines_processed = 0
            matches_found = 0
            max_samples_per_value = 3
            
            regex = re.compile(pattern)
            
            with blob.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    lines_processed += 1
                    
                    # Check if we should stop (sample mode)
                    if not full_log and lines_processed > sample_lines:
                        break
                    
                    match = regex.search(line)
                    if match:
                        # Use the first capture group, or the whole match if no group
                        val = match.group(1) if match.groups() else match.group(0)
                        counter[val] += 1
                        matches_found += 1
                        
                        # Store sample records (up to max_samples_per_value per unique value)
                        if len(sample_records[val]) < max_samples_per_value:
                            sample_records[val].append(line.strip())
            
            if not counter:
                return f"No matches found for pattern '{pattern}' in {lines_processed} lines."
                
            top_results = counter.most_common(limit)
            
            scan_type = "Full scan" if full_log else f"Sample ({sample_lines} lines)"
            output = [f"--- Analysis Result ({scan_type}: {lines_processed} lines, {matches_found} matches) ---"]
            output.append(f"Top {limit} results for pattern '{pattern}':")
            output.append("")
            
            for value, count in top_results:
                output.append(f"📊 {value}: {count} occurrences")
                # Add sample records for context
                samples = sample_records.get(value, [])
                if samples:
                    output.append(f"   Sample records:")
                    for sample in samples[:max_samples_per_value]:
                        # Truncate long lines for readability
                        truncated = sample[:150] + "..." if len(sample) > 150 else sample
                        output.append(f"   → {truncated}")
                output.append("")
                
            return "\n".join(output)

        except Exception as e:
            return f"Error analyzing log: {str(e)}"

    @mcp.tool()
    def discover_log_patterns(file_name: str, bucket_name: str = "", sample_lines: int = 500, full_log: bool = False) -> str:
        """
        Automatically detects log patterns by reading a sample of lines and generating structural signatures.
        Use this when you don't know what kind of log file you are looking at.
        
        Args:
            file_name: Path to the file in the bucket.
            bucket_name: Optional bucket override.
            sample_lines: Number of lines to sample (ignored if full_log=True).
            full_log: If True, scans the entire log file instead of sampling.
        
        Returns:
            A summary of the most common pattern signatures found, with example lines.
            This allows the LLM to identify the log type (e.g., "Nginx Access Log", "Syslog") 
            and recommend analysis steps.
        """
        # Import here to avoid circular imports
        from system_context import get_pattern_analysis_prompt
        
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            signatures = Counter()
            examples = {}  # Map signature -> first line seen
            
            # Regex patterns to abstract variable data into tokens
            patterns = [
                (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "<IP>"),
                (r"\d{4}-\d{2}-\d{2}", "<DATE>"),
                (r"\d{2}/\w{3}/\d{4}", "<DATE>"),
                (r"\d{2}:\d{2}:\d{2}", "<TIME>"),
                (r"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)", "<METHOD>"),
                (r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", "<UUID>"),
                (r"\b\d+\b", "<NUM>"),
                (r"0x[0-9a-fA-F]+", "<HEX>")
            ]
            
            lines_read = 0
            max_lines = float('inf') if full_log else sample_lines
            
            with blob.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if lines_read >= max_lines:
                        break
                    
                    line = line.strip()
                    if not line:
                        continue
                        
                    lines_read += 1
                    
                    # Generate signature
                    signature = line
                    for pat, token in patterns:
                        signature = re.sub(pat, token, signature)
                    
                    # Truncate very long signatures
                    if len(signature) > 200:
                        signature = signature[:200] + "..."
                    
                    signatures[signature] += 1
                    if signature not in examples:
                        examples[signature] = line
            
            if not signatures:
                return "File is empty or contains no readable text."
                
            scan_type = "Full Log Scan" if full_log else f"Sample Scan ({sample_lines} lines)"
            output = [f"--- Pattern Discovery ({scan_type}) ---"]
            output.append(f"Identified the following log structures:")
            output.append("")
            
            # Show top 5 patterns
            for sig, count in signatures.most_common(5):
                pct = (count / lines_read) * 100
                output.append(f"Pattern ({count} occurrences, {pct:.1f}%):")
                output.append(f"  Signature: {sig}")
                output.append(f"  Example:   {examples[sig]}")
                output.append("")
                
            output.append("--- Recommendation ---")
            output.append("Use the 'Example' above to determine the log type (e.g., JSON, Syslog, Apache).")
            output.append("Then ask for specific analysis like 'Show top <IP> from Pattern 1'.")
            
            # AI ANALYSIS INTEGRATION
            if _gemini_client:
                try:
                    summary_text = "\n".join(output)
                    prompt = get_pattern_analysis_prompt(file_name, summary_text)
                    
                    response = _gemini_client.models.generate_content(
                        model='gemini-3-flash-preview',
                        contents=prompt
                    )
                    ai_response_text = response.text
                    
                    output.append("\n" + "="*40)
                    output.append("🤖 AI ANALYST INSIGHT (GEMINI)")
                    output.append("="*40)
                    output.append(ai_response_text)
                    
                except Exception as ai_e:
                    output.append(f"\n[AI Analysis Failed: {str(ai_e)}]")
                    logging.error(f"Gemini API error: {ai_e}")
            else:
                output.append("\n[Note: Set GEMINI_API_KEY to enable automated AI analysis of these patterns]")
                
            return "\n".join(output)

        except Exception as e:
            return f"Error discovering patterns: {str(e)}"
