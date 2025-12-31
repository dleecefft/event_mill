"""
Investigation Tools - AI-powered threat investigation

Tools:
- investigate_log: Deep-dive AI analysis with threat intelligence
- soc_workflow: Common SOC analyst workflows
"""

import re
import logging
from collections import Counter


def register_investigation_tools(mcp, storage_client, gemini_client, get_bucket_func):
    """Register investigation tools with the MCP server."""
    
    _storage_client = storage_client
    _gemini_client = gemini_client
    _get_bucket = get_bucket_func

    @mcp.tool()
    def investigate_log(file_name: str, search_term: str, bucket_name: str = "", context_lines: int = 100, full_log: bool = False) -> str:
        """
        Investigates a specific search term in a log file using AI analysis and threat intelligence.
        Unlike 'analyze', this tool uses LLM knowledge and web searching to provide security context.
        Focused on a single log file for performance.
        
        Args:
            file_name: Path to the log file in the bucket.
            search_term: The string to search for (IP, username, error message, etc.)
            bucket_name: Optional bucket override.
            context_lines: Max number of matching lines to analyze (default 100).
            full_log: If True, search entire file. Otherwise, stop after context_lines matches.
        
        Returns:
            AI-powered analysis with threat intelligence context for the search term.
        """
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            # Search for matching lines
            matching_lines = []
            lines_scanned = 0
            total_matches = 0
            
            with blob.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    lines_scanned += 1
                    if search_term.lower() in line.lower():
                        total_matches += 1
                        if len(matching_lines) < context_lines:
                            matching_lines.append(line.strip())
                        elif not full_log:
                            break
            
            if not matching_lines:
                return f"No matches found for '{search_term}' in {file_name} ({lines_scanned} lines scanned)."
            
            # Build context for AI analysis
            output = []
            output.append(f"--- Investigation: '{search_term}' in {file_name} ---")
            output.append(f"Scanned {lines_scanned} lines, found {total_matches} matches")
            output.append(f"Analyzing {len(matching_lines)} sample matches:")
            output.append("")
            
            # Show sample matches
            for i, line in enumerate(matching_lines[:10], 1):
                truncated = line[:200] + "..." if len(line) > 200 else line
                output.append(f"  [{i}] {truncated}")
            
            if len(matching_lines) > 10:
                output.append(f"  ... and {len(matching_lines) - 10} more matches")
            output.append("")
            
            # AI Analysis with threat intelligence
            if _gemini_client:
                try:
                    sample_logs = "\n".join(matching_lines[:50])
                    
                    investigation_prompt = f"""You are a Senior Security Analyst investigating a potential security incident.

INVESTIGATION TARGET: "{search_term}"
LOG FILE: {file_name}
TOTAL MATCHES: {total_matches} occurrences in {lines_scanned} lines

SAMPLE LOG ENTRIES:
{sample_logs}

ANALYSIS REQUIRED:
1. **Identification**: What type of entity is "{search_term}"? (IP address, username, error code, malware signature, etc.)

2. **Threat Assessment**: Based on the log patterns:
   - Is this activity suspicious or malicious?
   - What is the severity level? (Critical/High/Medium/Low/Informational)
   - Are there indicators of compromise (IoCs)?

3. **Threat Intelligence**: Search your knowledge for:
   - Known malicious indicators matching this pattern
   - Associated threat actors or campaigns
   - Relevant CVEs or attack techniques (MITRE ATT&CK)
   - Historical context of similar attacks

4. **Timeline Analysis**: What does the activity timeline suggest?
   - Attack phases (reconnaissance, exploitation, persistence, etc.)
   - Frequency and pattern of activity

5. **Recommended Actions**:
   - Immediate containment steps
   - Further investigation queries
   - Evidence preservation
   - Escalation criteria

6. **Detection Rules**: Suggest detection logic or SIEM rules to catch similar activity.

Provide a structured, actionable security analysis."""

                    response = _gemini_client.models.generate_content(
                        model='gemini-3-flash-preview',
                        contents=investigation_prompt
                    )
                    
                    output.append("=" * 60)
                    output.append("🔍 AI SECURITY INVESTIGATION")
                    output.append("=" * 60)
                    output.append(response.text)
                    
                except Exception as ai_e:
                    output.append(f"\n[AI Analysis Failed: {str(ai_e)}]")
                    logging.error(f"Gemini API error in investigate: {ai_e}")
            else:
                output.append("\n[Note: Set GEMINI_API_KEY to enable AI-powered investigation]")
            
            return "\n".join(output)

        except Exception as e:
            return f"Error investigating log: {str(e)}"

    @mcp.tool()
    def soc_workflow(workflow_type: str, file_name: str, bucket_name: str = "", target: str = "") -> str:
        """
        Executes common SOC analyst workflows with predefined patterns and analysis.
        
        Args:
            workflow_type: Type of analysis ('top_talkers', 'investigate_ip', 'security_events', 'attack_patterns')
            file_name: Path to the log file
            bucket_name: Optional bucket override
            target: Specific target (IP address, user name, etc.) for targeted workflows
        
        Returns:
            Comprehensive analysis results with security recommendations.
        """
        # Import discover_log_patterns for attack_patterns workflow
        from tools.analysis import register_analysis_tools
        
        target_bucket = _get_bucket(bucket_name)
        if not target_bucket:
            return "Error: No bucket specified and GCS_LOG_BUCKET not set."

        if not _storage_client:
            return "Error: GCS Client not initialized."

        try:
            bucket = _storage_client.bucket(target_bucket)
            blob = bucket.blob(file_name)
            
            results = []
            
            if workflow_type == "top_talkers":
                patterns = [
                    ("IP Addresses", r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"),
                    ("HTTP Methods", r"\"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|PROPFIND|CONNECT|TRACE)\s"),
                    ("Status Codes", r"\s(\d{3})\s"),
                    ("User Agents", r"\"([^\"]+)\"\s*$")
                ]
                
                for name, pattern in patterns:
                    try:
                        counter = Counter()
                        regex = re.compile(pattern)
                        
                        with blob.open("r", encoding="utf-8", errors="replace") as f:
                            for line in f:
                                match = regex.search(line)
                                if match:
                                    val = match.group(1) if match.groups() else match.group(0)
                                    counter[val] += 1
                        
                        if counter:
                            top_results = counter.most_common(10)
                            results.append(f"--- Top {name} ---")
                            for value, count in top_results:
                                results.append(f"{value}: {count}")
                            results.append("")
                            
                    except Exception as e:
                        results.append(f"Error analyzing {name}: {str(e)}")
            
            elif workflow_type == "investigate_ip":
                if not target:
                    return "Error: investigate_ip workflow requires a target IP address"
                
                results.append(f"--- Investigation for IP: {target} ---")
                
                ip_pattern = re.compile(re.escape(target))
                lines_with_ip = []
                
                with blob.open("r", encoding="utf-8", errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        if ip_pattern.search(line):
                            lines_with_ip.append(f"{line_num}: {line.strip()}")
                            if len(lines_with_ip) >= 50:
                                break
                
                if lines_with_ip:
                    results.append(f"Found {len(lines_with_ip)} occurrences:")
                    results.extend(lines_with_ip[:20])
                    if len(lines_with_ip) > 20:
                        results.append(f"... and {len(lines_with_ip) - 20} more")
                else:
                    results.append(f"No activity found for IP {target}")
            
            elif workflow_type == "security_events":
                security_patterns = [
                    ("HTTP Errors", r"\s(4\d{2}|5\d{2})\s"),
                    ("Suspicious Methods", r"\"(PROPFIND|CONNECT|TRACE|TRACK|DEBUG)\s"),
                    ("Error Messages", r"(?i)(error|failed|denied|forbidden|unauthorized)"),
                    ("SQL Injection", r"(?i)(union.*select|drop.*table|insert.*into)"),
                    ("XSS Attempts", r"(?i)(<script|javascript:|onload=|onerror=)")
                ]
                
                for name, pattern in security_patterns:
                    try:
                        matches = []
                        regex = re.compile(pattern)
                        
                        with blob.open("r", encoding="utf-8", errors="replace") as f:
                            for line_num, line in enumerate(f, 1):
                                if regex.search(line):
                                    matches.append(f"{line_num}: {line.strip()}")
                                    if len(matches) >= 10:
                                        break
                        
                        if matches:
                            results.append(f"--- {name} ---")
                            results.extend(matches)
                            results.append("")
                            
                    except Exception as e:
                        results.append(f"Error searching for {name}: {str(e)}")
            
            elif workflow_type == "attack_patterns":
                # This would call discover_log_patterns but we need to handle it differently
                # For now, return a message directing to use the scan command
                return "Use the 'scan' command with --full flag for attack pattern analysis: scan <file> [bucket] --full"
            
            else:
                return f"Unknown workflow type: {workflow_type}. Available: top_talkers, investigate_ip, security_events, attack_patterns"
            
            return "\n".join(results) if results else "No results found for the specified workflow."
            
        except Exception as e:
            return f"Error executing workflow: {str(e)}"
