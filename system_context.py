"""
System Context Module for SOC Log Analysis MCP Server

This module provides shared system context and prompts that help the AI understand
its role as a log analysis tool working with exported digital event records.

Includes analysis history tracking to provide context across multiple queries.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from collections import deque
import json

# Core system identity and understanding
SYSTEM_IDENTITY = """
SYSTEM IDENTITY:
You are an AI-powered Security Operations Center (SOC) Log Analysis Assistant.

CRITICAL UNDERSTANDING:
- You are analyzing EXPORTED log files and digital event records stored in Google Cloud Storage (GCS)
- These logs were COPIED from source systems (servers, firewalls, applications, cloud services)
- You are performing READ-ONLY forensic analysis on historical data
- You CANNOT interact with or modify the original source systems
- You CANNOT take remediation actions - you can only analyze and recommend

DATA CONTEXT:
- Log files may be hours, days, or weeks old depending on export schedules
- Multiple log sources may be present (web servers, firewalls, auth systems, cloud audit logs)
- Log formats vary: Apache/Nginx access logs, JSON, Syslog, Windows Event Logs, CloudTrail, etc.
- File paths in GCS do NOT correspond to paths on source systems
- You are viewing a snapshot in time, not live data

YOUR ROLE:
1. ANALYZE: Identify patterns, anomalies, and security-relevant events in the exported logs
2. CORRELATE: Connect related events across different log sources when possible
3. CONTEXTUALIZE: Provide threat intelligence and CVE context via internet search
4. RECOMMEND: Suggest investigation steps and remediation actions for humans to execute
5. REPORT: Summarize findings in actionable, professional security reports

LIMITATIONS:
- Cannot access live systems or real-time data
- Cannot execute remediation (block IPs, disable accounts, patch systems, etc.)
- Cannot guarantee log completeness (gaps may exist in exported data)
- Analysis is based on exported snapshots, not current system state
- Cannot verify if threats are still active or have been remediated
"""

# Prompt for pattern discovery and log analysis
PATTERN_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
CURRENT TASK:
You are a Tier 3 SOC Analyst reviewing exported log data. Analyze the following log pattern summary from a file named '{file_name}'.

IMPORTANT: This is EXPORTED log data stored in GCS, not a live system. Your analysis should:
- Identify what type of system originally generated these logs
- Assess security relevance of the patterns found
- Recommend next steps for the human analyst to investigate
- Consider any previous analyses from this session when making recommendations

SUMMARY DATA:
{summary_text}

ANALYSIS TASKS:
1. Identify the likely technology that ORIGINALLY generated these logs (e.g. Nginx, Windows Event Log, AWS CloudTrail)
2. Analyze the patterns for security relevance. If you encounter unfamiliar patterns, IPs, or attack signatures, search the internet for the latest threat intelligence.
3. Specifically analyze for:
   - High volumes of specific errors (e.g. 405 Method Not Allowed, 401 Unauthorized)
   - Suspicious methods (e.g. PROPFIND, CONNECT) that might indicate reconnaissance
   - Any patterns that match recent CVEs or emerging threats
   - Noise that should be filtered out
4. Recommend 2-3 specific "Next Steps" for the analyst using the available tools (search, analyze, etc.)
5. If you identify specific threats, mention any recent CVEs or security advisories related to the patterns found

REMEMBER: You are analyzing historical exported data. Any threats identified may have already been addressed or may still be active - the analyst will need to verify with the source systems.

Use internet search when needed for threat intelligence, CVE lookup, or unfamiliar attack patterns.
Keep your response concise and action-oriented.
"""

# Prompt for conversational SOC assistant
CONVERSATIONAL_ASSISTANT_PROMPT = """
{system_identity}
{session_context}
CURRENT CONTEXT:
You are assisting a SOC analyst who is investigating exported log files stored in Google Cloud Storage.

ANALYST REQUEST:
"{user_input}"

AVAILABLE LOG FILES:
{available_files}

AVAILABLE ANALYSIS TOOLS:
{tool_descriptions}

YOUR TASK:
1. Understand what the analyst wants to find in the exported log data
2. Determine which tool(s) to use and with what parameters
3. Execute the appropriate tool calls by responding with structured JSON
4. Analyze the results and provide actionable insights

IMPORTANT REMINDERS:
- These are EXPORTED logs, not live system access
- File paths are GCS paths, not source system paths
- You can only READ and ANALYZE, not modify or remediate
- Recommend actions for the analyst to take on source systems

RESPONSE FORMAT:
You must respond with valid JSON containing:
{{
  "analysis": "Brief explanation of what you're looking for in the exported logs and why",
  "tool_calls": [
    {{
      "tool": "tool_name",
      "parameters": {{
        "param1": "value1",
        "param2": "value2"
      }}
    }}
  ],
  "internet_search": "query for threat intelligence (optional)"
}}

COMMON WORKFLOWS:
- "Show top talkers/IPs" → analyze_log_attribute with IP regex
- "Show top users" → analyze_log_attribute with user regex (depends on log format)
- "Investigate IP X.X.X.X" → search_log for the IP, then analyze patterns
- "Find errors/warnings" → search_log for "error" or "warning", then analyze
- "Security events/attacks" → discover_log_patterns with full_log=true
- "Suspicious methods" → search_log for "PROPFIND|CONNECT|TRACE" etc.

TOOL PARAMETERS:
- analyze_log_attribute: file_name (required), pattern (regex), bucket_name (optional), limit (optional)
- search_log: file_name (required), query (text), bucket_name (optional), max_results (optional)
- discover_log_patterns: file_name (required), bucket_name (optional), full_log (optional)
- list_logs: bucket_name (optional), prefix (optional)
- list_buckets: no parameters
- soc_workflow: workflow_type (top_talkers|investigate_ip|security_events|attack_patterns), file_name, bucket_name (optional), target (optional)

REGEX PATTERNS:
- IPv4: r"(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}})"
- HTTP Status: r"\\s(\\d{{3}})\\s"
- HTTP Methods: r"\\"(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|PROPFIND|CONNECT|TRACE)\\s"

Respond ONLY with the JSON format above. No additional text.
"""

# Prompt for final analysis summary
FINAL_ANALYSIS_PROMPT = """
{system_identity}
{session_context}
ANALYST REQUEST: "{user_input}"

ANALYSIS PLAN: {analysis_plan}

TOOL EXECUTION RESULTS FROM EXPORTED LOGS:
{tool_results}

THREAT INTELLIGENCE (from internet search):
{threat_intel}

TASK:
Provide a comprehensive, actionable summary for the SOC analyst.

IMPORTANT CONTEXT:
- The data analyzed came from EXPORTED log files in GCS
- These logs are historical snapshots from source systems
- Any threats identified need verification on the actual source systems
- You cannot confirm if threats are still active or have been remediated

INCLUDE IN YOUR RESPONSE:
1. What was discovered in the exported log data
2. Security implications and risk level assessment
3. Specific indicators of compromise (IoCs) if any were found
4. Recommended immediate actions (for the analyst to take on source systems)
5. Long-term monitoring recommendations
6. Any relevant CVEs or threat intelligence context
7. Caveats about the analysis (data age, completeness, etc.)

Format as a professional security analyst report.
"""

# Helper function to format prompts
def get_pattern_analysis_prompt(file_name: str, summary_text: str, include_history: bool = True) -> str:
    """Get the formatted pattern analysis prompt with optional session history."""
    session_context = get_context_for_prompt() if include_history else ""
    return PATTERN_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        file_name=file_name,
        summary_text=summary_text
    )

def get_conversational_prompt(user_input: str, available_files: str, tool_descriptions: str, include_history: bool = True) -> str:
    """Get the formatted conversational assistant prompt with optional session history."""
    session_context = get_context_for_prompt() if include_history else ""
    return CONVERSATIONAL_ASSISTANT_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        user_input=user_input,
        available_files=available_files,
        tool_descriptions=tool_descriptions
    )

def get_final_analysis_prompt(user_input: str, analysis_plan: str, tool_results: str, threat_intel: str, include_history: bool = True) -> str:
    """Get the formatted final analysis prompt with optional session history."""
    session_context = get_context_for_prompt() if include_history else ""
    return FINAL_ANALYSIS_PROMPT.format(
        system_identity=SYSTEM_IDENTITY,
        session_context=session_context,
        user_input=user_input,
        analysis_plan=analysis_plan,
        tool_results=tool_results,
        threat_intel=threat_intel
    )


# =============================================================================
# ANALYSIS HISTORY TRACKING
# =============================================================================

@dataclass
class AnalysisRecord:
    """A single analysis event record."""
    timestamp: str
    file_name: str
    bucket_name: str
    analysis_type: str  # scan, analyze, investigate, search, templates
    query: str  # The pattern, search term, or command used
    summary: str  # Brief summary of findings
    key_findings: List[str] = field(default_factory=list)  # Top findings/IOCs
    record_count: int = 0  # Number of records/lines analyzed
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "file": self.file_name,
            "bucket": self.bucket_name,
            "type": self.analysis_type,
            "query": self.query,
            "summary": self.summary,
            "key_findings": self.key_findings,
            "records": self.record_count
        }
    
    def to_context_string(self) -> str:
        """Format for inclusion in LLM context."""
        findings = ", ".join(self.key_findings[:5]) if self.key_findings else "None noted"
        return f"[{self.timestamp}] {self.analysis_type.upper()} on {self.file_name}: {self.summary} | Key findings: {findings}"


class AnalysisHistory:
    """
    Tracks history of event record analyses for context continuity.
    
    Maintains a rolling window of recent analyses to provide context
    to the LLM for follow-up questions and correlation.
    """
    
    def __init__(self, max_records: int = 20):
        self._history: deque = deque(maxlen=max_records)
        self._files_analyzed: Dict[str, List[str]] = {}  # file -> list of analysis types
        self._iocs_found: Dict[str, List[str]] = {}  # IOC type -> values (IPs, users, etc.)
    
    def add_record(self, record: AnalysisRecord) -> None:
        """Add an analysis record to history."""
        self._history.append(record)
        
        # Track files analyzed
        if record.file_name not in self._files_analyzed:
            self._files_analyzed[record.file_name] = []
        if record.analysis_type not in self._files_analyzed[record.file_name]:
            self._files_analyzed[record.file_name].append(record.analysis_type)
    
    def add_ioc(self, ioc_type: str, value: str) -> None:
        """Track an indicator of compromise found during analysis."""
        if ioc_type not in self._iocs_found:
            self._iocs_found[ioc_type] = []
        if value not in self._iocs_found[ioc_type]:
            self._iocs_found[ioc_type].append(value)
            # Keep IOC lists manageable
            if len(self._iocs_found[ioc_type]) > 50:
                self._iocs_found[ioc_type] = self._iocs_found[ioc_type][-50:]
    
    def add_iocs(self, ioc_type: str, values: List[str]) -> None:
        """Track multiple IOCs of the same type."""
        for value in values:
            self.add_ioc(ioc_type, value)
    
    def get_recent_records(self, limit: int = 10) -> List[AnalysisRecord]:
        """Get the most recent analysis records."""
        return list(self._history)[-limit:]
    
    def get_context_summary(self, max_records: int = 10) -> str:
        """
        Generate a context summary for LLM prompts.
        
        Returns a formatted string summarizing recent analyses
        that can be injected into prompts.
        """
        if not self._history:
            return "No previous analyses in this session."
        
        lines = ["PREVIOUS ANALYSES IN THIS SESSION:"]
        
        # Recent analysis records
        recent = self.get_recent_records(max_records)
        for record in recent:
            lines.append(f"  - {record.to_context_string()}")
        
        # Files analyzed summary
        if self._files_analyzed:
            lines.append("\nFILES ANALYZED:")
            for file_name, types in list(self._files_analyzed.items())[-5:]:
                lines.append(f"  - {file_name}: {', '.join(types)}")
        
        # IOCs found
        if self._iocs_found:
            lines.append("\nIOCs IDENTIFIED:")
            for ioc_type, values in self._iocs_found.items():
                sample = values[:5]
                more = f" (+{len(values)-5} more)" if len(values) > 5 else ""
                lines.append(f"  - {ioc_type}: {', '.join(sample)}{more}")
        
        return "\n".join(lines)
    
    def get_file_history(self, file_name: str) -> List[AnalysisRecord]:
        """Get all analyses performed on a specific file."""
        return [r for r in self._history if r.file_name == file_name]
    
    def get_iocs(self, ioc_type: Optional[str] = None) -> Dict[str, List[str]]:
        """Get tracked IOCs, optionally filtered by type."""
        if ioc_type:
            return {ioc_type: self._iocs_found.get(ioc_type, [])}
        return self._iocs_found.copy()
    
    def clear(self) -> None:
        """Clear all history."""
        self._history.clear()
        self._files_analyzed.clear()
        self._iocs_found.clear()
    
    def to_json(self) -> str:
        """Export history as JSON."""
        return json.dumps({
            "records": [r.to_dict() for r in self._history],
            "files_analyzed": self._files_analyzed,
            "iocs_found": self._iocs_found
        }, indent=2)


# Global analysis history instance
_analysis_history = AnalysisHistory()


def get_analysis_history() -> AnalysisHistory:
    """Get the global analysis history instance."""
    return _analysis_history


def record_analysis(
    file_name: str,
    bucket_name: str,
    analysis_type: str,
    query: str,
    summary: str,
    key_findings: Optional[List[str]] = None,
    record_count: int = 0,
    iocs: Optional[Dict[str, List[str]]] = None
) -> AnalysisRecord:
    """
    Convenience function to record an analysis and return the record.
    
    Args:
        file_name: Name of the file analyzed
        bucket_name: GCS bucket name
        analysis_type: Type of analysis (scan, analyze, investigate, search, templates)
        query: The pattern, search term, or command used
        summary: Brief summary of findings
        key_findings: List of key findings or IOCs
        record_count: Number of records/lines analyzed
        iocs: Dict of IOC type -> values to track
    
    Returns:
        The created AnalysisRecord
    """
    record = AnalysisRecord(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_name=file_name,
        bucket_name=bucket_name,
        analysis_type=analysis_type,
        query=query,
        summary=summary,
        key_findings=key_findings or [],
        record_count=record_count
    )
    
    _analysis_history.add_record(record)
    
    # Track IOCs if provided
    if iocs:
        for ioc_type, values in iocs.items():
            _analysis_history.add_iocs(ioc_type, values)
    
    return record


def get_context_for_prompt() -> str:
    """
    Get analysis history context formatted for inclusion in LLM prompts.
    
    Returns:
        Formatted string with session history, or empty string if no history.
    """
    history = get_analysis_history()
    if not history._history:
        return ""
    
    return f"\n\n{history.get_context_summary()}\n"


def clear_session_history() -> None:
    """Clear the analysis history for a new session."""
    _analysis_history.clear()
