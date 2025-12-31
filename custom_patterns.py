"""
Custom GROK Patterns for Event Mill

This file allows you to define custom GROK-style patterns for your organization's
specific log formats, internal applications, and proprietary record structures.

HOW TO ADD CUSTOM PATTERNS:
1. Add your pattern to the CUSTOM_GROK_PATTERNS dictionary below
2. Use a descriptive uppercase name (e.g., MYAPP_TXID, INTERNAL_USERID)
3. The regex MUST include ONE capture group () for the value to extract
4. Restart the Event Mill client to load new patterns

PATTERN REQUIREMENTS:
- Pattern name: UPPERCASE with underscores (e.g., MYAPP_ERROR_CODE)
- Regex: Must have exactly ONE capture group for the extracted value
- The capture group defines what gets counted in analysis

EXAMPLES:
    # Simple pattern - extract transaction IDs like "TXN-12345678"
    "MYAPP_TXID": r"TXN-(\d{8})",
    
    # Extract custom error codes like "ERR:A001" or "ERR:B999"  
    "MYAPP_ERRCODE": r"ERR:([A-Z]\d{3})",
    
    # Extract internal user IDs like "uid=jsmith" or "uid=admin123"
    "INTERNAL_UID": r"uid=(\w+)",
    
    # Extract custom session tokens
    "SESSION_TOKEN": r"session=([a-f0-9]{32})",

USAGE IN EVENT MILL:
    ⚙ mill> analyze MYAPP_TXID app.log mybucket
    ⚙ mill> analyze INTERNAL_UID auth.log mybucket --full

For more complex patterns, use analyze_rex with raw regex:
    ⚙ mill> analyze_rex "your-complex-regex-here" file.log bucket
"""

# =============================================================================
# CUSTOM GROK PATTERNS - ADD YOUR PATTERNS HERE
# =============================================================================

CUSTOM_GROK_PATTERNS = {
    # -------------------------------------------------------------------------
    # EXAMPLE PATTERNS (uncomment and modify as needed)
    # -------------------------------------------------------------------------
    
    # Transaction/Request IDs
    # "MYAPP_TXID": r"TXN-(\d{8})",
    # "REQUEST_ID": r"req_([a-zA-Z0-9]{16})",
    # "CORRELATION_ID": r"correlation[_-]?id[=:\s]+([a-f0-9-]{36})",
    
    # Custom Error Codes
    # "MYAPP_ERRCODE": r"ERR:([A-Z]{2}\d{4})",
    # "INTERNAL_ERROR": r"\[E(\d{4})\]",
    
    # Internal User/Account IDs
    # "INTERNAL_UID": r"uid=(\w+)",
    # "ACCOUNT_ID": r"acct[_-]?id[=:\s]+(\d{10})",
    # "EMPLOYEE_ID": r"emp[_-]?(\d{6})",
    
    # Custom Application Identifiers
    # "SERVICE_NAME": r"service[=:\s]+(\w+)",
    # "MODULE_ID": r"\[([A-Z]{3}-\d{3})\]",
    # "COMPONENT": r"component=(\w+)",
    
    # Custom Timestamps/Versions
    # "BUILD_VERSION": r"v(\d+\.\d+\.\d+)",
    # "RELEASE_TAG": r"release[=:\s]+([a-zA-Z0-9._-]+)",
    
    # Network/Infrastructure
    # "INTERNAL_VLAN": r"vlan[=:\s]+(\d{1,4})",
    # "CLUSTER_NODE": r"node[=:\s]+([a-zA-Z0-9-]+)",
    # "POD_NAME": r"pod[=:\s]+([a-zA-Z0-9-]+)",
    
    # Security/Compliance
    # "TICKET_ID": r"ticket[=:\s]+([A-Z]{2,4}-\d{4,6})",
    # "CASE_NUMBER": r"case[=:\s]+(\d{8})",
    # "POLICY_ID": r"policy[=:\s]+([A-Z0-9_]+)",
    
    # -------------------------------------------------------------------------
    # ADD YOUR CUSTOM PATTERNS BELOW THIS LINE
    # -------------------------------------------------------------------------
    
    
}

# =============================================================================
# PATTERN VALIDATION (DO NOT MODIFY)
# =============================================================================

def validate_patterns():
    """Validate that all custom patterns have exactly one capture group."""
    import re
    errors = []
    
    for name, pattern in CUSTOM_GROK_PATTERNS.items():
        try:
            compiled = re.compile(pattern)
            groups = compiled.groups
            if groups != 1:
                errors.append(f"  {name}: Expected 1 capture group, found {groups}")
        except re.error as e:
            errors.append(f"  {name}: Invalid regex - {e}")
    
    if errors:
        print("⚠️  Custom GROK Pattern Validation Errors:")
        for err in errors:
            print(err)
        return False
    return True

def get_custom_patterns():
    """Return validated custom patterns."""
    validate_patterns()
    return CUSTOM_GROK_PATTERNS

# Validate on import
if CUSTOM_GROK_PATTERNS:
    validate_patterns()
