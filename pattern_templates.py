"""
Pattern Template Generator for Log Analysis

This module provides GROK-style pattern templates and detection logic
for parsing various log formats. Uses OpenTelemetry semantic conventions
for field naming where applicable.

OpenTelemetry Semantic Conventions Reference:
- https://opentelemetry.io/docs/specs/semconv/
"""

import re
import json
from typing import Dict, List, Tuple, Optional
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict

# =============================================================================
# GROK PATTERN DEFINITIONS
# =============================================================================

GROK_PATTERNS = {
    # Network patterns
    "IP": r"(?:\d{1,3}\.){3}\d{1,3}",
    "IPV6": r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}",
    "MAC": r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
    "HOSTNAME": r"\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*\.?\b",
    "PORT": r"\b\d{1,5}\b",
    "URI": r"[A-Za-z][A-Za-z0-9+.-]*://[^\s]+",
    "URIPATH": r"/[^\s?#]*",
    
    # Timestamp patterns
    "TIMESTAMP_ISO8601": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    "HTTPDATE": r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}",
    "SYSLOGTIMESTAMP": r"[A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}",
    "DATESTAMP": r"\d{4}-\d{2}-\d{2}",
    "TIME": r"\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    
    # Identity patterns
    "USERNAME": r"[a-zA-Z0-9._-]+",
    "USER": r"[a-zA-Z0-9._-]+",
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "UUID": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    
    # HTTP patterns
    "HTTPMETHOD": r"GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND",
    "HTTPVERSION": r"HTTP/\d\.\d",
    "HTTPSTATUS": r"\d{3}",
    "USERAGENT": r"[^\"]+",
    
    # Numeric patterns
    "INT": r"[+-]?\d+",
    "NUMBER": r"[+-]?\d+(?:\.\d+)?",
    "POSINT": r"\d+",
    "BYTES": r"\d+",
    
    # Generic patterns
    "WORD": r"\b\w+\b",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "QUOTEDSTRING": r"\"[^\"]*\"|'[^']*'",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s+",
    
    # Log level patterns
    "LOGLEVEL": r"DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|TRACE|NOTICE|ALERT|EMERG(?:ENCY)?",
    
    # Process patterns
    "PID": r"\d+",
    "PROG": r"[\w._/-]+",
    
    # Windows Event patterns
    "WINEVENTID": r"\d{1,5}",
    "SID": r"S-\d-\d+-(?:\d+-)*\d+",
}

# =============================================================================
# OPENTELEMETRY SEMANTIC CONVENTION FIELD MAPPINGS
# =============================================================================

OTEL_FIELD_MAPPINGS = {
    # Network attributes
    "src_ip": "source.address",
    "dst_ip": "destination.address",
    "src_port": "source.port",
    "dst_port": "destination.port",
    "client_ip": "client.address",
    "server_ip": "server.address",
    
    # HTTP attributes
    "http_method": "http.request.method",
    "http_status": "http.response.status_code",
    "http_url": "url.full",
    "http_path": "url.path",
    "http_query": "url.query",
    "user_agent": "user_agent.original",
    "referer": "http.request.header.referer",
    "content_length": "http.request.body.size",
    "response_size": "http.response.body.size",
    
    # User/Identity attributes
    "user_id": "user.id",
    "user_name": "user.name",
    "user_email": "user.email",
    "user_domain": "user.domain",
    "target_user": "user.target.name",
    "effective_user": "user.effective.name",
    
    # Authentication attributes
    "auth_type": "authentication.type",
    "auth_result": "authentication.result",
    "session_id": "session.id",
    
    # Process attributes
    "process_id": "process.pid",
    "process_name": "process.name",
    "process_command": "process.command_line",
    "parent_pid": "process.parent.pid",
    
    # Host attributes
    "hostname": "host.name",
    "host_ip": "host.ip",
    
    # Event attributes
    "event_id": "event.id",
    "event_type": "event.type",
    "event_category": "event.category",
    "event_action": "event.action",
    "event_outcome": "event.outcome",
    
    # Error attributes
    "error_type": "error.type",
    "error_message": "error.message",
    "exception_type": "exception.type",
    "exception_message": "exception.message",
    "stack_trace": "exception.stacktrace",
    
    # Log attributes
    "log_level": "log.level",
    "log_logger": "log.logger",
    "log_file": "log.file.path",
    
    # Cloud attributes
    "cloud_provider": "cloud.provider",
    "cloud_region": "cloud.region",
    "cloud_account": "cloud.account.id",
    
    # Container attributes
    "container_id": "container.id",
    "container_name": "container.name",
    "container_image": "container.image.name",
    
    # Kubernetes attributes
    "k8s_namespace": "k8s.namespace.name",
    "k8s_pod": "k8s.pod.name",
    "k8s_container": "k8s.container.name",
}

# =============================================================================
# ECS EVENT CLASSIFICATION DEFINITIONS
# Based on Elastic Common Schema (ECS) event.category values
# Reference: https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category
# =============================================================================

EVENT_CLASSIFICATIONS = {
    # -------------------------------------------------------------------------
    # SECURITY OPERATIONS - Primary Categories
    # -------------------------------------------------------------------------
    "authentication": {
        "description": "Events related to challenge/response credential verification for session creation",
        "keywords": ["login", "logon", "logout", "logoff", "auth", "authenticate", "signin", "sign-in", "signout", "sso", "credential", "password", "kerberos", "ntlm", "saml", "oauth"],
        "expected_event_types": ["start", "end", "info"],
        "subtypes": {
            "success": ["success", "succeeded", "accepted", "granted", "allowed", "authenticated", "logged in", "logon success"],
            "failure": ["fail", "failed", "denied", "rejected", "invalid", "incorrect", "wrong", "bad", "locked", "expired", "logon failure"],
            "privileged": ["sudo", "root", "admin", "administrator", "elevated", "privilege", "runas", "impersonate"],
            "interactive": ["interactive", "console", "rdp", "ssh", "terminal", "tty", "gui", "desktop"],
            "service": ["service", "batch", "scheduled", "cron", "daemon", "api", "token", "service account"],
            "mfa": ["mfa", "2fa", "otp", "totp", "two-factor", "multi-factor", "second factor", "verification code"],
        }
    },
    "iam": {
        "description": "Identity and access management events - users, groups, roles, permissions",
        "keywords": ["user", "group", "role", "permission", "ldap", "active directory", "okta", "duo", "azure ad", "identity", "account", "member", "privilege"],
        "expected_event_types": ["admin", "change", "creation", "deletion", "group", "info", "user"],
        "subtypes": {
            "user_created": ["user created", "account created", "new user", "add user"],
            "user_deleted": ["user deleted", "account deleted", "remove user", "delete user"],
            "user_modified": ["user modified", "account modified", "update user", "change user"],
            "group_created": ["group created", "new group", "add group"],
            "group_modified": ["group modified", "group membership", "add member", "remove member"],
            "role_assigned": ["role assigned", "permission granted", "access granted"],
            "role_revoked": ["role revoked", "permission revoked", "access revoked"],
            "password_change": ["password change", "password reset", "credential update"],
        }
    },
    "intrusion_detection": {
        "description": "IDS/IPS alerts from network and host-based systems",
        "keywords": ["ids", "ips", "snort", "suricata", "palo alto", "threat", "alert", "signature", "exploit", "attack", "intrusion", "detection", "prevention"],
        "expected_event_types": ["allowed", "denied", "info"],
        "subtypes": {
            "blocked": ["blocked", "dropped", "prevented", "denied", "stopped"],
            "allowed": ["allowed", "passed", "permitted"],
            "alert": ["alert", "warning", "detected", "suspicious"],
        }
    },
    "malware": {
        "description": "Malware detection events from EDR/EPP/AV systems",
        "keywords": ["malware", "virus", "trojan", "ransomware", "worm", "spyware", "adware", "rootkit", "backdoor", "edr", "endpoint", "antivirus", "av", "quarantine", "infected"],
        "expected_event_types": ["info"],
        "subtypes": {
            "detected": ["detected", "found", "discovered", "identified"],
            "blocked": ["blocked", "quarantined", "removed", "cleaned", "deleted"],
            "allowed": ["allowed", "whitelisted", "excluded"],
        }
    },
    "threat": {
        "description": "Threat intelligence events describing actor targets, motives, or behaviors",
        "keywords": ["threat", "ioc", "indicator", "compromise", "ttp", "mitre", "att&ck", "campaign", "actor", "apt", "intelligence"],
        "expected_event_types": ["indicator"],
        "subtypes": {
            "indicator_match": ["indicator match", "ioc match", "hash match", "ip match", "domain match"],
            "behavior": ["behavior", "technique", "tactic", "procedure"],
        }
    },
    "vulnerability": {
        "description": "Vulnerability scan results from security scanners",
        "keywords": ["vulnerability", "cve", "cvss", "scan", "tenable", "qualys", "nessus", "openvas", "patch", "missing", "vulnerable", "weakness"],
        "expected_event_types": ["info"],
        "subtypes": {
            "critical": ["critical", "severity 10", "severity 9"],
            "high": ["high", "severity 8", "severity 7"],
            "medium": ["medium", "severity 6", "severity 5", "severity 4"],
            "low": ["low", "severity 3", "severity 2", "severity 1"],
            "info": ["informational", "info", "severity 0"],
        }
    },
    
    # -------------------------------------------------------------------------
    # SECURITY OPERATIONS - Activity Categories
    # -------------------------------------------------------------------------
    "network": {
        "description": "Network activity including connections, traffic, and protocol events",
        "keywords": ["connection", "connect", "socket", "tcp", "udp", "dns", "firewall", "packet", "flow", "traffic", "network", "port", "protocol", "ip address"],
        "expected_event_types": ["access", "allowed", "connection", "denied", "end", "info", "protocol", "start"],
        "subtypes": {
            "connection_start": ["connect", "established", "opened", "syn", "new connection"],
            "connection_end": ["disconnect", "closed", "reset", "fin", "terminated"],
            "allowed": ["allowed", "permitted", "accepted", "passed"],
            "denied": ["denied", "blocked", "dropped", "rejected", "refused"],
            "dns": ["dns", "resolve", "lookup", "query", "nxdomain"],
        }
    },
    "file": {
        "description": "File system events - creation, access, modification, deletion",
        "keywords": ["file", "directory", "folder", "path", "read", "write", "delete", "create", "modify", "rename", "copy", "move", "chmod", "chown"],
        "expected_event_types": ["access", "change", "creation", "deletion", "info"],
        "subtypes": {
            "created": ["create", "created", "new", "add", "write"],
            "modified": ["modify", "modified", "change", "changed", "update", "updated", "edit"],
            "deleted": ["delete", "deleted", "remove", "removed", "unlink"],
            "accessed": ["access", "accessed", "read", "open", "opened", "view"],
            "renamed": ["rename", "renamed", "move", "moved"],
            "permission_change": ["chmod", "chown", "permission", "acl"],
        }
    },
    "process": {
        "description": "Process lifecycle events - creation, termination, and ancestry",
        "keywords": ["process", "exec", "spawn", "fork", "command", "cmd", "shell", "script", "pid", "parent", "child", "terminate", "kill"],
        "expected_event_types": ["access", "change", "end", "info", "start"],
        "subtypes": {
            "started": ["start", "started", "launch", "launched", "exec", "spawn", "created", "fork"],
            "stopped": ["stop", "stopped", "terminate", "terminated", "killed", "exit", "ended"],
            "injection": ["inject", "injection", "hollowing", "dll injection"],
        }
    },
    "registry": {
        "description": "Windows registry events - access and modifications",
        "keywords": ["registry", "hkey", "hklm", "hkcu", "regedit", "regkey", "regvalue", "windows registry"],
        "expected_event_types": ["access", "change", "creation", "deletion"],
        "subtypes": {
            "created": ["create", "created", "add", "set"],
            "modified": ["modify", "modified", "change", "changed", "update"],
            "deleted": ["delete", "deleted", "remove", "removed"],
            "accessed": ["access", "accessed", "read", "query"],
        }
    },
    "library": {
        "description": "Library/module loading events (DLL, SO, dynlib)",
        "keywords": ["dll", "so", "dynlib", "library", "module", "load", "inject", "sideload"],
        "expected_event_types": ["start"],
        "subtypes": {
            "loaded": ["load", "loaded", "loading"],
            "unloaded": ["unload", "unloaded"],
            "sideload": ["sideload", "hijack", "injection"],
        }
    },
    "driver": {
        "description": "OS driver and kernel module events",
        "keywords": ["driver", "kernel", "module", "kext", "sys", "ko", "device driver"],
        "expected_event_types": ["change", "end", "info", "start"],
        "subtypes": {
            "loaded": ["load", "loaded", "start", "started", "install"],
            "unloaded": ["unload", "unloaded", "stop", "stopped", "remove"],
        }
    },
    
    # -------------------------------------------------------------------------
    # IT RELIABILITY - Infrastructure Categories
    # -------------------------------------------------------------------------
    "host": {
        "description": "Host inventory and lifecycle events (not activity on hosts)",
        "keywords": ["host", "server", "machine", "vm", "instance", "boot", "shutdown", "reboot", "startup", "inventory", "asset"],
        "expected_event_types": ["access", "change", "end", "info", "start"],
        "subtypes": {
            "started": ["start", "started", "boot", "booted", "power on", "launched"],
            "stopped": ["stop", "stopped", "shutdown", "power off", "terminated"],
            "restarted": ["restart", "restarted", "reboot", "rebooted"],
            "provisioned": ["provision", "provisioned", "created", "deployed"],
            "decommissioned": ["decommission", "decommissioned", "deleted", "destroyed"],
        }
    },
    "configuration": {
        "description": "Configuration and settings changes",
        "keywords": ["config", "configuration", "setting", "parameter", "policy", "change", "audit", "compliance"],
        "expected_event_types": ["access", "change", "creation", "deletion", "info"],
        "subtypes": {
            "changed": ["change", "changed", "modify", "modified", "update", "updated"],
            "created": ["create", "created", "add", "added", "new"],
            "deleted": ["delete", "deleted", "remove", "removed"],
            "policy_change": ["policy", "rule", "acl", "firewall rule"],
        }
    },
    "package": {
        "description": "Software package installation and management",
        "keywords": ["package", "install", "uninstall", "upgrade", "patch", "update", "apt", "yum", "rpm", "deb", "msi", "software"],
        "expected_event_types": ["access", "change", "deletion", "info", "installation", "start"],
        "subtypes": {
            "installed": ["install", "installed", "add", "added"],
            "uninstalled": ["uninstall", "uninstalled", "remove", "removed"],
            "upgraded": ["upgrade", "upgraded", "update", "updated", "patch", "patched"],
        }
    },
    "database": {
        "description": "Database events and metrics",
        "keywords": ["database", "db", "sql", "query", "mysql", "postgres", "oracle", "mongodb", "elasticsearch", "redis", "table", "schema"],
        "expected_event_types": ["access", "change", "info", "error"],
        "subtypes": {
            "query": ["query", "select", "read"],
            "modification": ["insert", "update", "delete", "modify", "write"],
            "schema_change": ["create table", "alter table", "drop table", "schema", "ddl"],
            "connection": ["connect", "disconnect", "connection"],
            "error": ["error", "failed", "timeout", "deadlock"],
        }
    },
    "session": {
        "description": "Logical persistent connections to hosts and services",
        "keywords": ["session", "connection", "ssh", "rdp", "vnc", "terminal", "shell", "interactive"],
        "expected_event_types": ["start", "end", "info"],
        "subtypes": {
            "started": ["start", "started", "opened", "established", "connected"],
            "ended": ["end", "ended", "closed", "disconnected", "terminated"],
        }
    },
    
    # -------------------------------------------------------------------------
    # IT RELIABILITY - Application Categories
    # -------------------------------------------------------------------------
    "web": {
        "description": "Web server access events",
        "keywords": ["http", "https", "request", "response", "web", "apache", "nginx", "iis", "api", "endpoint", "url", "uri"],
        "expected_event_types": ["access", "error", "info"],
        "subtypes": {
            "success": ["200", "201", "204", "2xx", "ok", "success"],
            "redirect": ["301", "302", "304", "3xx", "redirect"],
            "client_error": ["400", "401", "403", "404", "4xx", "bad request", "unauthorized", "forbidden", "not found"],
            "server_error": ["500", "502", "503", "504", "5xx", "internal server error", "bad gateway", "service unavailable"],
        }
    },
    "api": {
        "description": "API call events from OS, managed sources, or network protocols",
        "keywords": ["api", "rest", "soap", "rpc", "grpc", "websocket", "graphql", "endpoint", "call", "invoke"],
        "expected_event_types": ["access", "admin", "allowed", "change", "creation", "deletion", "denied", "end", "info", "start", "user"],
        "subtypes": {
            "success": ["success", "succeeded", "ok", "200", "201"],
            "failure": ["fail", "failed", "error", "denied", "rejected"],
            "rate_limited": ["rate limit", "throttle", "429", "too many requests"],
        }
    },
    "email": {
        "description": "Email message and protocol events",
        "keywords": ["email", "mail", "smtp", "imap", "pop3", "exchange", "attachment", "spam", "phishing", "sender", "recipient"],
        "expected_event_types": ["info"],
        "subtypes": {
            "sent": ["sent", "send", "outbound", "delivered"],
            "received": ["received", "receive", "inbound", "delivered"],
            "blocked": ["blocked", "quarantined", "spam", "rejected"],
            "phishing": ["phishing", "suspicious", "malicious"],
        }
    },
    
    # -------------------------------------------------------------------------
    # GENERAL CATEGORIES
    # -------------------------------------------------------------------------
    "error": {
        "description": "Application and system errors (custom category for reliability)",
        "keywords": ["error", "exception", "fail", "crash", "panic", "fatal", "critical", "traceback", "stacktrace"],
        "expected_event_types": ["error", "info"],
        "subtypes": {
            "application": ["application", "app", "runtime", "exception", "traceback"],
            "system": ["system", "kernel", "os", "hardware", "oom", "out of memory"],
            "database": ["database", "db", "sql", "query", "connection"],
            "network": ["network", "connection", "timeout", "refused", "unreachable"],
            "timeout": ["timeout", "timed out", "deadline exceeded"],
        }
    },
}

# =============================================================================
# PATTERN TEMPLATE DATA CLASSES
# =============================================================================

@dataclass
class ExtractionField:
    """Represents a field to extract from a log line"""
    field_name: str
    grok_pattern: str
    otel_name: str
    regex: str
    sample_values: List[str]

@dataclass
class PatternTemplate:
    """Represents a complete pattern template for log parsing"""
    template_id: str
    template_name: str
    event_category: str
    event_subtype: str
    detection_logic: str
    confidence_score: float
    sample_count: int
    extractions: Dict[str, str]
    otel_mappings: Dict[str, str]
    sample_lines: List[str]
    regex_pattern: str
    notes: str

# =============================================================================
# PATTERN TEMPLATE GENERATOR
# =============================================================================

class PatternTemplateGenerator:
    """Generates structured pattern templates from log samples"""
    
    def __init__(self):
        self.grok_patterns = GROK_PATTERNS
        self.otel_mappings = OTEL_FIELD_MAPPINGS
        self.event_classifications = EVENT_CLASSIFICATIONS
    
    def analyze_logs(self, log_lines: List[str], max_templates: int = 20) -> List[PatternTemplate]:
        """
        Analyze log lines and generate pattern templates.
        
        Args:
            log_lines: List of log lines to analyze
            max_templates: Maximum number of templates to generate
            
        Returns:
            List of PatternTemplate objects
        """
        # Group similar lines by structure
        structure_groups = self._group_by_structure(log_lines)
        
        # Generate templates for each group
        templates = []
        for structure_key, lines in sorted(structure_groups.items(), key=lambda x: -len(x[1]))[:max_templates]:
            if len(lines) >= 2:  # Need at least 2 samples
                template = self._generate_template(structure_key, lines)
                if template:
                    templates.append(template)
        
        return templates
    
    def _group_by_structure(self, log_lines: List[str]) -> Dict[str, List[str]]:
        """Group log lines by their structural signature"""
        groups = defaultdict(list)
        
        for line in log_lines:
            line = line.strip()
            if not line:
                continue
            
            # Generate structural signature
            signature = self._generate_signature(line)
            groups[signature].append(line)
        
        return groups
    
    def _generate_signature(self, line: str) -> str:
        """Generate a structural signature for a log line"""
        signature = line
        
        # Replace variable data with tokens (order matters)
        replacements = [
            (r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?', '<TIMESTAMP>'),
            (r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}', '<HTTPDATE>'),
            (r'[A-Za-z]{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}', '<SYSLOGTS>'),
            (r'(?:\d{1,3}\.){3}\d{1,3}', '<IP>'),
            (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<UUID>'),
            (r'"[^"]*"', '<QUOTED>'),
            (r"'[^']*'", '<SQUOTED>'),
            (r'\b\d+\.\d+\b', '<FLOAT>'),
            (r'\b\d{4,}\b', '<BIGNUM>'),
            (r'\b\d{1,3}\b', '<NUM>'),
        ]
        
        for pattern, token in replacements:
            signature = re.sub(pattern, token, signature)
        
        # Truncate very long signatures
        if len(signature) > 200:
            signature = signature[:200] + "..."
        
        return signature
    
    def _generate_template(self, signature: str, sample_lines: List[str]) -> Optional[PatternTemplate]:
        """Generate a pattern template from a group of similar lines"""
        
        # Classify the event type
        event_category, event_subtype = self._classify_event(sample_lines)
        
        # Detect extractable fields
        extractions, otel_mappings = self._detect_extractions(sample_lines)
        
        # Generate detection logic
        detection_logic = self._generate_detection_logic(sample_lines, event_category, event_subtype)
        
        # Generate regex pattern
        regex_pattern = self._generate_regex(signature, extractions)
        
        # Calculate confidence score
        confidence = self._calculate_confidence(len(sample_lines), len(extractions), event_category)
        
        # Generate template ID
        template_id = f"{event_category}_{event_subtype}_v1" if event_subtype else f"{event_category}_generic_v1"
        template_id = re.sub(r'[^a-z0-9_]', '_', template_id.lower())
        
        # Generate human-readable name
        template_name = f"{event_category.title()} - {event_subtype.title() if event_subtype else 'Generic'}"
        
        return PatternTemplate(
            template_id=template_id,
            template_name=template_name,
            event_category=event_category,
            event_subtype=event_subtype or "generic",
            detection_logic=detection_logic,
            confidence_score=confidence,
            sample_count=len(sample_lines),
            extractions=extractions,
            otel_mappings=otel_mappings,
            sample_lines=sample_lines[:5],  # Keep first 5 samples
            regex_pattern=regex_pattern,
            notes=f"Auto-generated from {len(sample_lines)} samples"
        )
    
    def _classify_event(self, sample_lines: List[str]) -> Tuple[str, str]:
        """Classify the event type based on content analysis"""
        
        # Combine samples for analysis
        combined_text = " ".join(sample_lines[:100]).lower()
        
        best_category = "unknown"
        best_subtype = ""
        best_score = 0
        
        for category, config in self.event_classifications.items():
            # Check category keywords
            category_score = sum(1 for kw in config["keywords"] if kw in combined_text)
            
            if category_score > best_score:
                best_score = category_score
                best_category = category
                best_subtype = ""
                
                # Check subtypes
                for subtype, subtype_keywords in config.get("subtypes", {}).items():
                    subtype_score = sum(1 for kw in subtype_keywords if kw in combined_text)
                    if subtype_score > 0:
                        best_subtype = subtype
                        break
        
        return best_category, best_subtype
    
    def _detect_extractions(self, sample_lines: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Detect extractable fields from sample lines"""
        
        extractions = {}
        otel_mappings = {}
        
        # Check for common patterns in samples
        combined = " ".join(sample_lines[:50])
        
        # IP addresses
        if re.search(GROK_PATTERNS["IP"], combined):
            ips = re.findall(GROK_PATTERNS["IP"], combined)
            if len(set(ips)) > 1:  # Multiple different IPs = variable field
                extractions["source_ip"] = f"%{{IP:src_ip}}"
                otel_mappings["src_ip"] = OTEL_FIELD_MAPPINGS.get("src_ip", "source.address")
        
        # Timestamps
        for ts_name, ts_pattern in [("TIMESTAMP_ISO8601", "timestamp"), ("HTTPDATE", "timestamp"), ("SYSLOGTIMESTAMP", "timestamp")]:
            if re.search(GROK_PATTERNS[ts_name], combined):
                extractions["timestamp"] = f"%{{{ts_name}:timestamp}}"
                otel_mappings["timestamp"] = "@timestamp"
                break
        
        # HTTP Status codes
        if re.search(r'\s\d{3}\s', combined):
            extractions["http_status"] = "%{HTTPSTATUS:http_status}"
            otel_mappings["http_status"] = OTEL_FIELD_MAPPINGS.get("http_status", "http.response.status_code")
        
        # HTTP Methods
        if re.search(GROK_PATTERNS["HTTPMETHOD"], combined):
            extractions["http_method"] = "%{HTTPMETHOD:http_method}"
            otel_mappings["http_method"] = OTEL_FIELD_MAPPINGS.get("http_method", "http.request.method")
        
        # User patterns
        user_patterns = [
            (r'user[=:\s]+["\']?(\w+)["\']?', "user_name"),
            (r'username[=:\s]+["\']?(\w+)["\']?', "user_name"),
            (r'User\s+["\']?(\w+)["\']?', "user_name"),
        ]
        for pattern, field in user_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                extractions[field] = f'user "%{{DATA:{field}}}"'
                otel_mappings[field] = OTEL_FIELD_MAPPINGS.get("user_name", "user.name")
                break
        
        # Log levels
        if re.search(GROK_PATTERNS["LOGLEVEL"], combined, re.IGNORECASE):
            extractions["log_level"] = "%{LOGLEVEL:log_level}"
            otel_mappings["log_level"] = OTEL_FIELD_MAPPINGS.get("log_level", "log.level")
        
        # UUIDs
        if re.search(GROK_PATTERNS["UUID"], combined):
            extractions["request_id"] = "%{UUID:request_id}"
            otel_mappings["request_id"] = "trace.id"
        
        # Quoted strings (potential messages/reasons)
        quoted_matches = re.findall(r'"([^"]+)"', combined)
        if len(set(quoted_matches)) > 3:  # Variable quoted content
            extractions["message"] = "%{QUOTEDSTRING:message}"
            otel_mappings["message"] = "message"
        
        # Numeric values (bytes, duration, etc.)
        if re.search(r'bytes[=:\s]+\d+', combined, re.IGNORECASE):
            extractions["bytes"] = "bytes=%{INT:bytes}"
            otel_mappings["bytes"] = "http.response.body.size"
        
        if re.search(r'duration[=:\s]+[\d.]+', combined, re.IGNORECASE):
            extractions["duration"] = "duration=%{NUMBER:duration}"
            otel_mappings["duration"] = "event.duration"
        
        return extractions, otel_mappings
    
    def _generate_detection_logic(self, sample_lines: List[str], category: str, subtype: str) -> str:
        """Generate detection logic expression"""
        
        conditions = []
        combined = " ".join(sample_lines[:20]).lower()
        
        # Add category-specific conditions
        if category in self.event_classifications:
            keywords = self.event_classifications[category]["keywords"]
            found_keywords = [kw for kw in keywords if kw in combined]
            if found_keywords:
                conditions.append(f"contains('{found_keywords[0]}')")
        
        # Add subtype conditions
        if subtype and category in self.event_classifications:
            subtypes = self.event_classifications[category].get("subtypes", {})
            if subtype in subtypes:
                subtype_keywords = subtypes[subtype]
                found_subtype_kw = [kw for kw in subtype_keywords if kw in combined]
                if found_subtype_kw:
                    conditions.append(f"contains('{found_subtype_kw[0]}')")
        
        # Add structural conditions
        if re.search(GROK_PATTERNS["IP"], combined):
            conditions.append("has_ip()")
        
        if re.search(GROK_PATTERNS["HTTPMETHOD"], combined):
            conditions.append("has_http_method()")
        
        if not conditions:
            conditions.append("true")  # Default match
        
        return " AND ".join(conditions)
    
    def _generate_regex(self, signature: str, extractions: Dict[str, str]) -> str:
        """Generate a regex pattern from the signature"""
        
        # Start with the signature and convert tokens to regex
        regex = re.escape(signature)
        
        # Replace escaped tokens with capture groups
        # Using lambda functions to avoid backslash escape issues in re.sub replacements
        token_replacements = [
            (r'\\<TIMESTAMP\\>', r'(?P<timestamp>' + GROK_PATTERNS["TIMESTAMP_ISO8601"] + r')'),
            (r'\\<HTTPDATE\\>', r'(?P<timestamp>' + GROK_PATTERNS["HTTPDATE"] + r')'),
            (r'\\<SYSLOGTS\\>', r'(?P<timestamp>' + GROK_PATTERNS["SYSLOGTIMESTAMP"] + r')'),
            (r'\\<IP\\>', r'(?P<ip>' + GROK_PATTERNS["IP"] + r')'),
            (r'\\<UUID\\>', r'(?P<uuid>' + GROK_PATTERNS["UUID"] + r')'),
            (r'\\<QUOTED\\>', r'(?P<quoted>"[^"]*")'),
            (r'\\<SQUOTED\\>', r"(?P<squoted>'[^']*')"),
            (r'\\<FLOAT\\>', r'(?P<float>\d+\.\d+)'),
            (r'\\<BIGNUM\\>', r'(?P<bignum>\d{4,})'),
            (r'\\<NUM\\>', r'(?P<num>\d{1,3})'),
        ]
        
        for token, replacement in token_replacements:
            # Use a lambda to return the replacement string literally (avoids backslash interpretation)
            regex = re.sub(token, lambda m: replacement, regex, count=1)
            # For subsequent matches, use non-capturing groups
            non_capturing = replacement.replace('(?P<', '(?:').split('>')[0] + '>'
            regex = re.sub(token, lambda m, nc=non_capturing: nc, regex)
        
        return regex
    
    def _calculate_confidence(self, sample_count: int, extraction_count: int, category: str) -> float:
        """Calculate confidence score for the template"""
        
        # Base score from sample count
        sample_score = min(sample_count / 100, 0.4)  # Max 0.4 from samples
        
        # Score from extractions
        extraction_score = min(extraction_count / 5, 0.3)  # Max 0.3 from extractions
        
        # Score from classification
        category_score = 0.3 if category != "unknown" else 0.1
        
        return round(sample_score + extraction_score + category_score, 2)
    
    def to_json(self, templates: List[PatternTemplate]) -> str:
        """Convert templates to JSON format"""
        return json.dumps([asdict(t) for t in templates], indent=2)
    
    def to_grok_config(self, templates: List[PatternTemplate]) -> str:
        """Convert templates to GROK configuration format"""
        output = []
        
        for t in templates:
            output.append(f"# Template: {t.template_name}")
            output.append(f"# Category: {t.event_category}/{t.event_subtype}")
            output.append(f"# Detection: {t.detection_logic}")
            output.append(f"# Confidence: {t.confidence_score}")
            output.append(f"# Samples: {t.sample_count}")
            output.append("")
            
            for field_name, grok_pattern in t.extractions.items():
                otel_name = t.otel_mappings.get(field_name, field_name)
                output.append(f"# {field_name} -> {otel_name}")
                output.append(f"EXTRACT_{t.template_id.upper()}_{field_name.upper()} {grok_pattern}")
            
            output.append("")
            output.append(f"# Sample lines:")
            for sample in t.sample_lines[:2]:
                output.append(f"# {sample[:100]}...")
            output.append("")
            output.append("-" * 60)
            output.append("")
        
        return "\n".join(output)


# =============================================================================
# HELPER FUNCTIONS FOR MCP TOOL
# =============================================================================

def generate_templates_from_text(log_text: str, max_templates: int = 20) -> str:
    """
    Generate pattern templates from log text.
    
    Args:
        log_text: Raw log text (newline separated)
        max_templates: Maximum number of templates to generate
        
    Returns:
        JSON string of generated templates
    """
    generator = PatternTemplateGenerator()
    lines = log_text.strip().split('\n')
    templates = generator.analyze_logs(lines, max_templates)
    return generator.to_json(templates)


def get_grok_patterns() -> Dict[str, str]:
    """Return available GROK patterns"""
    return GROK_PATTERNS


def get_otel_mappings() -> Dict[str, str]:
    """Return OpenTelemetry field mappings"""
    return OTEL_FIELD_MAPPINGS


def get_event_classifications() -> Dict:
    """Return event classification definitions"""
    return EVENT_CLASSIFICATIONS
