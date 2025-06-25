"""
Compliance Validation Module

Validates network configurations against security policies and
compliance requirements.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import yaml

logger = logging.getLogger(__name__)


class ComplianceStatus(Enum):
    """Compliance check status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


class RuleSeverity(Enum):
    """Compliance rule severity levels"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class ComplianceRule:
    """Represents a compliance rule"""
    rule_id: str
    name: str
    description: str
    category: str  # security, operational, regulatory
    severity: RuleSeverity
    vendor: Optional[str] = None  # None for vendor-agnostic rules
    check_type: str = "regex"  # regex, function, command
    check_pattern: Optional[str] = None
    check_function: Optional[str] = None
    remediation: Optional[str] = None
    enabled: bool = True


@dataclass
class ComplianceViolation:
    """Represents a compliance violation"""
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    status: ComplianceStatus
    message: str
    line_number: Optional[int] = None
    config_line: Optional[str] = None
    remediation: Optional[str] = None


@dataclass
class ComplianceReport:
    """Compliance validation report"""
    report_id: str
    timestamp: datetime
    device: str
    total_rules_checked: int
    violations: List[ComplianceViolation]
    compliant_count: int
    non_compliant_count: int
    warning_count: int
    overall_status: ComplianceStatus
    risk_score: float  # 0-100


class ComplianceValidator:
    """
    Validates network configurations against compliance policies
    """
    
    def __init__(self):
        """Initialize compliance validator"""
        self.rules: Dict[str, ComplianceRule] = {}
        self.rule_sets: Dict[str, List[str]] = {}  # Named sets of rules
        self._load_default_rules()
        
    def _load_default_rules(self):
        """Load default compliance rules"""
        default_rules = [
            # Security Rules
            ComplianceRule(
                rule_id="SEC-001",
                name="No Plain Text Passwords",
                description="Passwords must be encrypted in configuration",
                category="security",
                severity=RuleSeverity.CRITICAL,
                check_type="regex",
                check_pattern=r"password\s+(?!7\s)(?!\$)(?!encrypted)",
                remediation="Use 'service password-encryption' and re-enter passwords"
            ),
            ComplianceRule(
                rule_id="SEC-002",
                name="SSH Version 2 Required",
                description="Only SSH version 2 should be enabled",
                category="security",
                severity=RuleSeverity.HIGH,
                vendor="cisco_ios",
                check_type="regex",
                check_pattern=r"ip ssh version\s+1",
                remediation="Configure 'ip ssh version 2'"
            ),
            ComplianceRule(
                rule_id="SEC-003",
                name="VTY Access Control",
                description="VTY lines must have access control lists",
                category="security",
                severity=RuleSeverity.HIGH,
                vendor="cisco_ios",
                check_type="function",
                check_function="check_vty_acl",
                remediation="Apply access-class to all VTY lines"
            ),
            ComplianceRule(
                rule_id="SEC-004",
                name="SNMP Community Strings",
                description="Default SNMP community strings prohibited",
                category="security",
                severity=RuleSeverity.HIGH,
                check_type="regex",
                check_pattern=r"snmp-server community\s+(public|private)\s",
                remediation="Change SNMP community strings to complex values"
            ),
            
            # Operational Rules
            ComplianceRule(
                rule_id="OPS-001",
                name="NTP Configuration Required",
                description="NTP must be configured for time synchronization",
                category="operational",
                severity=RuleSeverity.MEDIUM,
                check_type="function",
                check_function="check_ntp_configured",
                remediation="Configure NTP servers using 'ntp server' command"
            ),
            ComplianceRule(
                rule_id="OPS-002",
                name="Logging Configuration",
                description="Centralized logging must be configured",
                category="operational",
                severity=RuleSeverity.MEDIUM,
                check_type="function",
                check_function="check_logging_configured",
                remediation="Configure syslog servers using 'logging host' command"
            ),
            ComplianceRule(
                rule_id="OPS-003",
                name="Banner Configuration",
                description="Login banner must be configured",
                category="operational",
                severity=RuleSeverity.LOW,
                check_type="regex",
                check_pattern=r"banner\s+(login|motd)",
                remediation="Configure login banner with legal warning"
            ),
            
            # Best Practice Rules
            ComplianceRule(
                rule_id="BP-001",
                name="Interface Descriptions",
                description="All active interfaces should have descriptions",
                category="operational",
                severity=RuleSeverity.INFO,
                check_type="function",
                check_function="check_interface_descriptions",
                remediation="Add descriptions to all active interfaces"
            ),
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
            
        # Create default rule sets
        self.rule_sets["security"] = ["SEC-001", "SEC-002", "SEC-003", "SEC-004"]
        self.rule_sets["operational"] = ["OPS-001", "OPS-002", "OPS-003", "BP-001"]
        self.rule_sets["all"] = list(self.rules.keys())
        
    def add_rule(self, rule: ComplianceRule) -> None:
        """Add a compliance rule"""
        self.rules[rule.rule_id] = rule
        logger.info(f"Added compliance rule: {rule.rule_id} - {rule.name}")
        
    def load_rules_from_file(self, filepath: str) -> None:
        """Load compliance rules from YAML file"""
        with open(filepath, 'r') as f:
            rules_data = yaml.safe_load(f)
            
        for rule_data in rules_data.get('rules', []):
            rule_data['severity'] = RuleSeverity[rule_data['severity']]
            rule = ComplianceRule(**rule_data)
            self.add_rule(rule)
            
    def validate_config(self, config: str, device: str, 
                       vendor: Optional[str] = None,
                       rule_set: str = "all") -> ComplianceReport:
        """
        Validate configuration against compliance rules
        
        Args:
            config: Configuration text to validate
            device: Device name
            vendor: Vendor type (for vendor-specific rules)
            rule_set: Name of rule set to use
            
        Returns:
            ComplianceReport with validation results
        """
        violations = []
        compliant_count = 0
        non_compliant_count = 0
        warning_count = 0
        
        # Get rules to check
        if rule_set in self.rule_sets:
            rules_to_check = [self.rules[rid] for rid in self.rule_sets[rule_set] 
                            if rid in self.rules and self.rules[rid].enabled]
        else:
            rules_to_check = [r for r in self.rules.values() if r.enabled]
            
        # Filter by vendor if specified
        if vendor:
            rules_to_check = [r for r in rules_to_check 
                            if r.vendor is None or r.vendor == vendor]
            
        # Check each rule
        for rule in rules_to_check:
            try:
                if rule.check_type == "regex":
                    violation = self._check_regex_rule(rule, config)
                elif rule.check_type == "function":
                    violation = self._check_function_rule(rule, config)
                else:
                    logger.warning(f"Unknown check type for rule {rule.rule_id}")
                    continue
                    
                if violation:
                    violations.append(violation)
                    if violation.status == ComplianceStatus.NON_COMPLIANT:
                        non_compliant_count += 1
                    elif violation.status == ComplianceStatus.WARNING:
                        warning_count += 1
                else:
                    compliant_count += 1
                    
            except Exception as e:
                logger.error(f"Error checking rule {rule.rule_id}: {str(e)}")
                violations.append(ComplianceViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    status=ComplianceStatus.ERROR,
                    message=f"Error checking rule: {str(e)}"
                ))
                
        # Calculate overall status and risk score
        overall_status = self._calculate_overall_status(violations)
        risk_score = self._calculate_risk_score(violations)
        
        report = ComplianceReport(
            report_id=f"CR-{device}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            device=device,
            total_rules_checked=len(rules_to_check),
            violations=violations,
            compliant_count=compliant_count,
            non_compliant_count=non_compliant_count,
            warning_count=warning_count,
            overall_status=overall_status,
            risk_score=risk_score
        )
        
        logger.info(f"Compliance check completed for {device}: {overall_status.value}")
        return report
        
    def _check_regex_rule(self, rule: ComplianceRule, config: str) -> Optional[ComplianceViolation]:
        """Check configuration against regex rule"""
        if not rule.check_pattern:
            return None
            
        lines = config.split('\n')
        
        for i, line in enumerate(lines, 1):
            if re.search(rule.check_pattern, line):
                return ComplianceViolation(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    status=ComplianceStatus.NON_COMPLIANT,
                    message=f"Rule violation: {rule.description}",
                    line_number=i,
                    config_line=line.strip(),
                    remediation=rule.remediation
                )
                
        return None
        
    def _check_function_rule(self, rule: ComplianceRule, config: str) -> Optional[ComplianceViolation]:
        """Check configuration using custom function"""
        if not rule.check_function:
            return None
            
        # Map function names to actual functions
        function_map = {
            "check_vty_acl": self._check_vty_acl,
            "check_ntp_configured": self._check_ntp_configured,
            "check_logging_configured": self._check_logging_configured,
            "check_interface_descriptions": self._check_interface_descriptions,
        }
        
        if rule.check_function in function_map:
            return function_map[rule.check_function](rule, config)
        else:
            logger.warning(f"Unknown check function: {rule.check_function}")
            return None
            
    def _check_vty_acl(self, rule: ComplianceRule, config: str) -> Optional[ComplianceViolation]:
        """Check if VTY lines have access control"""
        vty_section = False
        has_access_class = False
        
        for line in config.split('\n'):
            if re.match(r'^line vty', line):
                vty_section = True
                has_access_class = False
            elif vty_section and line.startswith('!'):
                if not has_access_class:
                    return ComplianceViolation(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        status=ComplianceStatus.NON_COMPLIANT,
                        message="VTY lines missing access control",
                        remediation=rule.remediation
                    )
                vty_section = False
            elif vty_section and 'access-class' in line:
                has_access_class = True
                
        return None
        
    def _check_ntp_configured(self, rule: ComplianceRule, config: str) -> Optional[ComplianceViolation]:
        """Check if NTP is configured"""
        ntp_pattern = r'ntp server\s+\S+'
        
        if not re.search(ntp_pattern, config):
            return ComplianceViolation(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                status=ComplianceStatus.NON_COMPLIANT,
                message="NTP servers not configured",
                remediation=rule.remediation
            )
            
        return None
        
    def _check_logging_configured(self, rule: ComplianceRule, config: str) -> Optional[ComplianceViolation]:
        """Check if logging is configured"""
        logging_pattern = r'logging\s+(host|server)\s+\S+'
        
        if not re.search(logging_pattern, config):
            return ComplianceViolation(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                status=ComplianceStatus.WARNING,
                message="Centralized logging not configured",
                remediation=rule.remediation
            )
            
        return None
        
    def _check_interface_descriptions(self, rule: ComplianceRule, config: str) -> Optional[ComplianceViolation]:
        """Check if active interfaces have descriptions"""
        interface_pattern = r'^interface\s+(\S+)'
        interfaces_without_desc = []
        current_interface = None
        has_description = False
        is_shutdown = False
        
        for line in config.split('\n'):
            match = re.match(interface_pattern, line)
            if match:
                # Check previous interface
                if current_interface and not is_shutdown and not has_description:
                    interfaces_without_desc.append(current_interface)
                    
                current_interface = match.group(1)
                has_description = False
                is_shutdown = False
            elif current_interface:
                if 'description' in line:
                    has_description = True
                elif 'shutdown' in line and not 'no shutdown' in line:
                    is_shutdown = True
                    
        # Check last interface
        if current_interface and not is_shutdown and not has_description:
            interfaces_without_desc.append(current_interface)
            
        if interfaces_without_desc:
            return ComplianceViolation(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                severity=rule.severity,
                status=ComplianceStatus.WARNING,
                message=f"Interfaces without descriptions: {', '.join(interfaces_without_desc[:5])}",
                remediation=rule.remediation
            )
            
        return None
        
    def _calculate_overall_status(self, violations: List[ComplianceViolation]) -> ComplianceStatus:
        """Calculate overall compliance status"""
        if not violations:
            return ComplianceStatus.COMPLIANT
            
        # Check for critical violations
        if any(v.severity == RuleSeverity.CRITICAL and 
               v.status == ComplianceStatus.NON_COMPLIANT for v in violations):
            return ComplianceStatus.NON_COMPLIANT
            
        # Check for high severity violations
        if any(v.severity == RuleSeverity.HIGH and 
               v.status == ComplianceStatus.NON_COMPLIANT for v in violations):
            return ComplianceStatus.NON_COMPLIANT
            
        # Only warnings or low severity issues
        if all(v.status == ComplianceStatus.WARNING or 
               v.severity in [RuleSeverity.LOW, RuleSeverity.INFO] for v in violations):
            return ComplianceStatus.WARNING
            
        return ComplianceStatus.NON_COMPLIANT
        
    def _calculate_risk_score(self, violations: List[ComplianceViolation]) -> float:
        """Calculate risk score from 0-100"""
        if not violations:
            return 0.0
            
        # Weight violations by severity
        severity_weights = {
            RuleSeverity.INFO: 1,
            RuleSeverity.LOW: 2,
            RuleSeverity.MEDIUM: 5,
            RuleSeverity.HIGH: 10,
            RuleSeverity.CRITICAL: 20
        }
        
        total_weight = sum(severity_weights[v.severity] for v in violations 
                          if v.status == ComplianceStatus.NON_COMPLIANT)
                          
        # Normalize to 0-100 scale
        # Assume 100 = 5 critical violations
        max_score = severity_weights[RuleSeverity.CRITICAL] * 5
        risk_score = min(100, (total_weight / max_score) * 100)
        
        return round(risk_score, 1)
        
    def generate_remediation_script(self, report: ComplianceReport, 
                                   vendor: str) -> str:
        """Generate remediation script for violations"""
        script_lines = [
            f"! Remediation script for {report.device}",
            f"! Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"! Violations: {report.non_compliant_count}",
            "!",
            "configure terminal"
        ]
        
        # Group remediations by type
        remediations = {}
        for violation in report.violations:
            if violation.remediation and violation.status == ComplianceStatus.NON_COMPLIANT:
                if violation.remediation not in remediations:
                    remediations[violation.remediation] = []
                remediations[violation.remediation].append(violation.rule_name)
                
        # Add remediation commands
        for remediation, rules in remediations.items():
            script_lines.append(f"! Fix for: {', '.join(rules)}")
            script_lines.append(remediation)
            
        script_lines.append("end")
        script_lines.append("write memory")
        
        return '\n'.join(script_lines)
        
    def export_report(self, report: ComplianceReport, format: str = "json") -> str:
        """Export compliance report in specified format"""
        if format == "json":
            report_dict = {
                "report_id": report.report_id,
                "timestamp": report.timestamp.isoformat(),
                "device": report.device,
                "total_rules_checked": report.total_rules_checked,
                "compliant_count": report.compliant_count,
                "non_compliant_count": report.non_compliant_count,
                "warning_count": report.warning_count,
                "overall_status": report.overall_status.value,
                "risk_score": report.risk_score,
                "violations": [
                    {
                        "rule_id": v.rule_id,
                        "rule_name": v.rule_name,
                        "severity": v.severity.name,
                        "status": v.status.value,
                        "message": v.message,
                        "line_number": v.line_number,
                        "config_line": v.config_line,
                        "remediation": v.remediation
                    }
                    for v in report.violations
                ]
            }
            return json.dumps(report_dict, indent=2)
            
        elif format == "text":
            lines = [
                f"COMPLIANCE REPORT - {report.device}",
                "=" * 50,
                f"Report ID: {report.report_id}",
                f"Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
                f"Overall Status: {report.overall_status.value.upper()}",
                f"Risk Score: {report.risk_score}/100",
                "",
                f"Rules Checked: {report.total_rules_checked}",
                f"Compliant: {report.compliant_count}",
                f"Non-Compliant: {report.non_compliant_count}",
                f"Warnings: {report.warning_count}",
                "",
                "VIOLATIONS:",
                "-" * 50
            ]
            
            for v in report.violations:
                lines.extend([
                    f"\n[{v.severity.name}] {v.rule_name} ({v.rule_id})",
                    f"Status: {v.status.value}",
                    f"Message: {v.message}"
                ])
                if v.config_line:
                    lines.append(f"Line {v.line_number}: {v.config_line}")
                if v.remediation:
                    lines.append(f"Remediation: {v.remediation}")
                    
            return '\n'.join(lines)
            
        else:
            raise ValueError(f"Unsupported format: {format}")
