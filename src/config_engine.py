"""
Configuration Engine Module

Provides template-based configuration management with validation,
rollback capabilities, and change tracking.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json
import hashlib
import difflib

from jinja2 import Environment, FileSystemLoader, Template
import yaml
from jsonschema import validate, ValidationError

logger = logging.getLogger(__name__)


@dataclass
class ConfigTemplate:
    """Represents a configuration template"""
    name: str
    vendor: str
    description: str
    template_content: str
    variables_schema: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    validated: bool = False


@dataclass
class ConfigChange:
    """Represents a configuration change"""
    change_id: str
    device: str
    timestamp: datetime
    old_config: str
    new_config: str
    template_used: Optional[str] = None
    variables: Optional[Dict[str, Any]] = None
    applied: bool = False
    rolled_back: bool = False
    error: Optional[str] = None


class ConfigEngine:
    """
    Configuration management engine with templating, validation,
    and rollback capabilities
    """
    
    def __init__(self, template_dir: str = "templates"):
        """Initialize configuration engine"""
        self.template_dir = Path(template_dir)
        self.templates: Dict[str, ConfigTemplate] = {}
        self.changes: Dict[str, ConfigChange] = {}
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Load built-in templates
        self._load_builtin_templates()
        
    def _load_builtin_templates(self):
        """Load built-in configuration templates"""
        # Example built-in templates
        builtin_templates = [
            ConfigTemplate(
                name="cisco_interface",
                vendor="cisco_ios",
                description="Configure Cisco interface",
                template_content="""interface {{ interface_name }}
 description {{ description }}
 ip address {{ ip_address }} {{ subnet_mask }}
 {% if vlan_id %}
 switchport access vlan {{ vlan_id }}
 {% endif %}
 {% if shutdown %}
 shutdown
 {% else %}
 no shutdown
 {% endif %}""",
                variables_schema={
                    "type": "object",
                    "properties": {
                        "interface_name": {"type": "string"},
                        "description": {"type": "string"},
                        "ip_address": {"type": "string", "format": "ipv4"},
                        "subnet_mask": {"type": "string", "format": "ipv4"},
                        "vlan_id": {"type": "integer", "minimum": 1, "maximum": 4094},
                        "shutdown": {"type": "boolean"}
                    },
                    "required": ["interface_name", "description"]
                }
            ),
            ConfigTemplate(
                name="bgp_neighbor",
                vendor="cisco_ios",
                description="Configure BGP neighbor",
                template_content="""router bgp {{ local_as }}
 neighbor {{ neighbor_ip }} remote-as {{ remote_as }}
 neighbor {{ neighbor_ip }} description {{ description }}
 {% if password %}
 neighbor {{ neighbor_ip }} password {{ password }}
 {% endif %}
 {% for network in networks %}
 network {{ network }}
 {% endfor %}""",
                variables_schema={
                    "type": "object",
                    "properties": {
                        "local_as": {"type": "integer"},
                        "neighbor_ip": {"type": "string", "format": "ipv4"},
                        "remote_as": {"type": "integer"},
                        "description": {"type": "string"},
                        "password": {"type": "string"},
                        "networks": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["local_as", "neighbor_ip", "remote_as"]
                }
            )
        ]
        
        for template in builtin_templates:
            self.add_template(template)
            
    def add_template(self, template: ConfigTemplate) -> None:
        """Add a configuration template"""
        # Validate template syntax
        try:
            Template(template.template_content)
            template.validated = True
        except Exception as e:
            logger.error(f"Invalid template syntax for {template.name}: {str(e)}")
            raise ValueError(f"Invalid template syntax: {str(e)}")
            
        self.templates[template.name] = template
        logger.info(f"Added template: {template.name}")
        
    def load_template_file(self, filename: str) -> ConfigTemplate:
        """Load a template from file"""
        filepath = self.template_dir / filename
        
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            
        template = ConfigTemplate(**data)
        self.add_template(template)
        return template
        
    def validate_variables(self, template_name: str, variables: Dict[str, Any]) -> bool:
        """
        Validate variables against template schema
        
        Args:
            template_name: Name of the template
            variables: Variables to validate
            
        Returns:
            True if valid, raises ValidationError if not
        """
        if template_name not in self.templates:
            raise ValueError(f"Template {template_name} not found")
            
        template = self.templates[template_name]
        
        try:
            validate(instance=variables, schema=template.variables_schema)
            return True
        except ValidationError as e:
            logger.error(f"Variable validation failed: {e.message}")
            raise
            
    def generate_config(self, template_name: str, variables: Dict[str, Any]) -> str:
        """
        Generate configuration from template
        
        Args:
            template_name: Name of the template
            variables: Variables to fill template
            
        Returns:
            Generated configuration text
        """
        if template_name not in self.templates:
            raise ValueError(f"Template {template_name} not found")
            
        # Validate variables first
        self.validate_variables(template_name, variables)
        
        template = self.templates[template_name]
        jinja_template = Template(template.template_content)
        
        try:
            config = jinja_template.render(**variables)
            logger.debug(f"Generated config using template {template_name}")
            return config
        except Exception as e:
            logger.error(f"Failed to generate config: {str(e)}")
            raise
            
    def generate_bulk_configs(self, template_name: str, 
                            devices_variables: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
        """
        Generate configurations for multiple devices
        
        Args:
            template_name: Template to use
            devices_variables: Dict mapping device names to their variables
            
        Returns:
            Dict mapping device names to generated configs
        """
        configs = {}
        
        for device, variables in devices_variables.items():
            try:
                config = self.generate_config(template_name, variables)
                configs[device] = config
            except Exception as e:
                logger.error(f"Failed to generate config for {device}: {str(e)}")
                configs[device] = f"ERROR: {str(e)}"
                
        return configs
        
    def create_change(self, device: str, old_config: str, new_config: str,
                     template_name: Optional[str] = None,
                     variables: Optional[Dict[str, Any]] = None) -> ConfigChange:
        """Create a configuration change record"""
        change_id = f"CHG-{device}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        change = ConfigChange(
            change_id=change_id,
            device=device,
            timestamp=datetime.now(),
            old_config=old_config,
            new_config=new_config,
            template_used=template_name,
            variables=variables
        )
        
        self.changes[change_id] = change
        logger.info(f"Created change record: {change_id}")
        return change
        
    def get_config_diff(self, old_config: str, new_config: str) -> str:
        """
        Generate diff between old and new configurations
        
        Returns:
            Unified diff string
        """
        old_lines = old_config.splitlines(keepends=True)
        new_lines = new_config.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            old_lines, new_lines,
            fromfile='current_config',
            tofile='new_config',
            lineterm=''
        )
        
        return ''.join(diff)
        
    def validate_config_syntax(self, config: str, vendor: str) -> Tuple[bool, Optional[str]]:
        """
        Validate configuration syntax for specific vendor
        
        Args:
            config: Configuration to validate
            vendor: Vendor type
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Basic syntax validation rules per vendor
        validation_rules = {
            'cisco_ios': [
                (r'^interface\s+\S+', 'Interface names must follow "interface <name>" format'),
                (r'^ip address\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+', 
                 'IP addresses must be in dotted decimal format'),
            ],
            'juniper_junos': [
                (r'^set\s+', 'Juniper configs should use set commands'),
            ]
        }
        
        # This is a simplified validation - in production, use vendor-specific parsers
        # For now, just check basic structure
        lines = config.strip().split('\n')
        if not lines:
            return False, "Empty configuration"
            
        # Check for common syntax errors
        for line in lines:
            if line.strip() and not line.startswith(' ') and not line.strip().startswith('!'):
                # Top-level command should be recognized
                if not any(line.startswith(cmd) for cmd in ['interface', 'router', 'ip', 'hostname', 
                                                             'access-list', 'vlan', 'line', 'set']):
                    return False, f"Unrecognized command: {line}"
                    
        return True, None
        
    def get_template_by_tags(self, tags: List[str]) -> List[ConfigTemplate]:
        """Get templates matching specific tags"""
        matching_templates = []
        
        for template in self.templates.values():
            if any(tag in template.tags for tag in tags):
                matching_templates.append(template)
                
        return matching_templates
        
    def export_template(self, template_name: str, filepath: str) -> None:
        """Export a template to file"""
        if template_name not in self.templates:
            raise ValueError(f"Template {template_name} not found")
            
        template = self.templates[template_name]
        
        data = {
            'name': template.name,
            'vendor': template.vendor,
            'description': template.description,
            'template_content': template.template_content,
            'variables_schema': template.variables_schema,
            'tags': template.tags,
            'version': template.version
        }
        
        with open(filepath, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)
            
        logger.info(f"Exported template {template_name} to {filepath}")
        
    def get_change_history(self, device: Optional[str] = None) -> List[ConfigChange]:
        """Get configuration change history"""
        changes = list(self.changes.values())
        
        if device:
            changes = [c for c in changes if c.device == device]
            
        # Sort by timestamp, most recent first
        changes.sort(key=lambda x: x.timestamp, reverse=True)
        return changes
        
    def calculate_config_hash(self, config: str) -> str:
        """Calculate hash of configuration for comparison"""
        return hashlib.sha256(config.encode()).hexdigest()
