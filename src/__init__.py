"""
Network Configuration Automator - Core Module

This module provides the main entry point for the network configuration
automation system.
"""

__version__ = "1.0.0"
__author__ = "Network Automation Team"

# Import main components for easier access
from .device_manager import DeviceManager
from .config_engine import ConfigEngine
from .impact_analyzer import BusinessImpactAnalyzer
from .compliance import ComplianceValidator

__all__ = [
    "DeviceManager",
    "ConfigEngine", 
    "BusinessImpactAnalyzer",
    "ComplianceValidator"
]
