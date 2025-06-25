"""
Device Manager Module

Handles multi-vendor device connections and abstracts vendor-specific
implementations.
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

from netmiko import ConnectHandler
from napalm import get_network_driver
import yaml

logger = logging.getLogger(__name__)


@dataclass
class Device:
    """Represents a network device"""
    hostname: str
    ip_address: str
    vendor: str
    device_type: str
    username: str
    password: str
    port: int = 22
    enable_password: Optional[str] = None
    snmp_community: Optional[str] = None
    location: Optional[str] = None
    role: Optional[str] = None
    business_criticality: str = "medium"  # low, medium, high, critical


class DeviceManager:
    """
    Manages network device connections and operations across multiple vendors
    """
    
    # Mapping of vendor to netmiko device types
    VENDOR_MAPPING = {
        'cisco_ios': 'cisco_ios',
        'cisco_xe': 'cisco_xe', 
        'cisco_nxos': 'cisco_nxos',
        'juniper': 'juniper_junos',
        'arista': 'arista_eos',
        'fortinet': 'fortinet',
        'paloalto': 'paloalto_panos'
    }
    
    def __init__(self, inventory_file: Optional[str] = None):
        """Initialize device manager with optional inventory file"""
        self.devices: Dict[str, Device] = {}
        self.connections: Dict[str, Any] = {}
        
        if inventory_file:
            self.load_inventory(inventory_file)
    
    def load_inventory(self, inventory_file: str) -> None:
        """Load device inventory from YAML file"""
        try:
            with open(inventory_file, 'r') as f:
                inventory = yaml.safe_load(f)
                
            for device_data in inventory.get('devices', []):
                device = Device(**device_data)
                self.add_device(device)
                
            logger.info(f"Loaded {len(self.devices)} devices from inventory")
            
        except Exception as e:
            logger.error(f"Failed to load inventory: {str(e)}")
            raise
    
    def add_device(self, device: Device) -> None:
        """Add a device to the manager"""
        self.devices[device.hostname] = device
        logger.debug(f"Added device: {device.hostname}")
    
    def connect(self, hostname: str, use_napalm: bool = False) -> Any:
        """
        Establish connection to a device
        
        Args:
            hostname: Device hostname
            use_napalm: Use NAPALM driver instead of Netmiko
            
        Returns:
            Connection object (Netmiko or NAPALM)
        """
        if hostname not in self.devices:
            raise ValueError(f"Device {hostname} not found in inventory")
            
        device = self.devices[hostname]
        
        try:
            if use_napalm:
                driver = get_network_driver(device.vendor)
                connection = driver(
                    hostname=device.ip_address,
                    username=device.username,
                    password=device.password,
                    optional_args={'port': device.port}
                )
                connection.open()
            else:
                connection = ConnectHandler(
                    device_type=self.VENDOR_MAPPING.get(device.vendor),
                    host=device.ip_address,
                    username=device.username,
                    password=device.password,
                    port=device.port,
                    secret=device.enable_password
                )
                
            self.connections[hostname] = connection
            logger.info(f"Connected to {hostname}")
            return connection
            
        except Exception as e:
            logger.error(f"Failed to connect to {hostname}: {str(e)}")
            raise
    
    def disconnect(self, hostname: str) -> None:
        """Disconnect from a device"""
        if hostname in self.connections:
            try:
                connection = self.connections[hostname]
                if hasattr(connection, 'close'):
                    connection.close()
                else:
                    connection.disconnect()
                    
                del self.connections[hostname]
                logger.info(f"Disconnected from {hostname}")
                
            except Exception as e:
                logger.error(f"Error disconnecting from {hostname}: {str(e)}")
    
    def execute_command(self, hostname: str, command: str) -> str:
        """
        Execute a command on a device
        
        Args:
            hostname: Device hostname
            command: Command to execute
            
        Returns:
            Command output
        """
        if hostname not in self.connections:
            self.connect(hostname)
            
        connection = self.connections[hostname]
        
        try:
            if hasattr(connection, 'send_command'):
                output = connection.send_command(command)
            else:
                output = connection.cli([command])[command]
                
            logger.debug(f"Executed command on {hostname}: {command}")
            return output
            
        except Exception as e:
            logger.error(f"Failed to execute command on {hostname}: {str(e)}")
            raise
    
    def execute_commands_parallel(self, commands_map: Dict[str, List[str]], 
                                 max_workers: int = 10) -> Dict[str, Dict[str, str]]:
        """
        Execute commands on multiple devices in parallel
        
        Args:
            commands_map: Dict mapping hostname to list of commands
            max_workers: Maximum number of parallel workers
            
        Returns:
            Dict mapping hostname to command outputs
        """
        results = {}
        
        def execute_on_device(hostname: str, commands: List[str]) -> tuple:
            device_results = {}
            try:
                self.connect(hostname)
                for command in commands:
                    output = self.execute_command(hostname, command)
                    device_results[command] = output
                return hostname, device_results
            except Exception as e:
                logger.error(f"Error executing on {hostname}: {str(e)}")
                return hostname, {"error": str(e)}
            finally:
                self.disconnect(hostname)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(execute_on_device, hostname, commands): hostname
                for hostname, commands in commands_map.items()
            }
            
            for future in as_completed(futures):
                hostname, device_results = future.result()
                results[hostname] = device_results
                
        return results
    
    def get_device_info(self, hostname: str) -> Dict[str, Any]:
        """Get device information and status"""
        if hostname not in self.devices:
            raise ValueError(f"Device {hostname} not found")
            
        device = self.devices[hostname]
        
        # Try to get live data if possible
        info = {
            'hostname': device.hostname,
            'ip_address': device.ip_address,
            'vendor': device.vendor,
            'location': device.location,
            'role': device.role,
            'business_criticality': device.business_criticality,
            'status': 'unknown'
        }
        
        try:
            self.connect(hostname, use_napalm=True)
            connection = self.connections[hostname]
            
            # Get device facts using NAPALM
            facts = connection.get_facts()
            info.update({
                'model': facts.get('model'),
                'serial_number': facts.get('serial_number'),
                'os_version': facts.get('os_version'),
                'uptime': facts.get('uptime'),
                'status': 'online'
            })
            
            self.disconnect(hostname)
            
        except Exception as e:
            logger.warning(f"Could not get live data for {hostname}: {str(e)}")
            info['status'] = 'offline'
            
        return info
    
    def get_devices_by_criteria(self, **criteria) -> List[Device]:
        """
        Get devices matching specific criteria
        
        Example:
            get_devices_by_criteria(vendor='cisco_ios', role='core')
        """
        matching_devices = []
        
        for device in self.devices.values():
            match = True
            for key, value in criteria.items():
                if hasattr(device, key):
                    if getattr(device, key) != value:
                        match = False
                        break
                        
            if match:
                matching_devices.append(device)
                
        return matching_devices
    
    def backup_configs(self, hostnames: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Backup configurations for specified devices
        
        Args:
            hostnames: List of hostnames to backup (None for all)
            
        Returns:
            Dict mapping hostname to configuration
        """
        if hostnames is None:
            hostnames = list(self.devices.keys())
            
        configs = {}
        
        for hostname in hostnames:
            try:
                self.connect(hostname, use_napalm=True)
                connection = self.connections[hostname]
                
                config = connection.get_config()
                configs[hostname] = config['running']
                
                self.disconnect(hostname)
                logger.info(f"Backed up configuration for {hostname}")
                
            except Exception as e:
                logger.error(f"Failed to backup {hostname}: {str(e)}")
                configs[hostname] = f"ERROR: {str(e)}"
                
        return configs
