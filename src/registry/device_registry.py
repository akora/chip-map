#!/usr/bin/env python3
"""
Device Registry Module

Manages the device registry database that tracks devices across multiple scans.
Provides a persistent store for device information and handles device identification
and updates over time.
"""

import datetime
import json
import logging
import os
import shutil
from typing import Dict, List, Optional, Any

logger = logging.getLogger("chip-map.registry")


class DeviceRegistry:
    """
    Device Registry maintains a database of known devices and their properties.
    """

    def __init__(self, registry_file: str = "db/device-registry.json", backup_dir: str = "db/backups"):
        """
        Initialize the device registry.
        
        Args:
            registry_file: Path to the registry JSON file
            backup_dir: Directory to store registry backups
        """
        self.registry_file = registry_file
        self.backup_dir = backup_dir
        self.devices = {}
        self.last_updated = datetime.datetime.now().isoformat()
        self.version = 1
    
    def load(self) -> bool:
        """
        Load the device registry from the JSON file.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        if not os.path.exists(self.registry_file):
            logger.warning(f"Registry file {self.registry_file} does not exist. Creating new registry.")
            self._ensure_dirs()
            return False
        
        try:
            with open(self.registry_file, 'r') as file:
                data = json.load(file)
                
                # Validate registry format
                if "version" not in data or "devices" not in data:
                    logger.error("Invalid registry file format")
                    return False
                
                self.version = data.get("version", 1)
                self.last_updated = data.get("last_updated", datetime.datetime.now().isoformat())
                
                # Build device dictionary with MAC address as key for faster lookups
                self.devices = {}
                for device in data.get("devices", []):
                    if "mac_address" in device:
                        self.devices[device["mac_address"]] = device
                
                logger.info(f"Loaded {len(self.devices)} devices from registry")
                return True
        
        except Exception as e:
            logger.error(f"Failed to load registry: {e}")
            return False
    
    def save(self) -> bool:
        """
        Save the device registry to the JSON file.
        
        Returns:
            True if saved successfully, False otherwise
        """
        self._ensure_dirs()
        
        # Create a backup before saving
        if os.path.exists(self.registry_file):
            self._create_backup()
        
        try:
            # Convert devices dictionary to list for storage
            device_list = list(self.devices.values())
            
            # Update timestamp
            self.last_updated = datetime.datetime.now().isoformat()
            
            data = {
                "version": self.version,
                "last_updated": self.last_updated,
                "devices": device_list
            }
            
            with open(self.registry_file, 'w') as file:
                json.dump(data, file, indent=2)
            
            logger.info(f"Saved {len(self.devices)} devices to registry")
            return True
        
        except Exception as e:
            logger.error(f"Failed to save registry: {e}")
            return False
    
    def find_by_mac(self, mac_address: str) -> Optional[Dict[str, Any]]:
        """
        Find a device by MAC address.
        
        Args:
            mac_address: MAC address to search for
            
        Returns:
            Device dictionary if found, None otherwise
        """
        if not mac_address:
            return None
        
        # Normalize MAC address to lowercase for comparison
        mac_lower = mac_address.lower()
        return self.devices.get(mac_lower)
    
    def find_by_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Find a device by IP address.
        
        Note: This is less reliable than MAC address lookup since IP addresses can change.
        
        Args:
            ip_address: IP address to search for
            
        Returns:
            Device dictionary if found, None otherwise
        """
        if not ip_address:
            return None
        
        for device in self.devices.values():
            if device.get("ip_address") == ip_address:
                return device
        
        return None
    
    def add_device(self, device: Dict[str, Any]) -> bool:
        """
        Add a new device to the registry.
        
        Args:
            device: Device dictionary containing at least a MAC address
            
        Returns:
            True if added successfully, False otherwise
        """
        if not device or "mac_address" not in device:
            logger.error("Cannot add device without MAC address")
            return False
        
        # Normalize MAC address to lowercase
        mac_address = device["mac_address"].lower()
        device["mac_address"] = mac_address
        
        # Set timestamps for new device
        now = datetime.datetime.now().isoformat()
        device["first_seen"] = now
        device["last_seen"] = now
        
        # Initialize scan history
        if "scan_history" not in device:
            device["scan_history"] = []
        
        # Add current scan entry
        scan_entry = {
            "timestamp": now,
            "ip_address": device.get("ip_address", "unknown"),
            "status": "online"
        }
        device["scan_history"].append(scan_entry)
        
        # Add to registry
        self.devices[mac_address] = device
        logger.info(f"Added new device: {mac_address} ({device.get('device_type', 'unknown')})")
        return True
    
    def update_device(self, device_info: Dict[str, Any]) -> bool:
        """
        Update a device in the registry.
        
        Args:
            device_info: Updated device information
            
        Returns:
            True if updated successfully, False if device not found
        """
        mac_address = device_info.get("mac_address")
        if not mac_address:
            logger.warning("Cannot update device without MAC address")
            return False
        
        # Standardize MAC address format
        mac_address = self._normalize_mac(mac_address)
        
        if mac_address not in self.devices:
            logger.warning(f"Device not found for update: {mac_address}")
            return False
        
        device = self.devices[mac_address]
        
        # Update base device properties
        for key in ["hostname", "ip_address", "device_type"]:
            if key in device_info and device_info[key]:
                device[key] = device_info[key]
        
        # Update OS information if present
        if "os" in device_info and device_info["os"]:
            device["os"] = device_info["os"]
        
        # Update last seen timestamp
        device["last_seen"] = datetime.datetime.now().isoformat()
        
        # Update chips if present - this is a complete replacement of chip data
        if "chips" in device_info and device_info["chips"]:
            device["chips"] = device_info["chips"]
        
        logger.debug(f"Updated device: {mac_address}")
        return True
    
    def mark_device_offline(self, mac_address: str) -> bool:
        """
        Mark a device as offline in the registry.
        
        Args:
            mac_address: MAC address of the device
            
        Returns:
            True if marked successfully, False if device not found
        """
        # Normalize MAC address to lowercase
        mac_lower = mac_address.lower()
        
        existing_device = self.devices.get(mac_lower)
        
        if not existing_device:
            logger.warning(f"Device not found to mark offline: {mac_lower}")
            return False
        
        # Update last_seen timestamp (keep the old one)
        now = datetime.datetime.now().isoformat()
        
        # Add scan history entry
        if "scan_history" not in existing_device:
            existing_device["scan_history"] = []
        
        scan_entry = {
            "timestamp": now,
            "ip_address": existing_device.get("ip_address", "unknown"),
            "status": "offline"
        }
        existing_device["scan_history"].append(scan_entry)
        
        logger.info(f"Marked device offline: {mac_lower}")
        return True
    
    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices in the registry.
        
        Returns:
            List of all device dictionaries
        """
        return list(self.devices.values())
    
    def get_devices_by_type(self, device_type: str) -> List[Dict[str, Any]]:
        """
        Get devices of a specific type.
        
        Args:
            device_type: Device type to filter by
            
        Returns:
            List of matching device dictionaries
        """
        return [d for d in self.devices.values() if d.get("device_type") == device_type]
    
    def _merge_chips(self, device: Dict[str, Any], new_chips: List[Dict[str, Any]]) -> None:
        """
        Merge new chip information with existing chips.
        
        Args:
            device: Existing device dictionary
            new_chips: List of new chips to merge
        """
        if "chips" not in device:
            device["chips"] = []
        
        existing_chips = device["chips"]
        
        for new_chip in new_chips:
            # Check if chip exists by manufacturer and model
            existing = next(
                (c for c in existing_chips 
                 if c.get("manufacturer") == new_chip.get("manufacturer") and
                    c.get("model") == new_chip.get("model")),
                None
            )
            
            if existing:
                # Update existing chip information
                for key, value in new_chip.items():
                    if value:  # Only update non-empty values
                        # For capabilities and links, merge instead of replace
                        if key in ["capabilities", "links"] and isinstance(value, list):
                            if key not in existing:
                                existing[key] = []
                            
                            # Add new items that don't already exist
                            for item in value:
                                if item not in existing[key]:
                                    existing[key].append(item)
                        else:
                            existing[key] = value
            else:
                # Add new chip
                device["chips"].append(new_chip)
    
    def _ensure_dirs(self) -> None:
        """Ensure registry and backup directories exist."""
        os.makedirs(os.path.dirname(self.registry_file), exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def _create_backup(self) -> None:
        """Create a backup of the current registry file."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            backup_file = os.path.join(self.backup_dir, f"device-registry-{timestamp}.json")
            
            shutil.copy2(self.registry_file, backup_file)
            logger.debug(f"Created registry backup: {backup_file}")
            
            # Prune old backups if needed
            self._prune_backups()
        
        except Exception as e:
            logger.error(f"Failed to create registry backup: {e}")
    
    def _prune_backups(self, max_backups: int = 5) -> None:
        """
        Prune old backups, keeping only the most recent ones.
        
        Args:
            max_backups: Maximum number of backups to keep
        """
        try:
            backup_files = [os.path.join(self.backup_dir, f) for f in os.listdir(self.backup_dir)
                           if f.startswith("device-registry-") and f.endswith(".json")]
            
            if len(backup_files) <= max_backups:
                return
            
            # Sort by modification time (oldest first)
            backup_files.sort(key=lambda f: os.path.getmtime(f))
            
            # Remove oldest backups
            files_to_remove = backup_files[:-max_backups]
            for file in files_to_remove:
                os.remove(file)
                logger.debug(f"Pruned old registry backup: {file}")
        
        except Exception as e:
            logger.error(f"Failed to prune registry backups: {e}")

    def _normalize_mac(self, mac_address: str) -> str:
        """
        Normalize MAC address to lowercase and standard format.
        
        Args:
            mac_address: MAC address to normalize
            
        Returns:
            Normalized MAC address
        """
        return mac_address.lower()


if __name__ == "__main__":
    # Example usage when run directly
    logging.basicConfig(level=logging.INFO)
    
    # Create registry
    registry = DeviceRegistry()
    
    # Add example device
    example_device = {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ip_address": "192.168.0.100",
        "hostname": "example.local",
        "device_type": "example"
    }
    
    registry.add_device(example_device)
    
    # List devices
    devices = registry.get_all_devices()
    for device in devices:
        print(f"Device: {device.get('hostname', device.get('mac_address'))}")
        print(f"  MAC: {device.get('mac_address')}")
        print(f"  IP: {device.get('ip_address')}")
        print(f"  Type: {device.get('device_type')}")
        print()
