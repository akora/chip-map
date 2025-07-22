#!/usr/bin/env python3
"""
Chip-Map - Discover and map chips in home devices

This tool auto-discovers, lists, and gathers information on chips used in computers,
network devices, and other connected hardware in a home environment.
"""

import argparse
import datetime
import logging
import os
import sys
import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("chip-map")

# Import project modules
try:
    from src.discovery import network_scanner
    from src.registry import device_registry
    from src.scanners import host_scanner
    from src.output import markdown_generator
except ImportError as e:
    logger.error(f"Failed to import project modules: {e}")
    logger.error("Make sure you're running from the project root directory")
    sys.exit(1)


def load_config(config_path="config/config.yaml"):
    """Load configuration from the specified YAML file."""
    try:
        with open(config_path, 'r') as file:
            return yaml.safe_load(file)
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        return {}


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Discover and map chips in home devices"
    )
    parser.add_argument(
        "--config", 
        default="config/config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--scan-network", 
        action="store_true",
        help="Scan the network for devices"
    )
    parser.add_argument(
        "--scan-host", 
        action="store_true",
        help="Scan the host machine"
    )
    parser.add_argument(
        "--ip-range",
        help="IP range to scan (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Enable verbose output"
    )
    return parser.parse_args()


def run_scan(config, args):
    """Run the chip discovery scan based on configuration and arguments."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    logger.info(f"Starting chip-map scan at {timestamp}")
    
    # Initialize device registry
    registry = device_registry.DeviceRegistry(config.get("database", {}).get("registry_file", "db/device-registry.json"))
    registry.load()
    
    scan_results = {
        "timestamp": timestamp,
        "new_devices": [],
        "updated_devices": [],
        "offline_devices": []
    }
    
    # Scan host machine if enabled
    if args.scan_host or config.get("scanning", {}).get("scan_host", True):
        logger.info("Scanning host machine...")
        try:
            host_info = host_scanner.scan_host()
            if host_info:
                registry.update_device(host_info)
                scan_results["updated_devices"].append(host_info)
        except Exception as e:
            logger.error(f"Error scanning host machine: {e}")
    
    # Scan network if enabled
    if args.scan_network or config.get("scanning", {}).get("scan_network", True):
        ip_range = args.ip_range or config.get("network", {}).get("ip_range", "192.168.0.0/24")
        use_sudo = config.get("network", {}).get("use_sudo", True)
        logger.info(f"Scanning network: {ip_range}...")
        try:
            network_devices = network_scanner.discover_devices(ip_range, use_sudo=use_sudo)
            for device in network_devices:
                # Process each discovered device
                existing = registry.find_by_mac(device.get("mac_address"))
                
                if existing:
                    # Update existing device if needed
                    registry.update_device(device)
                    scan_results["updated_devices"].append(device)
                else:
                    # Register new device
                    registry.add_device(device)
                    scan_results["new_devices"].append(device)
        except Exception as e:
            logger.error(f"Error scanning network: {e}")
    
    # Save updated registry
    registry.save()
    
    # Generate scan report and device files
    logger.info("Generating output files...")
    try:
        markdown_generator.generate_scan_report(scan_results, "scans", timestamp)
        
        for device in scan_results["new_devices"]:
            markdown_generator.generate_device_file(device, "devices")
        
        for device in scan_results["updated_devices"]:
            markdown_generator.update_device_file(device, "devices")
    except Exception as e:
        logger.error(f"Error generating output files: {e}")
    
    logger.info("Scan completed")
    return scan_results


def main():
    """Main entry point for the chip-map application."""
    args = parse_arguments()
    
    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args.config)
    
    # Run the scan
    run_scan(config, args)


if __name__ == "__main__":
    main()
