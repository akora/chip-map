#!/usr/bin/env python3
"""
Network Scanner Module

Discovers devices on the network using nmap and arp, identifies their MAC addresses,
and attempts to determine device types based on open ports and other signatures.
"""

import logging
import re
import subprocess
import sys
import socket
from typing import Dict, List, Optional

logger = logging.getLogger("chip-map.discovery")

# Common device signatures based on open ports
DEVICE_SIGNATURES = {
    "22": ["ssh", "linux", "raspberry_pi", "nas"],
    "80": ["http", "web_server", "router", "nas"],
    "443": ["https", "web_server", "router", "nas"],
    "445": ["smb", "nas", "windows"],
    "5000": ["synology", "nas"],
    "8080": ["http_alt", "web_server"],
    "8443": ["https_alt", "web_server"],
}

# MAC address prefixes for known manufacturers
MAC_PREFIXES = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading Ltd",
    "e4:5f:01": "Raspberry Pi Trading Ltd",
    "00:11:32": "Synology Inc.",
    "00:c0:a8": "GVC Corporation",  # These are examples, add more as needed
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "00:1e:c9": "Dell Inc.",
    "00:15:5d": "Microsoft",
    "00:21:86": "USI",  # Apple devices often use USI chips
    "a8:86:dd": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
}


def check_dependencies():
    """Check if required system dependencies (nmap, arp) are installed."""
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("nmap is not installed or not in PATH. Please install nmap to use network scanning features.")
        return False
    
    try:
        if sys.platform == "darwin":  # macOS
            subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        else:  # Linux
            subprocess.run(["arp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        logger.error("arp command is not available. Network device discovery may be limited.")
        return False
    
    return True


def scan_arp_table() -> List[Dict]:
    """
    Scan the ARP table to find devices that are known to the host machine
    but might not respond to ping scans.
    
    Returns:
        List of devices found in the ARP table with their MAC and IP addresses
    """
    devices = []
    
    try:
        # Get the ARP table
        arp_cmd = ["arp", "-a"]
        logger.debug(f"Running command: {' '.join(arp_cmd)}")
        arp_output = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, check=True).stdout
        
        # Parse the output to extract IP and MAC addresses
        # Pattern varies slightly between macOS and Linux
        if sys.platform == "darwin":  # macOS
            # Example macOS output:
            # ? (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
            pattern = r"\? \((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on (\w+)"
        else:  # Linux-like
            # Example Linux output:
            # 192.168.0.1 (192.168.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
            pattern = r"(\d+\.\d+\.\d+\.\d+).+at ([0-9a-f:]+)"
        
        matches = re.finditer(pattern, arp_output, re.IGNORECASE)
        
        for match in matches:
            ip_address = match.group(1)
            mac_address = match.group(2).lower()
            
            # Skip incomplete entries
            if "incomplete" in mac_address or "<incomplete>" in mac_address:
                continue
                
            # Skip localhost
            if ip_address.startswith("127."):
                continue
                
            # Get hostname if possible
            hostname = get_hostname(ip_address)
            
            # Determine vendor from MAC prefix
            vendor = "Unknown"
            for prefix, known_vendor in MAC_PREFIXES.items():
                if mac_address.startswith(prefix.lower().replace(':', '')):
                    vendor = known_vendor
                    break
            
            device = {
                "ip_address": ip_address,
                "mac_address": mac_address,
                "hostname": hostname,
                "vendor": vendor,
                "source": "arp_table"
            }
            
            devices.append(device)
            logger.info(f"Found device in ARP table: {ip_address} ({mac_address})")
    
    except subprocess.SubprocessError as e:
        logger.error(f"Error scanning ARP table: {e}")
    
    return devices

def scan_common_ips(ip_range: str) -> List[Dict]:
    """
    Scan common IP addresses directly (e.g., routers, gateways)
    that might not respond to regular scans.
    
    Args:
        ip_range: IP range in CIDR notation (e.g., 192.168.0.0/24)
        
    Returns:
        List of devices found at common IP addresses
    """
    devices = []
    
    # Extract network prefix from CIDR
    try:
        network_prefix = ip_range.split("/")[0].rsplit(".", 1)[0]
        
        # Common IPs to check directly (router, gateway, etc.)
        common_ips = [
            f"{network_prefix}.1",   # Common router/gateway
            f"{network_prefix}.254", # Alternative router/gateway
        ]
        
        for ip in common_ips:
            # Try to ping the IP first
            try:
                # Use ping with a short timeout
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
                subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             check=True, timeout=2)
                
                # If ping succeeds, try to get MAC and other info
                mac_info = get_mac_address(ip)
                
                if mac_info:
                    # Get hostname if possible
                    hostname = get_hostname(ip)
                    
                    # Try to determine device type
                    open_ports = scan_ports(ip)
                    device_type = determine_device_type(
                        mac_info.get("mac_address", ""),
                        open_ports
                    )
                    
                    device = {
                        "ip_address": ip,
                        "mac_address": mac_info.get("mac_address", ""),
                        "hostname": hostname,
                        "vendor": mac_info.get("vendor", "Unknown"),
                        "device_type": device_type,
                        "open_ports": open_ports,
                        "source": "direct_scan"
                    }
                    
                    devices.append(device)
                    logger.info(f"Found device at common IP: {ip} ({device_type})")
            
            except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                logger.debug(f"Could not reach common IP: {ip}")
    
    except Exception as e:
        logger.error(f"Error scanning common IPs: {e}")
    
    return devices

def get_hostname(ip_address: str) -> str:
    """
    Attempt to resolve the hostname for an IP address.
    
    Args:
        ip_address: IP address to resolve
        
    Returns:
        Hostname if resolved, empty string otherwise
    """
    try:
        hostname = socket.getfqdn(ip_address)
        if hostname != ip_address:  # If resolution was successful
            return hostname
    except (socket.error, socket.herror, socket.gaierror):
        pass
    
    # If DNS resolution fails, try nmblookup for NetBIOS names (if available)
    try:
        nmb_cmd = ["nmblookup", "-A", ip_address]
        nmb_output = subprocess.run(nmb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=2).stdout
        
        # Look for NetBIOS name
        match = re.search(r"<00> - <GROUP> B <ACTIVE>\s+(\S+)", nmb_output)
        if match:
            return match.group(1)
    except (subprocess.SubprocessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    return ""

def discover_devices(ip_range: str, use_sudo: bool = True) -> List[Dict]:
    """
    Discover devices on the network using multiple discovery methods.
    
    Args:
        ip_range: IP range to scan (e.g., "192.168.0.0/24")
        use_sudo: Whether to use sudo for more comprehensive scanning
        
    Returns:
        List of discovered devices with their information
    """
    if not check_dependencies():
        return []
    
    logger.info(f"Scanning network range: {ip_range}")
    all_devices = {}  # Using a dict keyed by MAC to avoid duplicates
    
    # Method 1: Basic nmap scan
    logger.info("Running nmap scan...")
    nmap_devices = basic_nmap_scan(ip_range)
    for device in nmap_devices:
        if "mac_address" in device and device["mac_address"]:
            all_devices[device["mac_address"]] = device
    
    # Method 2: Scan ARP table
    logger.info("Scanning ARP table...")
    arp_devices = scan_arp_table()
    for device in arp_devices:
        if "mac_address" in device and device["mac_address"]:
            # Update existing or add new
            if device["mac_address"] in all_devices:
                # Merge info if this device was already found
                all_devices[device["mac_address"]].update({
                    k: v for k, v in device.items() 
                    if k not in all_devices[device["mac_address"]] or not all_devices[device["mac_address"]][k]
                })
            else:
                all_devices[device["mac_address"]] = device
    
    # Method 3: Scan common IPs directly
    logger.info("Checking common IP addresses...")
    common_ip_devices = scan_common_ips(ip_range)
    for device in common_ip_devices:
        if "mac_address" in device and device["mac_address"]:
            # Update existing or add new
            if device["mac_address"] in all_devices:
                # Merge info if this device was already found
                all_devices[device["mac_address"]].update({
                    k: v for k, v in device.items() 
                    if k not in all_devices[device["mac_address"]] or not all_devices[device["mac_address"]][k]
                })
            else:
                all_devices[device["mac_address"]] = device
    
    # Enhance device information with OS detection if sudo is available
    if use_sudo:
        logger.info("Performing OS detection for discovered devices...")
        for mac, device in all_devices.items():
            if "os" not in device or not device["os"]:
                ip = device.get("ip_address")
                if ip:
                    try:
                        # OS detection requires sudo
                        logger.debug(f"Attempting OS detection for {ip}...")
                        os_cmd = ["sudo", "nmap", "-O", "--osscan-limit", "-T4", ip]
                        os_output = subprocess.run(os_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                text=True, timeout=30).stdout
                        
                        # Extract OS information
                        os_pattern = r"OS details: (.*?)(?=\n\n|\n[A-Z]|\Z)"
                        os_match = re.search(os_pattern, os_output)
                        if os_match:
                            os_info = os_match.group(1).strip()
                            device["os"] = os_info
                            logger.debug(f"Detected OS for {ip}: {os_info}")
                    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                        logger.debug(f"OS detection failed for {ip}: {e}")
    
    # Convert the dict back to a list
    devices = list(all_devices.values())
    
    # Ensure all devices have a device_type
    for device in devices:
        if "device_type" not in device or not device["device_type"]:
            device["device_type"] = determine_device_type(
                device.get("mac_address", ""),
                device.get("open_ports", []),
                device.get("os")
            )
    
    logger.info(f"Discovered {len(devices)} devices in total")
    return devices

def basic_nmap_scan(ip_range: str) -> List[Dict]:
    """
    Perform a basic nmap scan to discover devices.
    
    Args:
        ip_range: IP range to scan
        
    Returns:
        List of discovered devices with their information
    """
    devices = []
    
    try:
        # Basic ping scan to discover devices
        logger.info("Running simple ping scan to discover devices...")
        nmap_cmd = ["nmap", "-sn", ip_range]
        logger.debug(f"Running command: {' '.join(nmap_cmd)}")
        
        nmap_output = subprocess.run(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, check=True).stdout
        
        # Extract IP addresses from nmap output
        ip_pattern = r"Nmap scan report for (?:([^\s]+) )?\((\d+\.\d+\.\d+\.\d+)\)"
        ip_matches = re.finditer(ip_pattern, nmap_output)
        
        discovered_ips = {}
        for match in ip_matches:
            hostname = match.group(1) or ""
            ip_address = match.group(2)
            discovered_ips[ip_address] = hostname
            
        # For each discovered IP, get more detailed information
        for ip_address, hostname in discovered_ips.items():
            # Get MAC address using our helper function
            mac_info = get_mac_address(ip_address)
            
            if not mac_info:
                logger.debug(f"Could not determine MAC address for {ip_address}")
                continue
            
            # Scan ports to determine device type
            open_ports = scan_ports(ip_address)
            
            # Determine device type
            device_type = determine_device_type(mac_info.get("mac_address", ""), open_ports)
            
            device = {
                "ip_address": ip_address,
                "hostname": hostname,
                "mac_address": mac_info.get("mac_address", ""),
                "vendor": mac_info.get("vendor", "Unknown"),
                "open_ports": open_ports,
                "device_type": device_type,
                "source": "nmap_scan",
                "last_seen": None,  # Will be set by the registry
                "chips": []  # Will be populated by device-specific scanners
            }
            
            devices.append(device)
            logger.info(f"Discovered device: {hostname or ip_address} ({device_type})")
        
    except subprocess.SubprocessError as e:
        logger.error(f"Error running nmap scan: {e}")
    
    return devices

def scan_ports(ip_address: str, ports: List[int] = None, use_sudo: bool = False) -> List[int]:
    """
    Scan specific ports on a device to help identify device type.
    
    Args:
        ip_address: IP address to scan
        ports: List of ports to scan, defaults to common ports
        use_sudo: Whether to use sudo for more comprehensive scanning
        
    Returns:
        List of open ports
    """
    if ports is None:
        # Common ports that help identify device types
        ports = [22, 80, 443, 445, 515, 631, 5000, 8080, 8443, 9000]
    
    open_ports = []
    ports_str = ",".join(map(str, ports))
    
    try:
        # Basic TCP connect scan, which doesn't require sudo
        nmap_cmd = ["nmap", "-p", ports_str, "-T4", "--open", ip_address]
        
        logger.debug(f"Scanning ports on {ip_address}: {' '.join(nmap_cmd)}")
        
        nmap_output = subprocess.run(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, timeout=30).stdout
        
        # Parse output to get open ports
        port_pattern = r"(\d+)/tcp\s+open"
        port_matches = re.finditer(port_pattern, nmap_output)
        
        open_ports = [int(match.group(1)) for match in port_matches]
        
        # If we have sudo and no ports were found, try again with a SYN scan
        if use_sudo and not open_ports:
            try:
                sudo_cmd = ["sudo", "nmap", "-sS", "-p", ports_str, "-T4", "--open", ip_address]
                sudo_output = subprocess.run(sudo_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True, timeout=30).stdout
                
                port_matches = re.finditer(port_pattern, sudo_output)
                open_ports = [int(match.group(1)) for match in port_matches]
            except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
                logger.debug(f"SYN scan failed for {ip_address}: {e}")
    
    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
        logger.debug(f"Error scanning ports on {ip_address}: {e}")
    
    return open_ports

def get_mac_address(ip_address: str) -> Optional[Dict[str, str]]:
    """
    Get MAC address for a given IP address using the arp command.
    
    Args:
        ip_address: IP address to lookup
        
    Returns:
        Dictionary with mac_address and vendor if found, None otherwise
    """
    try:
        if sys.platform == "darwin":  # macOS
            arp_cmd = ["arp", "-n", ip_address]
        else:  # Linux
            arp_cmd = ["arp", "-a", ip_address]
        
        logger.debug(f"Running command: {' '.join(arp_cmd)}")
        arp_output = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, check=True).stdout
        
        # Extract MAC address from arp output
        mac_pattern = r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}"
        mac_match = re.search(mac_pattern, arp_output)
        
        if not mac_match:
            return None
        
        mac_address = mac_match.group(0).lower()
        
        # Check if vendor can be determined from MAC prefix
        vendor = "Unknown"
        for prefix, mfr in MAC_PREFIXES.items():
            if mac_address.startswith(prefix.lower().replace(':', '')):
                vendor = mfr
                break
        
        return {
            "mac_address": mac_address,
            "vendor": vendor
        }
    
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"Error running arp command: {e}")
        return None

def determine_device_type(mac_address: str, open_ports: List[int], os_info: str = None) -> str:
    """
    Determine device type based on MAC address prefix, open ports, and OS information.
    
    Args:
        mac_address: MAC address of the device
        open_ports: List of open ports
        os_info: OS information from nmap (if available)
        
    Returns:
        Device type string
    """
    # Normalize MAC address
    mac_address = mac_address.lower()
    
    # Check if this is a Raspberry Pi based on MAC prefix
    for prefix, vendor in MAC_PREFIXES.items():
        if mac_address.startswith(prefix.lower().replace(':', '')):
            if "Raspberry Pi" in vendor:
                return "raspberry_pi"
            elif "Synology" in vendor:
                return "synology_nas"
            elif "Apple" in vendor:
                # Determine Apple device type from ports and OS
                if 548 in open_ports or 88 in open_ports:  # AFP or Kerberos
                    return "mac"
                elif 62078 in open_ports:  # iPhone sync
                    return "iphone"
                elif 8080 in open_ports or 8443 in open_ports:  # Web server
                    return "apple_tv"
                else:
                    return "apple_device"
                
    # Check OS information if available
    if os_info:
        os_info = os_info.lower()
        if "linux" in os_info and "raspberry" in os_info:
            return "raspberry_pi"
        elif "synology" in os_info:
            return "synology_nas"
        elif "linux" in os_info:
            return "linux_server"
        elif "windows" in os_info:
            return "windows"
        elif "apple" in os_info or "mac" in os_info:
            return "mac"
        elif "android" in os_info:
            return "android"
        elif "ios" in os_info:
            return "ios_device"
            
    # Determine device type based on open ports
    if 22 in open_ports:  # SSH
        if 445 in open_ports or 139 in open_ports:  # SMB
            return "nas"
        else:
            return "linux_server"
    
    if 80 in open_ports or 443 in open_ports:  # HTTP/HTTPS
        if 5000 in open_ports:  # Synology DSM
            return "synology_nas"
        else:
            return "web_server"
    
    if 5353 in open_ports:  # mDNS
        return "iot_device"
        
    if 515 in open_ports or 631 in open_ports:  # Printing
        return "printer"
    
    # Default to generic network device if type can't be determined
    return "network_device"

if __name__ == "__main__":
    # Example usage when run directly
    logging.basicConfig(level=logging.INFO)
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        ip_range = sys.argv[1]
    else:
        ip_range = "192.168.0.0/24"  # Default range
    
    # Discover devices
    print(f"Scanning network range: {ip_range}")
    devices = discover_devices(ip_range)
    
    # Display results
    print(f"\nDiscovered {len(devices)} devices:")
    for device in devices:
        print(f"\n{device['hostname'] or device['ip_address']} ({device['device_type']})")
        print(f"  IP: {device['ip_address']}")
        print(f"  MAC: {device['mac_address']} ({device['vendor']})")
        if device.get('open_ports'):
            print(f"  Open ports: {', '.join(map(str, device['open_ports']))}")
        if device.get('os'):
            print(f"  OS: {device['os']}")
