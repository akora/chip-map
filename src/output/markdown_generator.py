#!/usr/bin/env python3
"""
Markdown Generator Module

Generates Markdown files for devices, chips, and scan reports.
Designed to produce Obsidian-compatible outputs with consistent formatting.
"""

import datetime
import logging
import os
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger("chip-map.output")


def generate_scan_report(scan_results: Dict[str, Any], output_dir: str, timestamp: str) -> str:
    """
    Generate a Markdown report for a scan.
    
    Args:
        scan_results: Dictionary containing scan results
        output_dir: Directory to write the report to
        timestamp: Timestamp string for the report
        
    Returns:
        Path to the generated report file
    """
    logger.info(f"Generating scan report for {timestamp}")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Format timestamp for display
    formatted_time = datetime.datetime.strptime(timestamp, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    
    # Create report file path
    report_path = os.path.join(output_dir, f"scan-{timestamp}.md")
    
    # Count devices in scan results
    new_count = len(scan_results.get("new_devices", []))
    updated_count = len(scan_results.get("updated_devices", []))
    offline_count = len(scan_results.get("offline_devices", []))
    total_count = new_count + updated_count
    
    # Generate report content
    content = [
        f"# Chip Map Scan - {formatted_time}",
        "",
        "## Scan Summary",
        "",
        f"* Devices Discovered: {total_count}",
        f"* New Devices: {new_count}",
        f"* Updated Devices: {updated_count}",
        f"* Offline Devices: {offline_count}",
        "",
        "## Devices",
        ""
    ]
    
    # Add new devices section
    if new_count > 0:
        content.append("### New Devices")
        content.append("")
        
        for device in scan_results.get("new_devices", []):
            device_name = get_device_name(device)
            device_type = device.get("device_type", "unknown")
            ip_address = device.get("ip_address", "unknown")
            chip_count = len(device.get("chips", []))
            
            content.append(f"* [[device-{device.get('mac_address', '').replace(':', '')}.md|{device_name}]]")
            content.append(f"  * Type: {device_type}")
            content.append(f"  * IP: {ip_address}")
            content.append(f"  * Chips: {chip_count}")
            content.append("")
    
    # Add updated devices section
    if updated_count > 0:
        content.append("### Updated Devices")
        content.append("")
        
        for device in scan_results.get("updated_devices", []):
            device_name = get_device_name(device)
            device_type = device.get("device_type", "unknown")
            ip_address = device.get("ip_address", "unknown")
            chip_count = len(device.get("chips", []))
            
            content.append(f"* [[device-{device.get('mac_address', '').replace(':', '')}.md|{device_name}]]")
            content.append(f"  * Type: {device_type}")
            content.append(f"  * IP: {ip_address}")
            content.append(f"  * Chips: {chip_count}")
            content.append("")
    
    # Add offline devices section
    if offline_count > 0:
        content.append("### Offline Devices")
        content.append("")
        
        for device in scan_results.get("offline_devices", []):
            device_name = get_device_name(device)
            device_type = device.get("device_type", "unknown")
            last_seen = device.get("last_seen", "unknown")
            
            # Format last_seen if it's an ISO format date
            if isinstance(last_seen, str) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', last_seen):
                last_seen = datetime.datetime.fromisoformat(last_seen).strftime("%Y-%m-%d %H:%M:%S")
            
            content.append(f"* [[device-{device.get('mac_address', '').replace(':', '')}.md|{device_name}]]")
            content.append(f"  * Type: {device_type}")
            content.append(f"  * Last Seen: {last_seen}")
            content.append("")
    
    # Write content to file
    with open(report_path, 'w') as f:
        f.write("\n".join(content))
    
    logger.info(f"Scan report written to {report_path}")
    return report_path


def generate_device_file(device: Dict[str, Any], output_dir: str) -> str:
    """
    Generate a Markdown file for a device.
    
    Args:
        device: Dictionary containing device information
        output_dir: Directory to write the file to
        
    Returns:
        Path to the generated file
    """
    if not device or "mac_address" not in device:
        logger.error("Cannot generate device file without MAC address")
        return ""
    
    logger.info(f"Generating device file for {device.get('mac_address', '')}")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Create file path based on MAC address
    mac_address = device.get("mac_address", "").replace(":", "")
    file_path = os.path.join(output_dir, f"device-{mac_address}.md")
    
    # Get device name and format timestamps
    device_name = get_device_name(device)
    first_seen = format_timestamp(device.get("first_seen", ""))
    last_seen = format_timestamp(device.get("last_seen", ""))
    
    # Generate content
    content = [
        f"# Device: {device_name}",
        "",
        "## Device Information",
        "",
        f"* MAC Address: `{device.get('mac_address', '')}`",
        f"* IP Address: `{device.get('ip_address', 'Unknown')}`",
        f"* Device Type: {device.get('device_type', 'Unknown')}",
        f"* Hostname: {device.get('hostname', 'Unknown')}",
        f"* First Seen: {first_seen}",
        f"* Last Seen: {last_seen}",
        ""
    ]
    
    # Add OS information if available
    if "os" in device:
        content.append(f"* Operating System: {device.get('os', '')} {device.get('os_version', '')}")
        content.append("")
    
    # Add chip information
    chips = device.get("chips", [])
    if chips:
        content.extend(_generate_device_chip_section(device))
    
    # Add scan history if available
    scan_history = device.get("scan_history", [])
    if scan_history:
        content.append("## Scan History")
        content.append("")
        
        for scan in scan_history[-5:]:  # Show only the 5 most recent entries
            timestamp = format_timestamp(scan.get("timestamp", ""))
            ip = scan.get("ip_address", "Unknown")
            status = scan.get("status", "Unknown")
            
            content.append(f"* {timestamp}: IP `{ip}`, Status: {status}")
        
        if len(scan_history) > 5:
            content.append(f"* ... and {len(scan_history) - 5} more entries")
        
        content.append("")
    
    # Write content to file
    with open(file_path, 'w') as f:
        f.write("\n".join(content))
    
    logger.info(f"Device file written to {file_path}")
    return file_path


def update_device_file(device: Dict[str, Any], output_dir: str) -> str:
    """
    Update an existing device file or create a new one.
    Since we want complete information, we just regenerate the file.
    
    Args:
        device: Dictionary containing device information
        output_dir: Directory containing the file
        
    Returns:
        Path to the updated file
    """
    return generate_device_file(device, output_dir)


def generate_chip_file(chip: Dict[str, Any], output_dir: str) -> str:
    """
    Generate a Markdown file for a chip if it doesn't already exist.
    
    Args:
        chip: Dictionary containing chip information
        output_dir: Directory to write the file to
        
    Returns:
        Path to the generated or existing file
    """
    if not chip or "manufacturer" not in chip or "model" not in chip:
        logger.error("Cannot generate chip file without manufacturer and model")
        return ""
    
    # Create a standardized chip identifier
    manufacturer = chip.get("manufacturer", "Unknown")
    model = chip.get("model", "Unknown")
    chip_id = f"{manufacturer.lower().replace(' ', '-')}-{model.lower().replace(' ', '-').replace('/', '-')}"
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    # Create file path
    file_path = os.path.join(output_dir, f"{chip_id}.md")
    
    # Check if file already exists
    if os.path.exists(file_path):
        logger.debug(f"Chip file already exists: {file_path}")
        return file_path
    
    logger.info(f"Generating chip file for {manufacturer} {model}")
    
    # Generate content
    chip_type = chip.get("type", "unknown").title()
    country = chip.get("country_of_origin", "Unknown")
    
    content = [
        f"# {chip_type}: {manufacturer} {model}",
        "",
        "## Chip Information",
        "",
        f"* Type: {chip_type}",
        f"* Manufacturer: {manufacturer}",
        f"* Model: {model}",
        f"* Country of Origin: {country}",
        ""
    ]
    
    # Add manufacturing information (fabrication and assembly)
    if "manufacturing" in chip:
        content.extend([
            f"* Fabrication: {chip['manufacturing']['fabrication']}",
            f"* Assembly: {chip['manufacturing']['assembly']}"
        ])
    elif "country_of_origin" in chip:
        # For backward compatibility with older chips
        content.append(f"* Country of Origin: {chip['country_of_origin']}")
    
    # Add capabilities if available
    capabilities = chip.get("capabilities", [])
    if capabilities:
        content.append("## Capabilities")
        content.append("")
        for capability in capabilities:
            content.append(f"* {capability}")
        content.append("")
    
    # Add links if available
    links = chip.get("links", [])
    if links:
        content.append("## Links")
        content.append("")
        for link in links:
            content.append(f"* [{link}]({link})")
        content.append("")
    
    # Add devices section (to be filled in later)
    content.append("## Devices Using This Chip")
    content.append("")
    content.append("*No devices linked yet*")
    content.append("")
    
    # Write content to file
    with open(file_path, 'w') as f:
        f.write("\n".join(content))
    
    logger.info(f"Chip file written to {file_path}")
    return file_path


def get_device_name(device: Dict[str, Any]) -> str:
    """
    Get a human-readable name for a device.
    
    Args:
        device: Device dictionary
        
    Returns:
        Device name string
    """
    if "hostname" in device and device["hostname"]:
        return device["hostname"]
    elif "device_type" in device and device["device_type"]:
        if "ip_address" in device and device["ip_address"]:
            return f"{device['device_type'].replace('_', ' ').title()} ({device['ip_address']})"
        else:
            return device['device_type'].replace('_', ' ').title()
    elif "ip_address" in device and device["ip_address"]:
        return f"Device at {device['ip_address']}"
    elif "mac_address" in device and device["mac_address"]:
        return f"Device {device['mac_address']}"
    else:
        return "Unknown Device"


def format_timestamp(timestamp: str) -> str:
    """
    Format an ISO timestamp for display.
    
    Args:
        timestamp: ISO format timestamp
        
    Returns:
        Formatted timestamp string
    """
    if not timestamp:
        return "Unknown"
    
    try:
        dt = datetime.datetime.fromisoformat(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return timestamp


def _generate_device_chip_section(device: Dict[str, Any]) -> List[str]:
    """
    Generate content for the chips section of a device markdown file.
    
    Args:
        device: Device dictionary
        
    Returns:
        List of markdown content lines
    """
    content = []
    
    # Check if device has chips
    if not device.get("chips"):
        return content
    
    content.extend([
        "## Chips",
        ""
    ])
    
    for chip in device["chips"]:
        chip_type = chip["type"].capitalize()
        content.extend([
            f"### {chip_type}: {chip['manufacturer']} {chip['model']}",
            "",
            f"* Manufacturer: {chip['manufacturer']}",
            f"* Model: {chip['model']}"
        ])
        
        # Add manufacturing information (fabrication and assembly)
        if "manufacturing" in chip:
            content.extend([
                f"* Fabrication: {chip['manufacturing']['fabrication']}",
                f"* Assembly: {chip['manufacturing']['assembly']}"
            ])
        elif "country_of_origin" in chip:
            # For backward compatibility with older chips
            content.append(f"* Country of Origin: {chip['country_of_origin']}")
            
        # Add capabilities if present
        if chip.get("capabilities"):
            content.append("* Capabilities:")
            for capability in chip["capabilities"]:
                content.append(f"  * {capability}")
                
        # Add links if present
        if chip.get("links"):
            content.append("* Links:")
            for link in chip["links"]:
                content.append(f"  * [{link}]({link})")
                
        content.append("")  # Add blank line after each chip
    
    return content


def generate_chip_markdown(chip: Dict[str, Any]) -> str:
    """
    Generate Markdown content for a chip.
    
    Args:
        chip: Dictionary containing chip information
        
    Returns:
        Markdown content
    """
    # Uppercase first letter of chip type
    chip_type = chip["type"].capitalize()
    
    # Create frontmatter and content
    markdown = f"# {chip_type}: {chip['manufacturer']} {chip['model']}\n\n"
    
    # Add chip information section
    markdown += "## Chip Information\n\n"
    markdown += f"* Type: {chip_type}\n"
    markdown += f"* Manufacturer: {chip['manufacturer']}\n"
    markdown += f"* Model: {chip['model']}\n"
    
    # Add manufacturing information (fabrication and assembly)
    if "manufacturing" in chip:
        markdown += f"* Fabrication: {chip['manufacturing']['fabrication']}\n"
        markdown += f"* Assembly: {chip['manufacturing']['assembly']}\n"
    elif "country_of_origin" in chip:
        # For backward compatibility with older chips
        markdown += f"* Country of Origin: {chip['country_of_origin']}\n"
    
    # Add capabilities if present
    if chip.get("capabilities"):
        markdown += "\n## Capabilities\n\n"
        for capability in chip["capabilities"]:
            markdown += f"* {capability}\n"
    
    # Add links if present
    if chip.get("links"):
        markdown += "\n## Links\n\n"
        for link in chip["links"]:
            url = link.strip()
            # Extract domain name for link text
            domain = re.search(r"https?://(?:www\.)?([^/]+)", url)
            link_text = domain.group(1) if domain else url
            markdown += f"* [{url}]({url})\n"
    
    # Add placeholder for devices using this chip
    markdown += "\n## Devices Using This Chip\n\n"
    markdown += "*No devices linked yet*\n"
    
    return markdown


def generate_device_markdown(device: Dict[str, Any]) -> str:
    """
    Generate Markdown content for a device.
    
    Args:
        device: Dictionary containing device information
        
    Returns:
        Markdown content
    """
    # Create frontmatter and content
    markdown = f"# Device: {device['hostname']}\n\n"
    
    # Add device information section
    markdown += "## Device Information\n\n"
    markdown += f"* MAC Address: `{device['mac_address']}`\n"
    markdown += f"* IP Address: `{device['ip_address']}`\n"
    markdown += f"* Device Type: {device['device_type']}\n"
    markdown += f"* Hostname: {device['hostname']}\n"
    markdown += f"* First Seen: {device.get('first_seen', 'Unknown')}\n"
    markdown += f"* Last Seen: {device.get('last_seen', 'Unknown')}\n\n"
    
    # Add OS information if present
    if device.get("os"):
        os_info = device["os"]
        markdown += f"* Operating System: {os_info.get('name', 'Unknown')} {os_info.get('version', '')}\n\n"
    
    # Add chips section if present
    if device.get("chips"):
        markdown += "## Chips\n\n"
        
        for chip in device["chips"]:
            chip_type = chip["type"].capitalize()
            markdown += f"### {chip_type}: {chip['manufacturer']} {chip['model']}\n\n"
            markdown += f"* Manufacturer: {chip['manufacturer']}\n"
            markdown += f"* Model: {chip['model']}\n"
            
            # Add manufacturing information (fabrication and assembly)
            if "manufacturing" in chip:
                markdown += f"* Fabrication: {chip['manufacturing']['fabrication']}\n"
                markdown += f"* Assembly: {chip['manufacturing']['assembly']}\n"
            elif "country_of_origin" in chip:
                # For backward compatibility with older chips
                markdown += f"* Country of Origin: {chip['country_of_origin']}\n"
            
            # Add capabilities if present
            if chip.get("capabilities"):
                markdown += "* Capabilities:\n"
                for capability in chip["capabilities"]:
                    markdown += f"  * {capability}\n"
            
            # Add links section
            if chip.get("links"):
                markdown += "* Links:\n"
                for link in chip["links"]:
                    markdown += f"  * [{link}]({link})\n"
            
            markdown += "\n"
    
    return markdown


if __name__ == "__main__":
    # Example usage when run directly
    logging.basicConfig(level=logging.INFO)
    
    # Example device for demonstration
    example_device = {
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "ip_address": "192.168.0.100",
        "device_type": "example",
        "hostname": "example.local",
        "os": {
            "name": "Example OS",
            "version": "1.0"
        },
        "first_seen": "2025-03-30T00:00:00.000000",
        "last_seen": "2025-03-30T00:00:00.000000",
        "chips": [
            {
                "type": "cpu",
                "manufacturer": "Example",
                "model": "CPU-X1000",
                "manufacturing": {
                    "fabrication": "Taiwan",
                    "assembly": "China"
                },
                "capabilities": ["Feature 1", "Feature 2"],
                "links": ["https://example.com/cpu"]
            }
        ],
        "scan_history": [
            {
                "timestamp": "2025-03-30T00:00:00.000000",
                "ip_address": "192.168.0.100",
                "status": "online"
            }
        ]
    }
    
    # Generate device file
    device_file = generate_device_file(example_device, "example")
    print(f"Generated device file: {device_file}")
    
    # Generate chip file
    chip_file = generate_chip_file(example_device["chips"][0], "example")
    print(f"Generated chip file: {chip_file}")
