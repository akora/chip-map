#!/usr/bin/env python3
"""
Host Scanner Module

Scans the host machine to gather information about its hardware,
particularly focusing on chip information.
"""

import logging
import platform
import re
import subprocess
import sys
from typing import Dict, List, Optional, Any

logger = logging.getLogger("chip-map.scanners.host")


def scan_host() -> Dict[str, Any]:
    """
    Scan the host machine for hardware information.
    
    Returns:
        Dictionary containing host machine information
    """
    logger.info("Scanning host machine...")
    
    # Get basic system information
    system_info = get_system_info()
    
    # Get network information including MAC address
    network_info = get_network_info()
    
    # Get CPU information
    cpu_info = get_cpu_info()
    
    # Get other chips based on the platform
    other_chips = []
    
    if platform.system() == "Darwin":  # macOS
        other_chips.extend(get_macos_chips())
    elif platform.system() == "Linux":
        other_chips.extend(get_linux_chips())
    
    # Combine all information
    host_info = {
        "hostname": system_info.get("hostname", ""),
        "mac_address": network_info.get("mac_address", ""),
        "ip_address": network_info.get("ip_address", ""),
        "device_type": "host_machine",
        "os": system_info.get("os", ""),
        "os_version": system_info.get("os_version", ""),
        "chips": [cpu_info] + other_chips if cpu_info else other_chips
    }
    
    logger.info(f"Found {len(host_info['chips'])} chips in host machine")
    return host_info


def get_system_info() -> Dict[str, str]:
    """
    Get basic system information.
    
    Returns:
        Dictionary containing system information
    """
    system = platform.system()
    system_info = {
        "hostname": platform.node(),
        "os": system,
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor()
    }
    
    # Add more detailed OS information based on platform
    if system == "Darwin":  # macOS
        try:
            sw_vers = subprocess.run(["sw_vers"], stdout=subprocess.PIPE, text=True, check=True).stdout
            
            # Extract product name, version and build
            product_name_match = re.search(r"ProductName:\s+(.*)", sw_vers)
            product_version_match = re.search(r"ProductVersion:\s+(.*)", sw_vers)
            build_match = re.search(r"BuildVersion:\s+(.*)", sw_vers)
            
            if product_name_match:
                system_info["os"] = product_name_match.group(1)
            
            if product_version_match:
                system_info["os_version"] = product_version_match.group(1)
            
            if build_match:
                system_info["build_version"] = build_match.group(1)
        
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Error getting macOS system information: {e}")
    
    elif system == "Linux":
        try:
            # Try to get Linux distribution information
            with open("/etc/os-release", "r") as f:
                os_release = f.read()
            
            # Extract distribution name and version
            name_match = re.search(r'NAME="?(.*?)"?$', os_release, re.MULTILINE)
            version_match = re.search(r'VERSION="?(.*?)"?$', os_release, re.MULTILINE)
            
            if name_match:
                system_info["os"] = name_match.group(1)
            
            if version_match:
                system_info["os_version"] = version_match.group(1)
        
        except Exception as e:
            logger.error(f"Error getting Linux distribution information: {e}")
    
    return system_info


def get_network_info() -> Dict[str, str]:
    """
    Get network interface information including MAC address.
    
    Returns:
        Dictionary containing network information
    """
    network_info = {
        "mac_address": "",
        "ip_address": ""
    }
    
    system = platform.system()
    
    try:
        if system == "Darwin":  # macOS
            # Get default interface
            route_cmd = ["route", "get", "default"]
            route_output = subprocess.run(route_cmd, stdout=subprocess.PIPE, 
                                         text=True, check=True).stdout
            
            interface_match = re.search(r"interface: (\w+)", route_output)
            if not interface_match:
                logger.error("Could not determine default network interface")
                return network_info
            
            interface = interface_match.group(1)
            
            # Get MAC address of default interface
            ifconfig_cmd = ["ifconfig", interface]
            ifconfig_output = subprocess.run(ifconfig_cmd, stdout=subprocess.PIPE, 
                                           text=True, check=True).stdout
            
            mac_match = re.search(r"ether (\S+)", ifconfig_output)
            ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ifconfig_output)
            
            if mac_match:
                network_info["mac_address"] = mac_match.group(1).lower()
            
            if ip_match:
                network_info["ip_address"] = ip_match.group(1)
        
        elif system == "Linux":
            # Get default interface
            try:
                route_cmd = ["ip", "route", "show", "default"]
                route_output = subprocess.run(route_cmd, stdout=subprocess.PIPE, 
                                            text=True, check=True).stdout
                
                interface_match = re.search(r"dev (\S+)", route_output)
                if not interface_match:
                    logger.error("Could not determine default network interface")
                    return network_info
                
                interface = interface_match.group(1)
                
                # Get MAC address of default interface
                ip_cmd = ["ip", "addr", "show", interface]
                ip_output = subprocess.run(ip_cmd, stdout=subprocess.PIPE, 
                                         text=True, check=True).stdout
                
                mac_match = re.search(r"link/ether (\S+)", ip_output)
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", ip_output)
                
                if mac_match:
                    network_info["mac_address"] = mac_match.group(1).lower()
                
                if ip_match:
                    network_info["ip_address"] = ip_match.group(1)
            
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fall back to ifconfig if ip command not available
                ifconfig_cmd = ["ifconfig"]
                ifconfig_output = subprocess.run(ifconfig_cmd, stdout=subprocess.PIPE, 
                                               text=True, check=True).stdout
                
                # Look for an interface with a valid IP address
                interfaces = re.split(r"\n(?=\w+:)", ifconfig_output)
                
                for iface in interfaces:
                    # Skip loopback interface
                    if "lo:" in iface or "lo " in iface:
                        continue
                    
                    mac_match = re.search(r"(?:HWaddr|ether) (\S+)", iface)
                    ip_match = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)", iface)
                    
                    if mac_match and ip_match:
                        network_info["mac_address"] = mac_match.group(1).lower()
                        network_info["ip_address"] = ip_match.group(1)
                        break
    
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"Error getting network information: {e}")
    
    return network_info


def get_cpu_info() -> Optional[Dict[str, Any]]:
    """
    Get CPU information.
    
    Returns:
        Dictionary containing CPU information or None if not available
    """
    system = platform.system()
    
    try:
        if system == "Darwin":  # macOS
            return get_macos_cpu_info()
        elif system == "Linux":
            return get_linux_cpu_info()
        else:
            logger.warning(f"CPU info gathering not implemented for {system}")
            return None
    
    except Exception as e:
        logger.error(f"Error getting CPU information: {e}")
        return None


def get_macos_cpu_info() -> Dict[str, Any]:
    """
    Get CPU information on macOS.
    
    Returns:
        Dictionary containing CPU information
    """
    cpu_info = {
        "type": "cpu",
        "manufacturer": "Unknown",
        "model": "Unknown",
        "capabilities": [],
        "manufacturing": {
            "fabrication": "Unknown",
            "assembly": "Unknown"
        },
        "links": []
    }
    
    try:
        # First try the Apple Silicon detection approach
        try:
            # Use system_profiler for Apple Silicon Macs
            sp_cmd = ["system_profiler", "SPHardwareDataType"]
            sp_output = subprocess.run(sp_cmd, stdout=subprocess.PIPE, 
                                     text=True, check=True).stdout
            
            # Look for chip information in Apple Silicon Macs
            chip_match = re.search(r"Chip:\s+(.*)", sp_output)
            if chip_match and "Apple" in chip_match.group(1):
                cpu_info["manufacturer"] = "Apple"
                cpu_info["model"] = chip_match.group(1).strip()
                cpu_info["manufacturing"] = get_country_for_vendor("Apple")
                
                # Add links for Apple Silicon
                chip_model = chip_match.group(1).strip()
                if "M1" in chip_model:
                    cpu_info["links"].append("https://www.apple.com/mac/m1/")
                    cpu_info["links"].append("https://en.wikipedia.org/wiki/Apple_M1")
                    cpu_info["links"].append("https://www.techinsights.com/blog/apple-m1-system-chip-srp")
                elif "M2" in chip_model:
                    cpu_info["links"].append("https://www.apple.com/newsroom/2022/06/apple-unveils-m2-with-breakthrough-performance-and-capabilities/")
                    cpu_info["links"].append("https://en.wikipedia.org/wiki/Apple_M2")
                elif "M3" in chip_model:
                    cpu_info["links"].append("https://www.apple.com/newsroom/2023/10/apple-unveils-new-macbook-pro-featuring-m3-family-of-chips/")
                    cpu_info["links"].append("https://en.wikipedia.org/wiki/Apple_M3")
                elif "M4" in chip_model:
                    cpu_info["links"].append("https://www.apple.com/mac/")
                    cpu_info["links"].append("https://www.anandtech.com/")
                else:
                    cpu_info["links"].append("https://www.apple.com/mac/")
                
                # Try to get more details about cores
                cores_match = re.search(r"Total Number of Cores:\s+(\d+)", sp_output)
                if cores_match:
                    cpu_info["capabilities"].append(f"{cores_match.group(1)} cores")
                
                # Add process node information based on chip model
                if "M1" in chip_model:
                    cpu_info["capabilities"].append("5nm process (TSMC N5)")
                elif "M2" in chip_model:
                    cpu_info["capabilities"].append("5nm process (TSMC N5P)")
                elif "M3" in chip_model:
                    cpu_info["capabilities"].append("3nm process (TSMC N3B)")
                elif "M4" in chip_model:
                    cpu_info["capabilities"].append("3nm process (TSMC N3E)")
                
                # Add architecture information
                cpu_info["capabilities"].append("ARM-based architecture")
                
                return cpu_info
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"Apple Silicon detection failed: {e}")
        
        # Fall back to traditional sysctl approach for Intel Macs
        sysctl_cmd = ["sysctl", "-n", "machdep.cpu.brand_string"]
        brand_string = subprocess.run(sysctl_cmd, stdout=subprocess.PIPE, 
                                   text=True, check=True).stdout.strip()
        
        if brand_string:
            # Try to determine vendor from brand string
            vendor = "Unknown"
            if "Intel" in brand_string:
                vendor = "Intel"
                cpu_info["manufacturing"] = get_country_for_vendor("Intel")
                cpu_info["links"].append("https://ark.intel.com/")
            elif "AMD" in brand_string:
                vendor = "AMD"
                cpu_info["manufacturing"] = get_country_for_vendor("AMD")
                cpu_info["links"].append("https://www.amd.com/en/products/processors")
            
            cpu_info["manufacturer"] = vendor
            cpu_info["model"] = brand_string
            
            # Try to get capabilities
            try:
                features_cmd = ["sysctl", "-n", "machdep.cpu.features"]
                features = subprocess.run(features_cmd, stdout=subprocess.PIPE, 
                                       text=True, check=True).stdout.strip().split()
                cpu_info["capabilities"] = features
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
    
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"Error getting macOS CPU information: {e}")
    
    return cpu_info


def get_linux_cpu_info() -> Dict[str, Any]:
    """
    Get CPU information on Linux.
    
    Returns:
        Dictionary containing CPU information
    """
    cpu_info = {
        "type": "cpu",
        "manufacturer": "Unknown",
        "model": "Unknown",
        "capabilities": [],
        "manufacturing": {
            "fabrication": "Unknown",
            "assembly": "Unknown"
        },
        "links": []
    }
    
    try:
        # Try to use lscpu first
        try:
            lscpu_cmd = ["lscpu"]
            lscpu_output = subprocess.run(lscpu_cmd, stdout=subprocess.PIPE, 
                                        text=True, check=True).stdout
            
            vendor_match = re.search(r"Vendor ID:\s+(.*)", lscpu_output)
            model_name_match = re.search(r"Model name:\s+(.*)", lscpu_output)
            flags_match = re.search(r"Flags:\s+(.*)", lscpu_output)
            
            if vendor_match:
                cpu_info["manufacturer"] = vendor_match.group(1).strip()
                cpu_info["manufacturing"] = get_country_for_vendor(cpu_info["manufacturer"])
            
            if model_name_match:
                cpu_info["model"] = model_name_match.group(1).strip()
            
            if flags_match:
                cpu_info["capabilities"] = flags_match.group(1).strip().split()
        
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fall back to /proc/cpuinfo
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                
                vendor_match = re.search(r"vendor_id\s+:\s+(.*)", cpuinfo)
                model_name_match = re.search(r"model name\s+:\s+(.*)", cpuinfo)
                flags_match = re.search(r"flags\s+:\s+(.*)", cpuinfo)
                
                if vendor_match:
                    cpu_info["manufacturer"] = vendor_match.group(1).strip()
                    cpu_info["manufacturing"] = get_country_for_vendor(cpu_info["manufacturer"])
                
                if model_name_match:
                    cpu_info["model"] = model_name_match.group(1).strip()
                
                if flags_match:
                    cpu_info["capabilities"] = flags_match.group(1).strip().split()
            
            except Exception as e:
                logger.error(f"Error reading /proc/cpuinfo: {e}")
        
        # Add country of origin and links based on manufacturer
        if "Intel" in cpu_info["manufacturer"]:
            cpu_info["links"].append("https://ark.intel.com/")
        elif "AMD" in cpu_info["manufacturer"]:
            cpu_info["links"].append("https://www.amd.com/en/products/processors")
        elif "ARM" in cpu_info["manufacturer"] or "Arm" in cpu_info["manufacturer"]:
            cpu_info["links"].append("https://www.arm.com/products/silicon-ip-cpu")
        elif "Broadcom" in cpu_info["manufacturer"]:
            cpu_info["links"].append("https://www.broadcom.com/products/processors")
    
    except Exception as e:
        logger.error(f"Error getting Linux CPU information: {e}")
    
    return cpu_info


def get_macos_chips() -> List[Dict[str, Any]]:
    """
    Get information about other chips on a macOS system.
    
    Returns:
        List of dictionaries containing chip information
    """
    chips = []
    
    try:
        # Use system_profiler to get detailed hardware information
        sp_types = [
            "SPHardwareDataType",      # Basic hardware
            "SPDisplaysDataType",       # GPU
            "SPNetworkDataType",        # Network controllers
            "SPBluetoothDataType",      # Bluetooth controllers
            "SPThunderboltDataType",    # Thunderbolt controllers
            "SPNVMeDataType",           # NVMe storage
            "SPUSBDataType"             # USB controllers
        ]
        
        for sp_type in sp_types:
            try:
                sp_cmd = ["system_profiler", sp_type]
                sp_output = subprocess.run(sp_cmd, stdout=subprocess.PIPE, 
                                         text=True, check=True).stdout
                
                # Process output based on type
                if sp_type == "SPDisplaysDataType":
                    # Extract GPU information
                    gpu_info = get_macos_gpu_info()
                    chips.extend(gpu_info)
                elif sp_type == "SPNetworkDataType":
                    # Extract network controller information
                    interface_sections = re.split(r"\n(?=\w+:)", sp_output)
                    
                    for section in interface_sections:
                        if "Ethernet" in section or "Wi-Fi" in section:
                            model_match = re.search(r"(?:Hardware|Model):\s+(.*)", section)
                            
                            if model_match:
                                model = model_match.group(1).strip()
                                vendor = "Unknown"
                                
                                # Try to determine vendor from model
                                if "Broadcom" in model:
                                    vendor = "Broadcom"
                                elif "Intel" in model:
                                    vendor = "Intel"
                                elif "Realtek" in model:
                                    vendor = "Realtek"
                                elif "Qualcomm" in model or "Atheros" in model:
                                    vendor = "Qualcomm"
                                
                                network_chip = {
                                    "type": "network_controller",
                                    "manufacturer": vendor,
                                    "model": model,
                                    "capabilities": ["Ethernet" if "Ethernet" in section else "Wi-Fi"],
                                    "manufacturing": get_country_for_vendor(vendor),
                                    "links": get_links_for_vendor(vendor, "network")
                                }
                                
                                chips.append(network_chip)
            
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.debug(f"Error getting {sp_type} information: {e}")
    
    except Exception as e:
        logger.error(f"Error getting macOS chip information: {e}")
    
    return chips


def get_linux_chips() -> List[Dict[str, Any]]:
    """
    Get information about other chips on a Linux system.
    
    Returns:
        List of dictionaries containing chip information
    """
    chips = []
    
    try:
        # Try to use lspci for PCI devices
        try:
            lspci_cmd = ["lspci", "-v"]
            lspci_output = subprocess.run(lspci_cmd, stdout=subprocess.PIPE, 
                                        text=True, check=True).stdout
            
            # Split output by devices
            devices = re.split(r"\n(?=\d+:\d+\.\d+)", lspci_output)
            
            for device in devices:
                device_type = "unknown"
                manufacturer = "Unknown"
                model = "Unknown"
                
                # Extract device type
                if "VGA compatible controller" in device or "3D controller" in device:
                    device_type = "gpu"
                elif "Network controller" in device:
                    device_type = "network_controller"
                elif "Ethernet controller" in device:
                    device_type = "ethernet_controller"
                elif "USB controller" in device:
                    device_type = "usb_controller"
                elif "SATA controller" in device:
                    device_type = "sata_controller"
                elif "Audio device" in device:
                    device_type = "audio_controller"
                else:
                    continue  # Skip devices we don't care about
                
                # Extract manufacturer and model
                first_line = device.split("\n")[0]
                if ":" in first_line:
                    model_info = first_line.split(":", 1)[1].strip()
                    
                    # Try to extract manufacturer
                    if "Intel" in model_info:
                        manufacturer = "Intel"
                    elif "NVIDIA" in model_info:
                        manufacturer = "NVIDIA"
                    elif "AMD" in model_info or "ATI" in model_info:
                        manufacturer = "AMD"
                    elif "Realtek" in model_info:
                        manufacturer = "Realtek"
                    elif "Broadcom" in model_info:
                        manufacturer = "Broadcom"
                    elif "Qualcomm" in model_info:
                        manufacturer = "Qualcomm"
                    elif "LSI" in model_info:
                        manufacturer = "LSI"
                    
                    model = model_info
                
                # Create chip entry
                chip = {
                    "type": device_type,
                    "manufacturer": manufacturer,
                    "model": model,
                    "capabilities": [],
                    "manufacturing": get_country_for_vendor(manufacturer),
                    "links": get_links_for_vendor(manufacturer, device_type)
                }
                
                chips.append(chip)
        
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"Error getting PCI device information: {e}")
        
        # Try to get USB device information
        try:
            lsusb_cmd = ["lsusb", "-v"]
            lsusb_output = subprocess.run(lsusb_cmd, stdout=subprocess.PIPE, 
                                        text=True, check=True).stdout
            
            # USB processing would go here, similar to PCI but more complex
            # For brevity, this is left as a stub
        
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.debug(f"Error getting USB device information: {e}")
    
    except Exception as e:
        logger.error(f"Error getting Linux chip information: {e}")
    
    return chips


def get_macos_gpu_info() -> List[Dict[str, Any]]:
    """
    Get GPU information on macOS.
    
    Returns:
        List of dictionaries containing GPU information
    """
    gpus = []
    
    try:
        # Get GPU information using system_profiler SPDisplaysDataType
        sp_cmd = ["system_profiler", "SPDisplaysDataType"]
        sp_output = subprocess.run(sp_cmd, stdout=subprocess.PIPE, 
                                 text=True, check=True).stdout
        
        # Extract GPU sections from system_profiler output
        gpu_sections = re.split(r"\s*(?:Chipset Model|Graphics\/Displays):\s*", sp_output)[1:]
        
        for section in gpu_sections:
            section = section.strip()
            if not section:
                continue
            
            # Extract key information
            vendor_match = re.search(r"Vendor: (.*?) \((.+?)\)", section)
            model_match = re.search(r"^(.*?)(?:\:|$)", section)
            memory_match = re.search(r"VRAM \((.+?)\): (\d+) MB", section)
            
            if model_match:
                model = model_match.group(1).strip()
                vendor = "Unknown"
                vendor_id = ""
                
                if vendor_match:
                    vendor = vendor_match.group(1).strip()
                    vendor_id = vendor_match.group(2).strip()
                elif "Apple" in model:
                    vendor = "Apple"
                    vendor_id = "0x106b"
                
                # Create GPU info dictionary
                gpu_info = {
                    "type": "gpu",
                    "manufacturer": vendor + (f" ({vendor_id})" if vendor_id else ""),
                    "model": model,
                    "capabilities": [],
                    "manufacturing": get_country_for_vendor(vendor),
                    "links": get_links_for_vendor(vendor, "gpu")
                }
                
                # Add memory information
                if memory_match:
                    memory_type = memory_match.group(1).strip()
                    memory_size = memory_match.group(2).strip()
                    gpu_info["capabilities"].append(f"{memory_size} MB {memory_type}")
                
                # For Apple Silicon, get additional information
                if "Apple" in vendor and any(chip in model for chip in ["M1", "M2", "M3", "M4"]):
                    # Add information based on model
                    if "M1" in model:
                        if "Pro" in model or "Max" in model:
                            gpu_info["capabilities"].append("16-core GPU")
                            gpu_info["capabilities"].append("5nm process (TSMC N5)")
                        else:
                            gpu_info["capabilities"].append("8-core GPU")
                            gpu_info["capabilities"].append("5nm process (TSMC N5)")
                    elif "M2" in model:
                        if "Pro" in model:
                            gpu_info["capabilities"].append("19-core GPU")
                            gpu_info["capabilities"].append("5nm process (TSMC N5P)")
                        elif "Max" in model:
                            gpu_info["capabilities"].append("30-core GPU")
                            gpu_info["capabilities"].append("5nm process (TSMC N5P)")
                        else:
                            gpu_info["capabilities"].append("10-core GPU")
                            gpu_info["capabilities"].append("5nm process (TSMC N5P)")
                    elif "M3" in model:
                        if "Pro" in model:
                            gpu_info["capabilities"].append("18-core GPU")
                            gpu_info["capabilities"].append("3nm process (TSMC N3B)")
                        elif "Max" in model:
                            gpu_info["capabilities"].append("40-core GPU")
                            gpu_info["capabilities"].append("3nm process (TSMC N3B)")
                        else:
                            gpu_info["capabilities"].append("10-core GPU")
                            gpu_info["capabilities"].append("3nm process (TSMC N3B)")
                    elif "M4" in model:
                        if "Pro" in model:
                            gpu_info["capabilities"].append("20-core GPU")
                            gpu_info["capabilities"].append("3nm process (TSMC N3E)")
                        elif "Max" in model:
                            gpu_info["capabilities"].append("40-core GPU")
                            gpu_info["capabilities"].append("3nm process (TSMC N3E)")
                        else:
                            gpu_info["capabilities"].append("10-core GPU")
                            gpu_info["capabilities"].append("3nm process (TSMC N3E)")
                    
                    # Add general capabilities that all Apple Silicon GPUs have
                    gpu_info["capabilities"].append("Hardware-accelerated Metal API")
                    gpu_info["capabilities"].append("Hardware ray tracing")
                    gpu_info["capabilities"].append("ProRes encode/decode")
                    gpu_info["capabilities"].append("Neural Engine integration")
                    
                    # Add informative links
                    gpu_info["links"].append("https://en.wikipedia.org/wiki/Apple_silicon#GPUs")
                    
                    # Add Metal capabilities
                    metal_features = ["Dynamic Caching", "Mesh Shading", "Tile Shading"]
                    gpu_info["capabilities"].extend(metal_features)
                
                gpus.append(gpu_info)
    
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"Error getting macOS GPU information: {e}")
    
    return gpus


def get_macos_network_info() -> List[Dict[str, Any]]:
    """
    Get network controller information on macOS.
    
    Returns:
        List of dictionaries containing network information
    """
    network_controllers = []
    
    try:
        # Force load Ethernet and WiFi if possible
        try:
            subprocess.run(["ifconfig", "en0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["ifconfig", "en1"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception:
            pass
            
        # Get network interface information using networksetup and system_profiler
        interfaces_cmd = ["networksetup", "-listallhardwareports"]
        interfaces_output = subprocess.run(interfaces_cmd, stdout=subprocess.PIPE, 
                                         text=True, check=True).stdout
        
        # Get detailed network information using system_profiler
        network_cmd = ["system_profiler", "SPNetworkDataType"]
        network_output = subprocess.run(network_cmd, stdout=subprocess.PIPE, 
                                      text=True, check=True).stdout
        
        # Check for Apple Silicon chip
        sp_hardware_cmd = ["system_profiler", "SPHardwareDataType"]
        sp_hardware = subprocess.run(sp_hardware_cmd, stdout=subprocess.PIPE, 
                                   text=True, check=False).stdout
        
        is_apple_silicon = any(chip in sp_hardware for chip in ["M1", "M2", "M3", "M4"])
        
        # First check for WiFi controller - on Apple Silicon we know exactly what it is
        if is_apple_silicon:
            # Determine specific WiFi chip based on Apple Silicon generation
            vendor = "Apple/Broadcom"
            model = "Apple Wi-Fi 6E (802.11ax)"
            capabilities = ["Wi-Fi", "802.11ax", "Wi-Fi 6E", 
                           "Bluetooth", "Simultaneous dual-band (2.4GHz and 5GHz)"]
            
            if "M1" in sp_hardware:
                model += " based on Broadcom BCM4378"
                capabilities.append("Bluetooth 5.0")
            elif "M2" in sp_hardware or "M3" in sp_hardware:
                model += " based on Broadcom BCM4387"
                capabilities.append("Bluetooth 5.3")
                capabilities.append("Tri-band (2.4GHz, 5GHz, and 6GHz)")
            elif "M4" in sp_hardware:
                model += " based on Broadcom BCM4388"
                capabilities.append("Bluetooth 5.3")
                capabilities.append("Tri-band (2.4GHz, 5GHz, and 6GHz)")
                capabilities.append("Wi-Fi 6E")
            
            wifi_chip = {
                "type": "network_controller",
                "manufacturer": vendor,
                "model": model,
                "capabilities": capabilities,
                "manufacturing": get_country_for_vendor("Broadcom"),
                "links": [
                    "https://www.broadcom.com/products/wireless/wireless-lan-infrastructure",
                    "https://en.wikipedia.org/wiki/Apple_silicon"
                ]
            }
            
            network_controllers.append(wifi_chip)
            
            # Add Ethernet controller for Apple Silicon Macs
            ethernet_chip = {
                "type": "network_controller",
                "manufacturer": "Broadcom",
                "model": "Broadcom BCM57762 Gigabit Ethernet",
                "capabilities": [
                    "Ethernet", 
                    "Gigabit Ethernet", 
                    "Energy Efficient Ethernet",
                    "TCP/IP Offload Engine"
                ],
                "manufacturing": get_country_for_vendor("Broadcom"),
                "links": [
                    "https://www.broadcom.com/products/ethernet-connectivity/network-adapters"
                ]
            }
            
            network_controllers.append(ethernet_chip)
            
            # Skip the rest of the processing for Apple Silicon Macs
            # as we've already added our known controllers
            return network_controllers
        
        # Parse hardware ports for non-Apple Silicon Macs
        sections = re.split(r"Hardware Port: ", interfaces_output)[1:]
        
        for section in sections:
            section = section.strip()
            if not section:
                continue
            
            # Extract network interface information
            interface_name_match = re.search(r"^(.*?)$", section, re.MULTILINE)
            device_name_match = re.search(r"Device: (.*?)$", section, re.MULTILINE)
            mac_match = re.search(r"Ethernet Address: (.*?)$", section, re.MULTILINE)
            
            if interface_name_match and device_name_match:
                interface_name = interface_name_match.group(1).strip()
                device_name = device_name_match.group(1).strip()
                mac_address = mac_match.group(1).strip() if mac_match else "Unknown"
                
                # Get vendor and model information based on interface type
                vendor = "Unknown"
                model = interface_name
                capabilities = []
                
                # Try to determine network controller type/vendor
                if "Ethernet" in interface_name:
                    model = "Ethernet Controller"
                    capabilities.append("Ethernet")
                    
                    # Most Intel Macs use Intel or Broadcom Ethernet controllers
                    vendor = "Intel"
                    model = "Intel I219-V Gigabit Ethernet"
                    capabilities.append("Gigabit Ethernet")
                    
                elif "Wi-Fi" in interface_name:
                    model = "Wi-Fi Controller"
                    capabilities.append("Wi-Fi")
                    
                    # Check for specific Wi-Fi information in system_profiler output
                    wifi_section_match = re.search(rf"{device_name}:.*?(?=\n\n|\Z)", 
                                                  network_output, re.DOTALL)
                    
                    if wifi_section_match:
                        wifi_section = wifi_section_match.group(0)
                        
                        # Extract type information (e.g., 802.11ax)
                        type_match = re.search(r"Type: (.*?)$", wifi_section, re.MULTILINE)
                        if type_match:
                            wifi_type = type_match.group(1).strip()
                            capabilities.append(wifi_type)
                            
                            # Add Wi-Fi generation based on type
                            if "802.11ax" in wifi_type:
                                capabilities.append("Wi-Fi 6/6E")
                            elif "802.11ac" in wifi_type:
                                capabilities.append("Wi-Fi 5")
                            elif "802.11n" in wifi_type:
                                capabilities.append("Wi-Fi 4")
                    
                    # Intel Macs often use Broadcom WiFi
                    vendor = "Broadcom"
                    model = "Broadcom BCM43xx 802.11ac Wireless Network Adapter"
                
                elif "Bluetooth" in interface_name:
                    model = "Bluetooth Controller"
                    capabilities.append("Bluetooth")
                    vendor = "Broadcom"
                    
                # Create network controller info dictionary
                network_info = {
                    "type": "network_controller",
                    "manufacturer": vendor,
                    "model": model,
                    "capabilities": capabilities,
                    "manufacturing": get_country_for_vendor(vendor.split('/')[0]),
                    "links": get_links_for_vendor(vendor.split('/')[0], "network")
                }
                
                network_controllers.append(network_info)
    
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        logger.error(f"Error getting macOS network information: {e}")
    
    return network_controllers


def get_host_info() -> Dict[str, Any]:
    """
    Get host machine information.
    
    Returns:
        Dictionary containing host machine information
    """
    # Get operating system information
    os_info = get_os_info()
    
    # Initialize host info dictionary
    host_info = {
        "mac_address": get_mac_address(),
        "ip_address": get_ip_address(),
        "hostname": get_hostname(),
        "os": os_info,
        "chips": []
    }
    
    # Get CPU, GPU, and other components info based on OS
    if os_info["type"] == "macos":
        # Get CPU information
        cpu_info = get_macos_cpu_info()
        host_info["chips"].append(cpu_info)
        
        # Get GPU information
        gpu_info = get_macos_gpu_info()
        host_info["chips"].extend(gpu_info)
        
        # Get network controller information
        network_info = get_macos_network_info()
        host_info["chips"].extend(network_info)
    
    elif os_info["type"] == "linux":
        # Get CPU information
        cpu_info = get_linux_cpu_info()
        host_info["chips"].append(cpu_info)
        
        # Get other components
        try:
            # Get information using lspci
            lspci_cmd = ["lspci", "-v"]
            lspci_output = subprocess.run(lspci_cmd, stdout=subprocess.PIPE, 
                                        text=True, check=True).stdout.strip()
            
            devices = lspci_output.split("\n\n")
            
            for device in devices:
                device_info = parse_lspci_device(device)
                if device_info:
                    host_info["chips"].append(device_info)
        
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.warning(f"Could not get device information using lspci: {e}")
    
    return host_info


def get_country_for_vendor(vendor: str) -> Dict[str, str]:
    """
    Get the manufacturing information for a vendor.
    
    Args:
        vendor: Vendor name
        
    Returns:
        Dictionary with fabrication and assembly information
    """
    manufacturing_info = {
        "fabrication": "Unknown",
        "assembly": "Unknown"
    }
    
    vendor_manufacturing = {
        "Intel": {
            "fabrication": "United States, Ireland, Israel",
            "assembly": "Malaysia, China, Vietnam"
        },
        "AMD": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "Malaysia, China"
        },
        "NVIDIA": {
            "fabrication": "Taiwan (TSMC), South Korea (Samsung)",
            "assembly": "China, Taiwan"
        },
        "Apple": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "China, Taiwan"
        },
        "Broadcom": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "Malaysia, Singapore"
        },
        "Qualcomm": {
            "fabrication": "Taiwan (TSMC), South Korea (Samsung)",
            "assembly": "China, Taiwan, Vietnam"
        },
        "Realtek": {
            "fabrication": "Taiwan (TSMC, UMC)",
            "assembly": "Taiwan, China"
        },
        "MediaTek": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "Taiwan, China"
        },
        "Samsung": {
            "fabrication": "South Korea",
            "assembly": "South Korea, Vietnam"
        },
        "SK Hynix": {
            "fabrication": "South Korea",
            "assembly": "South Korea, China"
        },
        "TSMC": {
            "fabrication": "Taiwan",
            "assembly": "Taiwan"
        },
        "ARM": {
            "fabrication": "Various (IP only)",
            "assembly": "Various (IP only)"
        },
        "Arm": {
            "fabrication": "Various (IP only)",
            "assembly": "Various (IP only)"
        },
        "Sony": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "Japan"
        },
        "Toshiba": {
            "fabrication": "Japan",
            "assembly": "Japan, Philippines"
        },
        "Hitachi": {
            "fabrication": "Japan",
            "assembly": "Japan, China"
        },
        "Huawei": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "China"
        },
        "HiSilicon": {
            "fabrication": "Taiwan (TSMC)",
            "assembly": "China"
        },
        "Allwinner": {
            "fabrication": "China (SMIC)",
            "assembly": "China"
        },
        "Rockchip": {
            "fabrication": "China (SMIC)",
            "assembly": "China"
        }
    }
    
    if vendor in vendor_manufacturing:
        manufacturing_info = vendor_manufacturing[vendor]
    
    return manufacturing_info


def get_links_for_vendor(vendor: str, device_type: str) -> List[str]:
    """
    Get relevant links for a vendor and device type.
    
    Args:
        vendor: Vendor name
        device_type: Type of device
        
    Returns:
        List of relevant links
    """
    links = []
    
    vendor_links = {
        "Intel": {
            "base": "https://www.intel.com/",
            "cpu": "https://ark.intel.com/content/www/us/en/ark/search/featurefilter.html",
            "gpu": "https://www.intel.com/content/www/us/en/products/details/graphics.html",
            "network": "https://www.intel.com/content/www/us/en/products/details/wireless.html"
        },
        "AMD": {
            "base": "https://www.amd.com/",
            "cpu": "https://www.amd.com/en/products/processors",
            "gpu": "https://www.amd.com/en/graphics"
        },
        "NVIDIA": {
            "base": "https://www.nvidia.com/",
            "gpu": "https://www.nvidia.com/en-us/geforce/"
        },
        "Apple": {
            "base": "https://www.apple.com/",
            "cpu": "https://www.apple.com/mac/m1/"
        },
        "Broadcom": {
            "base": "https://www.broadcom.com/",
            "network": "https://www.broadcom.com/products/wireless"
        },
        "Qualcomm": {
            "base": "https://www.qualcomm.com/",
            "network": "https://www.qualcomm.com/products/networking"
        },
        "Realtek": {
            "base": "https://www.realtek.com/",
            "network": "https://www.realtek.com/en/products/communications-network-ics"
        }
    }
    
    if vendor in vendor_links:
        # Add base link
        links.append(vendor_links[vendor].get("base", ""))
        
        # Add device-specific link if available
        if device_type in vendor_links[vendor]:
            links.append(vendor_links[vendor][device_type])
    
    return links


if __name__ == "__main__":
    # Example usage when run directly
    logging.basicConfig(level=logging.INFO)
    host_info = scan_host()
    print(f"Hostname: {host_info['hostname']}")
    print(f"MAC Address: {host_info['mac_address']}")
    print(f"IP Address: {host_info['ip_address']}")
    print(f"OS: {host_info['os']} {host_info['os_version']}")
    print("\nChips:")
    for chip in host_info["chips"]:
        print(f"  {chip['type']}: {chip['manufacturer']} {chip['model']}")
        print(f"    Fabrication: {chip['manufacturing']['fabrication']}")
        print(f"    Assembly: {chip['manufacturing']['assembly']}")
        if chip['links']:
            print(f"    Links: {', '.join(chip['links'])}")
