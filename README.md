# Explore all chips present in my home

## Project Scope

The scope of the project is to auto-discover, list and gather more information on key chips used in all the computers and wifi enabled devices - including connected smartphones - that are present in my home. Devices also include hubs and docks, for example a Thunderbolt dock or a USB-C hub.

The solution does not have to be complex, for example there is no need to have a UI or a web based interface.

The solution needs to be reproducible. Meaning that I can run it on any machine and get the same results, and also I can run it multiple times and get the same results.

## Common Rules

* Use already available tools like nmap, arp.
* If it makes sense, dockerize the project.
* Search for available open source libraries, APIs and tools.

## Project Structure

This project is organized as follows:

```bash
chip-map/
├── config/              # Configuration files
│   ├── config.yaml      # General configuration
│   └── credentials.yaml # Device credentials (not in git)
├── src/                 # Source code
│   ├── discovery/       # Network discovery modules
│   ├── scanners/        # Device scanners
│   ├── registry/        # Device registry management
│   └── output/          # Output formatting and generation
├── devices/             # Device markdown files
├── chips/               # Chip markdown files
├── scans/               # Scan logs
├── db/                  # Registry database
├── utils/               # Utility functions
└── requirements.txt     # Python dependencies
```

## Getting Started

### Prerequisites

* Python 3.8 or higher.
* Network access to devices you want to scan.
* Required system tools:
  * nmap (for network scanning).
  * arp (for MAC address resolution).

### Installation

1. Clone this repository:

```bash
git clone https://github.com/yourusername/chip-map.git
cd chip-map
```

1. Create and activate a virtual environment:

```bash
# Create virtual environment
python3 -m venv venv
   
# Activate on macOS/Linux
source venv/bin/activate
   
# Activate on Windows
# venv\Scripts\activate
```

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

1. Configure device credentials (optional, for SSH-based remote chip discovery):

   ```bash
   # Copy the example credentials file
   cp config/credentials.example.yaml config/credentials.yaml
   
   # Edit with your device SSH access information
   nano config/credentials.yaml
   ```

   * The `credentials.yaml` file is automatically excluded from git commits for security.

### Usage

Basic usage will be documented as the project develops.

## Development Status

This project is currently in early development.
