#!/bin/bash

# Cross-Platform YARA Installation and Rule Setup Script
# Compatible with macOS and Ubuntu/Debian Linux
# Version: 1.0
# Purpose: Install YARA and configure detection rules for IoT malware threats

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
YARA_RULES_DIR="/usr/local/share/yara-rules"
YARA_CONFIG_DIR="/etc/yara"
BACKUP_DIR="/var/backups/yara-backup-$(date +%Y%m%d-%H%M%S)"
YARA_VERSION="4.5.0"  # Target version for source compilation if needed

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_message "$BLUE" "[INFO] Detected macOS"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]] || [[ "$ID" == "debian" ]]; then
            OS="ubuntu"
            print_message "$BLUE" "[INFO] Detected Ubuntu/Debian Linux"
        else
            print_message "$RED" "[ERROR] Unsupported Linux distribution: $ID"
            exit 1
        fi
    else
        print_message "$RED" "[ERROR] Unable to detect operating system"
        exit 1
    fi
}

# Function to check if running as root (for Linux)
check_privileges() {
    if [[ "$OS" == "ubuntu" ]] && [[ $EUID -ne 0 ]]; then
        print_message "$RED" "[ERROR] This script must be run as root on Linux"
        print_message "$YELLOW" "[INFO] Please run: sudo $0"
        exit 1
    fi
}

# Function to check for existing YARA installation
check_existing_yara() {
    if command -v yara &> /dev/null; then
        EXISTING_VERSION=$(yara --version 2>/dev/null | head -n1)
        print_message "$YELLOW" "[WARNING] YARA is already installed: $EXISTING_VERSION"
        read -p "Do you want to continue and potentially upgrade? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_message "$BLUE" "[INFO] Installation cancelled by user"
            exit 0
        fi
        
        # Backup existing configuration
        if [[ -d "$YARA_CONFIG_DIR" ]] || [[ -d "$YARA_RULES_DIR" ]]; then
            print_message "$BLUE" "[INFO] Backing up existing configuration to $BACKUP_DIR"
            mkdir -p "$BACKUP_DIR"
            
            if [[ -d "$YARA_CONFIG_DIR" ]]; then
                cp -r "$YARA_CONFIG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
            fi
            
            if [[ -d "$YARA_RULES_DIR" ]]; then
                cp -r "$YARA_RULES_DIR" "$BACKUP_DIR/" 2>/dev/null || true
            fi
        fi
    fi
}

# Function to install dependencies for Ubuntu
install_ubuntu_dependencies() {
    print_message "$BLUE" "[INFO] Installing dependencies for Ubuntu..."
    
    apt-get update
    apt-get install -y \
        automake \
        libtool \
        make \
        gcc \
        pkg-config \
        libssl-dev \
        libjansson-dev \
        libmagic-dev \
        curl \
        wget \
        git \
        python3-pip
}

# Function to install YARA on Ubuntu
install_yara_ubuntu() {
    print_message "$BLUE" "[INFO] Installing YARA on Ubuntu..."
    
    # Try to install from package manager first
    if apt-cache show yara &>/dev/null; then
        apt-get install -y yara
        print_message "$GREEN" "[SUCCESS] YARA installed from package manager"
    else
        print_message "$YELLOW" "[INFO] Package not found, compiling from source..."
        compile_yara_from_source
    fi
    
    # Install Python bindings
    pip3 install yara-python --break-system-packages 2>/dev/null || pip3 install yara-python
}

# Function to install YARA on macOS
install_yara_macos() {
    print_message "$BLUE" "[INFO] Installing YARA on macOS..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        print_message "$YELLOW" "[WARNING] Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    # Update Homebrew
    brew update
    
    # Install YARA
    if brew list yara &>/dev/null; then
        print_message "$BLUE" "[INFO] Upgrading existing YARA installation..."
        brew upgrade yara || true
    else
        brew install yara
    fi
    
    # Install Python bindings
    pip3 install yara-python --break-system-packages 2>/dev/null || pip3 install yara-python
    
    print_message "$GREEN" "[SUCCESS] YARA installed via Homebrew"
}

# Function to compile YARA from source (fallback option)
compile_yara_from_source() {
    print_message "$BLUE" "[INFO] Compiling YARA from source..."
    
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download YARA source
    wget "https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz" -O yara.tar.gz
    tar -zxf yara.tar.gz
    cd "yara-${YARA_VERSION}"
    
    # Compile and install
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet
    make
    make install
    ldconfig 2>/dev/null || true
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
    
    print_message "$GREEN" "[SUCCESS] YARA compiled and installed from source"
}

# Function to create YARA rules directory structure
create_rules_structure() {
    print_message "$BLUE" "[INFO] Creating YARA rules directory structure..."
    
    # Create directories
    mkdir -p "$YARA_RULES_DIR"/{malware,exploits,webshells,suspicious,custom}
    mkdir -p "$YARA_CONFIG_DIR"
    
    # Set appropriate permissions
    if [[ "$OS" == "ubuntu" ]]; then
        chmod 755 "$YARA_RULES_DIR"
        chmod 755 "$YARA_CONFIG_DIR"
    fi
}

# Function to install Gayfemboy detection rules
install_gayfemboy_rules() {
    print_message "$BLUE" "[INFO] Installing Gayfemboy/IoT malware detection rules..."
    
    cat > "$YARA_RULES_DIR/malware/gayfemboy_detection.yar" << 'EOF'
/*
    YARA Rules for Gayfemboy/Twinkfemboy IoT Botnet Detection
    Version: 1.0
    Last Updated: 2024
    
    These rules detect various components and variants of the Gayfemboy malware family
*/

import "pe"
import "elf"
import "hash"

rule Gayfemboy_Core_Detection {
    meta:
        description = "Detects Gayfemboy/Twinkfemboy IoT botnet core components"
        author = "Security Research Team"
        date = "2024-01-01"
        reference = "FortiGuard Labs Analysis"
        severity = "high"
        category = "botnet"
        
    strings:
        // Modified UPX headers
        $magic1 = { 10 F0 00 00 }
        $magic2 = "YTS\x99"
        $magic3 = "1wom"
        
        // Characteristic strings
        $display1 = "twinks :3"
        $display2 = "we gone now\n"
        $backdoor = "meowmeow"
        $trigger = "whattheflip"
        
        // Watchdog communication format
        $watchdog = /\<\d+\|\d+\>/
        
        // C2 domains
        $c2_1 = "cross-compiling.org"
        $c2_2 = "furry-femboys.top"
        $c2_3 = "i-kiss-boys.com"
        $c2_4 = "twinkfinder.nl"
        $c2_5 = "3gipcam.com"
        
        // Architecture identifiers
        $arch_x64 = "xale"
        $arch_arm64 = "aale"
        $arch_mips = "mbe"
        $arch_ppc = "ppc"
        
        // Process termination targets
        $kill1 = "tcpdump"
        $kill2 = "strace"
        $kill3 = "lsof"
        
        // Competitor scan patterns
        $scan1 = "/tmp/."
        $scan2 = "/bot."
        $scan3 = "dvrlocker"
        $scan4 = "/.ai"
        
    condition:
        (uint32(0) == 0x464C457F or uint32(0) == 0x7f454c46) and  // ELF header
        (
            any of ($magic*) or
            2 of ($display*, $backdoor, $trigger) or
            2 of ($c2_*) or
            2 of ($arch_*) or
            3 of ($kill*) or
            2 of ($scan*)
        )
}

rule Gayfemboy_Downloader_Script {
    meta:
        description = "Detects Gayfemboy downloader shell scripts"
        author = "Security Research Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $download1 = "wget http"
        $download2 = "curl -O"
        $binary1 = "xale"
        $binary2 = "aale"
        $binary3 = "mbe"
        $chmod = "chmod +x"
        $exec = "./"
        $cleanup = "rm -f"
        
    condition:
        filesize < 10KB and
        (
            ($download1 or $download2) and
            any of ($binary*) and
            $chmod and
            $exec
        )
}

rule Gayfemboy_Network_Commands {
    meta:
        description = "Detects Gayfemboy C2 command patterns"
        author = "Security Research Team"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        // Hex command patterns
        $cmd1 = { 6C 6C 6F 66 }  // Reset socket
        $cmd2 = { 55 55 55 55 }  // Sleep state
        $cmd3 = { 44 44 44 44 }  // Connection flag
        $cmd4 = { 11 11 11 11 }  // System info
        
        // UDP port binding
        $udp_port = { 00 00 B8 E8 }  // Port 47272 in network byte order
        
    condition:
        any of ($cmd*) and $udp_port
}

rule Gayfemboy_Exploit_Patterns {
    meta:
        description = "Detects exploitation patterns used by Gayfemboy"
        author = "Security Research Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        // CVE-2020-8515 (DrayTek)
        $exploit1 = "/cgi-bin/mainfunction.cgi"
        $exploit2 = "action=login"
        
        // CVE-2023-1389 (TP-Link)
        $exploit3 = "/goform/setDeviceSettings"
        
        // CVE-2024-7120 (Raisecom)
        $exploit4 = "/cgi-bin/login.cgi"
        
        // Generic router exploitation
        $telnet1 = "admin:admin"
        $telnet2 = "root:root"
        $telnet3 = "default:default"
        
    condition:
        2 of them
}

rule Gayfemboy_Persistence_Mechanism {
    meta:
        description = "Detects Gayfemboy persistence and anti-analysis techniques"
        author = "Security Research Team"
        date = "2024-01-01"
        severity = "medium"
        
    strings:
        // Process monitoring
        $proc1 = "/proc/"
        $proc2 = "/exe"
        $proc3 = "readlink"
        
        // Self-restart patterns
        $restart1 = "fork()"
        $restart2 = "execve"
        $restart3 = "clone"
        
        // Anti-analysis
        $anti1 = "ptrace"
        $anti2 = "PTRACE_TRACEME"
        $anti3 = { 50 E8 00 00 00 00 }  // 50ns delay pattern
        
    condition:
        (all of ($proc*) and any of ($restart*)) or
        2 of ($anti*)
}

rule Gayfemboy_DDoS_Module {
    meta:
        description = "Detects Gayfemboy DDoS attack modules"
        author = "Security Research Team"
        date = "2024-01-01"
        severity = "high"
        
    strings:
        $udp_flood = "UDP Flood"
        $syn_flood = "SYN Flood"
        $icmp_flood = "ICMP Flood"
        $tcp_flood = "TCP Flood"
        
        // Attack configuration
        $attack_size = { 00 00 40 00 }  // Common packet size
        $attack_port = { 00 50 }         // Port 80
        
    condition:
        2 of ($*_flood) or
        (any of ($*_flood) and all of ($attack_*))
}
EOF

    print_message "$GREEN" "[SUCCESS] Gayfemboy detection rules installed"
}

# Function to install additional community rules
install_community_rules() {
    print_message "$BLUE" "[INFO] Downloading community YARA rules..."
    
    # Create temporary directory for downloads
    TEMP_RULES=$(mktemp -d)
    cd "$TEMP_RULES"
    
    # Download Yara-Rules repository (contains many useful rules)
    if git clone --depth 1 https://github.com/Yara-Rules/rules.git 2>/dev/null; then
        cp -r rules/* "$YARA_RULES_DIR/" 2>/dev/null || true
        print_message "$GREEN" "[SUCCESS] Community rules downloaded"
    else
        print_message "$YELLOW" "[WARNING] Could not download community rules"
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_RULES"
}

# Function to create index file for all rules
create_rules_index() {
    print_message "$BLUE" "[INFO] Creating rules index file..."
    
    cat > "$YARA_RULES_DIR/index.yar" << 'EOF'
/*
    Master YARA Rules Index
    This file includes all rule files in the rules directory
*/

include "./malware/gayfemboy_detection.yar"

// Add additional rule includes as needed
// include "./exploits/*.yar"
// include "./webshells/*.yar"
// include "./suspicious/*.yar"
// include "./custom/*.yar"
EOF

    print_message "$GREEN" "[SUCCESS] Rules index created"
}

# Function to create YARA configuration file
create_yara_config() {
    print_message "$BLUE" "[INFO] Creating YARA configuration..."
    
    cat > "$YARA_CONFIG_DIR/yara.conf" << EOF
# YARA Configuration File
# Generated by installation script

# Default rules directory
rules_dir = $YARA_RULES_DIR

# Maximum number of threads
max_threads = 8

# Maximum string match length
max_match_length = 1000000

# Stack size (in MB)
stack_size = 16

# Fast matching mode
fast_matching = true

# Include all rules from index
include = $YARA_RULES_DIR/index.yar
EOF

    print_message "$GREEN" "[SUCCESS] Configuration file created"
}

# Function to create helper scripts
create_helper_scripts() {
    print_message "$BLUE" "[INFO] Creating helper scripts..."
    
    # Create scan script
    cat > /usr/local/bin/yara-scan << 'EOF'
#!/bin/bash
# YARA Quick Scan Script

RULES_DIR="/usr/local/share/yara-rules"
TARGET="${1:-.}"

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: yara-scan [target_directory]"
    echo "  target_directory: Directory to scan (default: current directory)"
    echo ""
    echo "Options:"
    echo "  --gayfemboy    Scan specifically for Gayfemboy malware"
    echo "  --full         Scan with all available rules"
    echo "  --help         Show this help message"
    exit 0
fi

if [ "$1" == "--gayfemboy" ]; then
    echo "[*] Scanning for Gayfemboy/IoT malware..."
    yara -r "$RULES_DIR/malware/gayfemboy_detection.yar" "${2:-.}"
elif [ "$1" == "--full" ]; then
    echo "[*] Running full scan with all rules..."
    yara -r "$RULES_DIR/index.yar" "${2:-.}"
else
    echo "[*] Scanning $TARGET for malware..."
    yara -r "$RULES_DIR/malware/gayfemboy_detection.yar" "$TARGET"
fi
EOF

    chmod +x /usr/local/bin/yara-scan
    
    # Create update script
    cat > /usr/local/bin/yara-update << 'EOF'
#!/bin/bash
# YARA Rules Update Script

echo "[*] Updating YARA rules..."
cd /usr/local/share/yara-rules

# Update community rules if git repo exists
if [ -d ".git" ]; then
    git pull origin master
    echo "[✓] Community rules updated"
fi

echo "[✓] Update complete"
EOF

    chmod +x /usr/local/bin/yara-update
    
    print_message "$GREEN" "[SUCCESS] Helper scripts created"
}

# Function to verify installation
verify_installation() {
    print_message "$BLUE" "[INFO] Verifying installation..."
    
    # Check YARA binary
    if ! command -v yara &> /dev/null; then
        print_message "$RED" "[ERROR] YARA binary not found in PATH"
        return 1
    fi
    
    # Check version
    INSTALLED_VERSION=$(yara --version 2>/dev/null | head -n1)
    print_message "$GREEN" "[SUCCESS] YARA installed: $INSTALLED_VERSION"
    
    # Test rules compilation
    if yara "$YARA_RULES_DIR/malware/gayfemboy_detection.yar" /dev/null &>/dev/null; then
        print_message "$GREEN" "[SUCCESS] Rules compile successfully"
    else
        print_message "$YELLOW" "[WARNING] Some rules may have compilation issues"
    fi
    
    # Check helper scripts
    if [[ -x /usr/local/bin/yara-scan ]]; then
        print_message "$GREEN" "[SUCCESS] Helper scripts installed"
    fi
    
    return 0
}

# Function to display usage information
show_usage() {
    cat << EOF

${GREEN}=== YARA Installation Complete ===${NC}

${BLUE}Installed Components:${NC}
  - YARA binary: $(which yara)
  - Rules directory: $YARA_RULES_DIR
  - Configuration: $YARA_CONFIG_DIR/yara.conf
  - Helper scripts: /usr/local/bin/yara-scan, /usr/local/bin/yara-update

${BLUE}Quick Usage:${NC}
  
  1. Scan current directory for Gayfemboy malware:
     ${YELLOW}yara-scan${NC}
  
  2. Scan specific directory:
     ${YELLOW}yara-scan /path/to/directory${NC}
  
  3. Run full scan with all rules:
     ${YELLOW}yara-scan --full /path/to/directory${NC}
  
  4. Use YARA directly:
     ${YELLOW}yara $YARA_RULES_DIR/malware/gayfemboy_detection.yar /path/to/file${NC}
  
  5. Update rules:
     ${YELLOW}yara-update${NC}

${BLUE}Python Integration:${NC}
  ${YELLOW}import yara
  rules = yara.compile('$YARA_RULES_DIR/malware/gayfemboy_detection.yar')
  matches = rules.match('/path/to/file')${NC}

${GREEN}Documentation:${NC} https://yara.readthedocs.io/

EOF
}

# Main installation flow
main() {
    print_message "$GREEN" "=== YARA Cross-Platform Installation Script ==="
    print_message "$BLUE" "[INFO] Starting installation process..."
    
    # Detect operating system
    detect_os
    
    # Check privileges
    check_privileges
    
    # Check for existing installation
    check_existing_yara
    
    # Install YARA based on OS
    if [[ "$OS" == "ubuntu" ]]; then
        install_ubuntu_dependencies
        install_yara_ubuntu
    elif [[ "$OS" == "macos" ]]; then
        install_yara_macos
    fi
    
    # Create directory structure
    create_rules_structure
    
    # Install rules
    install_gayfemboy_rules
    install_community_rules
    
    # Create configuration files
    create_rules_index
    create_yara_config
    
    # Create helper scripts
    create_helper_scripts
    
    # Verify installation
    if verify_installation; then
        print_message "$GREEN" "[SUCCESS] YARA installation completed successfully!"
        show_usage
    else
        print_message "$RED" "[ERROR] Installation completed with errors. Please check the output above."
        exit 1
    fi
}

# Run main function
main "$@"