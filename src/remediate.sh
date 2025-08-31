#!/bin/bash

# Gayfemboy Malware Remediation and Hardening Script
# Compatible with: macOS and Linux
# Version: 1.0
# Purpose: Remove Gayfemboy infections and harden system against reinfection

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging configuration
LOG_FILE="/var/log/gayfemboy_remediation_$(date +%Y%m%d_%H%M%S).log"
QUARANTINE_DIR="/var/quarantine/gayfemboy_$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="/var/backup/pre_remediation_$(date +%Y%m%d_%H%M%S)"

# Known malicious indicators
MALICIOUS_PROCESSES=(
    "xale" "aale" "mbe" "mle" "ppc"
    "a4le" "a5le" "a6le" "a7le"
)

MALICIOUS_FILES=(
    "/tmp/xale" "/tmp/aale" "/tmp/mbe"
    "/var/tmp/xale" "/var/tmp/aale" "/var/tmp/mbe"
    "/dev/shm/xale" "/dev/shm/aale" "/dev/shm/mbe"
)

MALICIOUS_DOMAINS=(
    "cross-compiling.org"
    "i-kiss-boys.com"
    "furry-femboys.top"
    "twinkfinder.nl"
    "3gipcam.com"
)

MALICIOUS_IPS=(
    "87.121.84.34"
    "220.158.234.135"
    "141.11.62.222"
    "149.50.96.114"
    "78.31.250.15"
)

# Detection flags
INFECTION_FOUND=0
PROCESSES_KILLED=0
FILES_QUARANTINED=0
RULES_ADDED=0

# Function to print messages
print_msg() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "$RED" "[ERROR] This script must be run as root"
        exit 1
    fi
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_msg "$BLUE" "[INFO] Detected macOS"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS="linux"
        DISTRO="$ID"
        print_msg "$BLUE" "[INFO] Detected Linux ($DISTRO)"
    else
        print_msg "$RED" "[ERROR] Unsupported operating system"
        exit 1
    fi
}

# Create necessary directories
setup_directories() {
    print_msg "$BLUE" "[INFO] Setting up directories..."
    
    mkdir -p "$QUARANTINE_DIR"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$QUARANTINE_DIR"
    chmod 700 "$BACKUP_DIR"
    
    # Create log file
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
}

# Kill malicious processes
kill_malicious_processes() {
    print_msg "$YELLOW" "[SCAN] Searching for malicious processes..."
    
    for process in "${MALICIOUS_PROCESSES[@]}"; do
        # Find and kill processes
        if [[ "$OS" == "linux" ]]; then
            pids=$(pgrep -f "$process" 2>/dev/null || true)
        else
            pids=$(pgrep "$process" 2>/dev/null || true)
        fi
        
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                print_msg "$RED" "[FOUND] Malicious process detected: $process (PID: $pid)"
                
                # Get process details before killing
                if [[ "$OS" == "linux" ]]; then
                    exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
                    cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ' || echo "unknown")
                else
                    exe_path=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                    cmdline=$(ps -p "$pid" -o command= 2>/dev/null || echo "unknown")
                fi
                
                print_msg "$BLUE" "[INFO] Process details: exe=$exe_path, cmd=$cmdline"
                
                # Kill the process
                kill -9 "$pid" 2>/dev/null && {
                    print_msg "$GREEN" "[KILLED] Process $process (PID: $pid) terminated"
                    ((PROCESSES_KILLED++))
                    INFECTION_FOUND=1
                } || {
                    print_msg "$YELLOW" "[WARNING] Could not kill process $pid"
                }
            done
        fi
    done
    
    # Also check for processes binding to port 47272 (watchdog)
    if command -v netstat &>/dev/null; then
        watchdog_pids=$(netstat -nlup 2>/dev/null | grep ':47272' | awk '{print $NF}' | cut -d'/' -f1 | grep -E '^[0-9]+$' || true)
        
        for pid in $watchdog_pids; do
            print_msg "$RED" "[FOUND] Process binding to watchdog port 47272 (PID: $pid)"
            kill -9 "$pid" 2>/dev/null && {
                print_msg "$GREEN" "[KILLED] Watchdog process terminated"
                ((PROCESSES_KILLED++))
                INFECTION_FOUND=1
            }
        done
    fi
}

# Quarantine malicious files
quarantine_files() {
    print_msg "$YELLOW" "[SCAN] Searching for malicious files..."
    
    # Check known malicious file locations
    for file in "${MALICIOUS_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            print_msg "$RED" "[FOUND] Malicious file: $file"
            
            # Calculate hash for logging
            file_hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
            print_msg "$BLUE" "[INFO] File hash: $file_hash"
            
            # Move to quarantine
            mv "$file" "$QUARANTINE_DIR/" 2>/dev/null && {
                print_msg "$GREEN" "[QUARANTINED] File moved to quarantine: $file"
                ((FILES_QUARANTINED++))
                INFECTION_FOUND=1
            } || {
                print_msg "$YELLOW" "[WARNING] Could not quarantine $file"
            }
        fi
    done
    
    # Search for suspicious files in temp directories
    temp_dirs=("/tmp" "/var/tmp" "/dev/shm")
    
    for dir in "${temp_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            print_msg "$BLUE" "[INFO] Scanning $dir..."
            
            # Look for ELF files with suspicious names
            find "$dir" -type f -executable 2>/dev/null | while read -r file; do
                filename=$(basename "$file")
                
                # Check if file matches suspicious patterns
                for pattern in "${MALICIOUS_PROCESSES[@]}"; do
                    if [[ "$filename" == *"$pattern"* ]]; then
                        print_msg "$RED" "[FOUND] Suspicious file: $file"
                        
                        # Move to quarantine
                        mv "$file" "$QUARANTINE_DIR/" 2>/dev/null && {
                            print_msg "$GREEN" "[QUARANTINED] $file"
                            ((FILES_QUARANTINED++))
                            INFECTION_FOUND=1
                        }
                        break
                    fi
                done
                
                # Check for files with "twinks :3" string
                if grep -q "twinks :3" "$file" 2>/dev/null; then
                    print_msg "$RED" "[FOUND] File contains malware signature: $file"
                    mv "$file" "$QUARANTINE_DIR/" 2>/dev/null && {
                        print_msg "$GREEN" "[QUARANTINED] $file"
                        ((FILES_QUARANTINED++))
                        INFECTION_FOUND=1
                    }
                fi
            done
        fi
    done
}

# Clean cron jobs
clean_cron_jobs() {
    print_msg "$YELLOW" "[SCAN] Checking cron jobs..."
    
    cron_files=(
        "/etc/crontab"
        "/var/spool/cron/root"
        "/var/spool/cron/crontabs/root"
    )
    
    for cron_file in "${cron_files[@]}"; do
        if [[ -f "$cron_file" ]]; then
            # Backup original
            cp "$cron_file" "$BACKUP_DIR/$(basename $cron_file).backup" 2>/dev/null || true
            
            # Check for suspicious entries
            for pattern in "${MALICIOUS_PROCESSES[@]}"; do
                if grep -q "$pattern" "$cron_file" 2>/dev/null; then
                    print_msg "$RED" "[FOUND] Suspicious cron entry in $cron_file"
                    
                    # Remove the malicious lines
                    sed -i.bak "/$pattern/d" "$cron_file"
                    print_msg "$GREEN" "[CLEANED] Removed malicious cron entries"
                    INFECTION_FOUND=1
                fi
            done
        fi
    done
    
    # Check cron.d directory
    if [[ -d "/etc/cron.d" ]]; then
        for file in /etc/cron.d/*; do
            if [[ -f "$file" ]]; then
                for pattern in "${MALICIOUS_PROCESSES[@]}"; do
                    if grep -q "$pattern" "$file" 2>/dev/null; then
                        print_msg "$RED" "[FOUND] Suspicious cron file: $file"
                        mv "$file" "$QUARANTINE_DIR/" 2>/dev/null && {
                            print_msg "$GREEN" "[QUARANTINED] Cron file: $file"
                            INFECTION_FOUND=1
                        }
                    fi
                done
            fi
        done
    fi
}

# Clean startup items
clean_startup_items() {
    print_msg "$YELLOW" "[SCAN] Checking startup items..."
    
    if [[ "$OS" == "linux" ]]; then
        # Check systemd services
        if command -v systemctl &>/dev/null; then
            for pattern in "${MALICIOUS_PROCESSES[@]}"; do
                services=$(systemctl list-unit-files | grep "$pattern" | awk '{print $1}' || true)
                for service in $services; do
                    print_msg "$RED" "[FOUND] Suspicious service: $service"
                    systemctl stop "$service" 2>/dev/null
                    systemctl disable "$service" 2>/dev/null
                    
                    # Find and quarantine service file
                    service_file=$(systemctl show -p FragmentPath "$service" | cut -d'=' -f2)
                    if [[ -f "$service_file" ]]; then
                        mv "$service_file" "$QUARANTINE_DIR/" 2>/dev/null && {
                            print_msg "$GREEN" "[QUARANTINED] Service file: $service_file"
                            INFECTION_FOUND=1
                        }
                    fi
                done
            done
            
            systemctl daemon-reload 2>/dev/null
        fi
        
        # Check rc.local
        if [[ -f "/etc/rc.local" ]]; then
            cp "/etc/rc.local" "$BACKUP_DIR/rc.local.backup" 2>/dev/null || true
            
            for pattern in "${MALICIOUS_PROCESSES[@]}"; do
                if grep -q "$pattern" "/etc/rc.local" 2>/dev/null; then
                    print_msg "$RED" "[FOUND] Suspicious entry in rc.local"
                    sed -i.bak "/$pattern/d" "/etc/rc.local"
                    print_msg "$GREEN" "[CLEANED] rc.local"
                    INFECTION_FOUND=1
                fi
            done
        fi
        
    elif [[ "$OS" == "macos" ]]; then
        # Check LaunchAgents and LaunchDaemons
        launch_dirs=(
            "/Library/LaunchAgents"
            "/Library/LaunchDaemons"
            "$HOME/Library/LaunchAgents"
        )
        
        for dir in "${launch_dirs[@]}"; do
            if [[ -d "$dir" ]]; then
                for file in "$dir"/*.plist; do
                    if [[ -f "$file" ]]; then
                        for pattern in "${MALICIOUS_PROCESSES[@]}"; do
                            if grep -q "$pattern" "$file" 2>/dev/null; then
                                print_msg "$RED" "[FOUND] Suspicious launch item: $file"
                                
                                # Unload the service
                                launchctl unload "$file" 2>/dev/null || true
                                
                                # Quarantine the file
                                mv "$file" "$QUARANTINE_DIR/" 2>/dev/null && {
                                    print_msg "$GREEN" "[QUARANTINED] Launch item: $file"
                                    INFECTION_FOUND=1
                                }
                            fi
                        done
                    fi
                done
            fi
        done
    fi
}

# Block malicious domains and IPs
block_malicious_network() {
    print_msg "$YELLOW" "[HARDENING] Blocking malicious network endpoints..."
    
    # Update hosts file
    print_msg "$BLUE" "[INFO] Updating hosts file..."
    
    # Backup hosts file
    cp /etc/hosts "$BACKUP_DIR/hosts.backup" 2>/dev/null || true
    
    # Add blocking entries
    echo "" >> /etc/hosts
    echo "# Gayfemboy malware blocking - Added by remediation script" >> /etc/hosts
    
    for domain in "${MALICIOUS_DOMAINS[@]}"; do
        if ! grep -q "$domain" /etc/hosts 2>/dev/null; then
            echo "0.0.0.0 $domain" >> /etc/hosts
            echo "::0 $domain" >> /etc/hosts
            print_msg "$GREEN" "[BLOCKED] Domain: $domain"
            ((RULES_ADDED++))
        fi
    done
    
    # Configure firewall rules
    if [[ "$OS" == "linux" ]]; then
        if command -v iptables &>/dev/null; then
            print_msg "$BLUE" "[INFO] Adding iptables rules..."
            
            # Save current rules
            iptables-save > "$BACKUP_DIR/iptables.backup" 2>/dev/null || true
            
            # Block malicious IPs
            for ip in "${MALICIOUS_IPS[@]}"; do
                iptables -A OUTPUT -d "$ip" -j DROP 2>/dev/null && {
                    print_msg "$GREEN" "[BLOCKED] IP: $ip (outbound)"
                    ((RULES_ADDED++))
                }
                iptables -A INPUT -s "$ip" -j DROP 2>/dev/null && {
                    print_msg "$GREEN" "[BLOCKED] IP: $ip (inbound)"
                    ((RULES_ADDED++))
                }
            done
            
            # Block suspicious ports
            iptables -A INPUT -p udp --dport 47272 -j DROP 2>/dev/null && {
                print_msg "$GREEN" "[BLOCKED] UDP port 47272 (watchdog)"
                ((RULES_ADDED++))
            }
            
            # Save rules
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            
        elif command -v ufw &>/dev/null; then
            print_msg "$BLUE" "[INFO] Adding UFW rules..."
            
            for ip in "${MALICIOUS_IPS[@]}"; do
                ufw deny from "$ip" 2>/dev/null && {
                    print_msg "$GREEN" "[BLOCKED] IP: $ip"
                    ((RULES_ADDED++))
                }
            done
        fi
        
    elif [[ "$OS" == "macos" ]]; then
        # Use pfctl on macOS
        if [[ -f "/etc/pf.conf" ]]; then
            print_msg "$BLUE" "[INFO] Adding pfctl rules..."
            
            # Backup pf.conf
            cp /etc/pf.conf "$BACKUP_DIR/pf.conf.backup" 2>/dev/null || true
            
            # Create blocking rules
            echo "" >> /etc/pf.conf
            echo "# Gayfemboy malware blocking" >> /etc/pf.conf
            
            for ip in "${MALICIOUS_IPS[@]}"; do
                echo "block drop from any to $ip" >> /etc/pf.conf
                echo "block drop from $ip to any" >> /etc/pf.conf
                print_msg "$GREEN" "[BLOCKED] IP: $ip"
                ((RULES_ADDED++))
            done
            
            # Reload pfctl
            pfctl -f /etc/pf.conf 2>/dev/null || true
            pfctl -e 2>/dev/null || true
        fi
    fi
}

# Harden system security
harden_system() {
    print_msg "$YELLOW" "[HARDENING] Applying security hardening measures..."
    
    # Disable unnecessary services
    if [[ "$OS" == "linux" ]]; then
        # Disable telnet if present
        if command -v systemctl &>/dev/null; then
            systemctl stop telnet.socket 2>/dev/null || true
            systemctl disable telnet.socket 2>/dev/null || true
            systemctl stop telnetd 2>/dev/null || true
            systemctl disable telnetd 2>/dev/null || true
        fi
        
        # Set secure permissions on temp directories
        chmod 1777 /tmp 2>/dev/null || true
        chmod 1777 /var/tmp 2>/dev/null || true
        
        # Enable process accounting if available
        if command -v accton &>/dev/null; then
            touch /var/log/pacct
            accton /var/log/pacct 2>/dev/null || true
            print_msg "$GREEN" "[HARDENED] Process accounting enabled"
        fi
        
        # Set kernel parameters for security
        if [[ -f /etc/sysctl.conf ]]; then
            cp /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.backup" 2>/dev/null || true
            
            # Add security parameters
            cat >> /etc/sysctl.conf << EOF

# Security hardening - Added by Gayfemboy remediation
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
kernel.randomize_va_space = 2
EOF
            
            # Apply settings
            sysctl -p 2>/dev/null || true
            print_msg "$GREEN" "[HARDENED] Kernel parameters updated"
        fi
    fi
    
    # Create monitoring script
    cat > /usr/local/bin/gayfemboy_monitor.sh << 'EOF'
#!/bin/bash
# Gayfemboy monitoring script
# Checks for reinfection indicators

ALERT_FILE="/var/log/gayfemboy_alerts.log"

check_processes() {
    for proc in xale aale mbe mle ppc; do
        if pgrep -f "$proc" >/dev/null 2>&1; then
            echo "$(date): ALERT - Suspicious process detected: $proc" >> "$ALERT_FILE"
            return 1
        fi
    done
    return 0
}

check_ports() {
    if netstat -an | grep -q ':47272'; then
        echo "$(date): ALERT - Suspicious port 47272 in use" >> "$ALERT_FILE"
        return 1
    fi
    return 0
}

# Run checks
check_processes
check_ports

# Alert if issues found
if [[ -s "$ALERT_FILE" ]]; then
    tail -n 10 "$ALERT_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/gayfemboy_monitor.sh
    
    # Add to cron for regular monitoring
    if ! grep -q "gayfemboy_monitor" /etc/crontab 2>/dev/null; then
        echo "*/15 * * * * root /usr/local/bin/gayfemboy_monitor.sh" >> /etc/crontab
        print_msg "$GREEN" "[HARDENED] Monitoring script installed"
    fi
}

# Reset security tools
restore_security_tools() {
    print_msg "$YELLOW" "[RESTORE] Attempting to restore security tools..."
    
    # List of security tools that may have been terminated
    security_tools=(
        "tcpdump" "wireshark" "tshark"
        "netstat" "ss" "lsof"
        "top" "htop" "iotop"
        "strace" "ltrace"
    )
    
    # Check if tools are available and working
    for tool in "${security_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            print_msg "$GREEN" "[OK] $tool is available"
        else
            print_msg "$YELLOW" "[MISSING] $tool not found - consider reinstalling"
        fi
    done
}

# Generate remediation report
generate_report() {
    print_msg "$BLUE" "[INFO] Generating remediation report..."
    
    REPORT_FILE="/var/log/gayfemboy_remediation_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$REPORT_FILE" << EOF
================================================================================
                    GAYFEMBOY MALWARE REMEDIATION REPORT
================================================================================

Date: $(date)
System: $(uname -a)
Hostname: $(hostname)

INFECTION STATUS:
-----------------
Infection Found: $([ $INFECTION_FOUND -eq 1 ] && echo "YES" || echo "NO")
Processes Killed: $PROCESSES_KILLED
Files Quarantined: $FILES_QUARANTINED
Firewall Rules Added: $RULES_ADDED

ACTIONS TAKEN:
--------------
1. Killed malicious processes
2. Quarantined suspicious files
3. Cleaned cron jobs
4. Removed startup items
5. Blocked malicious domains and IPs
6. Applied system hardening
7. Installed monitoring script

QUARANTINE LOCATION:
--------------------
$QUARANTINE_DIR

BACKUP LOCATION:
----------------
$BACKUP_DIR

LOG FILE:
---------
$LOG_FILE

RECOMMENDATIONS:
----------------
1. Change all system passwords
2. Update all software to latest versions
3. Review quarantined files before deletion
4. Monitor system for unusual activity
5. Consider full system reinstall if critical system

MONITORING:
-----------
Monitor script installed at: /usr/local/bin/gayfemboy_monitor.sh
Alerts will be logged to: /var/log/gayfemboy_alerts.log

================================================================================
EOF
    
    print_msg "$GREEN" "[COMPLETE] Report saved to: $REPORT_FILE"
    cat "$REPORT_FILE"
}

# Main execution
main() {
    echo ""
    echo "======================================================"
    echo "   GAYFEMBOY MALWARE REMEDIATION & HARDENING TOOL    "
    echo "======================================================"
    echo ""
    
    # Check for root privileges
    check_root
    
    # Detect OS
    detect_os
    
    # Setup directories
    setup_directories
    
    print_msg "$MAGENTA" "[START] Beginning remediation process..."
    
    # Execute remediation steps
    kill_malicious_processes
    quarantine_files
    clean_cron_jobs
    clean_startup_items
    block_malicious_network
    harden_system
    restore_security_tools
    
    # Generate report
    generate_report
    
    # Final status
    echo ""
    if [[ $INFECTION_FOUND -eq 1 ]]; then
        print_msg "$RED" "[INFECTED] System was infected with Gayfemboy malware"
        print_msg "$GREEN" "[CLEANED] Remediation completed - Review report for details"
        print_msg "$YELLOW" "[WARNING] Monitor system closely for reinfection"
    else
        print_msg "$GREEN" "[CLEAN] No active Gayfemboy infections detected"
        print_msg "$BLUE" "[HARDENED] Security measures applied as prevention"
    fi
    
    echo ""
    print_msg "$MAGENTA" "[DONE] Remediation process complete"
    echo ""
}

# Handle interrupts
trap 'print_msg "$RED" "[INTERRUPT] Script interrupted by user"; exit 130' INT TERM

# Run main function
main "$@"