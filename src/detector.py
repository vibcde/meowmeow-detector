#!/usr/bin/env python3
"""
Gayfemboy/Twinkfemboy Malware Detection Script
Compatible with: macOS, Linux, and accessible routers
Version: 1.0
Purpose: Detect traces and indicators of Gayfemboy IoT botnet malware
"""

import os
import sys
import platform
import subprocess
import hashlib
import socket
import struct
import json
import re
import argparse
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import signal
import psutil
import logging

# Try to import YARA (optional but recommended)
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("Warning: YARA Python module not found. Install with: pip3 install yara-python")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gayfemboy_scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Known Gayfemboy indicators
KNOWN_HASHES = {
    'e85291d70a144ebe2842aeba2c77029762ca8ebfd36008b7bb83cda3e5d5d99d',
    'dd0c9a205b0c0f4c801c40e1663ca3989f9136e117d4dcb4f451474ceb67c3da',
    '6ca219e62ca53b64e4fdf7bff5c43a53681ed010cbaa688fa12de85a8f3de5e7',
    '47785b773808d7e1d2f1064b054e7e13b8b2ce9a35c68b926cd32c006c78f655',
    '915ee7620406946b859dd4a00f9862d77fba8b452aebee5d94587e66c1085c88',
    '1940296f59fb5fb29f52e96044eca25946f849183ceda4feb03e816b79fbaa81',
    '269259e5c2df6b51719fd227fa90668dd8400d7da6c0e816a8e8e03f88e06026',
    '87b6917034daa6f96f1f3813f88f2eb6d5e5c1b8f6b5b9ab337ab7065d4cb4c0'
}

MALICIOUS_DOMAINS = [
    'cross-compiling.org',
    'i-kiss-boys.com',
    'furry-femboys.top',
    'twinkfinder.nl',
    '3gipcam.com'
]

MALICIOUS_IPS = [
    '87.121.84.34',
    '220.158.234.135',
    '141.11.62.222',
    '149.50.96.114',
    '78.31.250.15'
]

SUSPICIOUS_PORTS = [47272, 1111, 2222, 3333, 2659, 1900]

SUSPICIOUS_STRINGS = [
    b'twinks :3',
    b'we gone now\n',
    b'meowmeow',
    b'whattheflip',
    b'xale',
    b'aale',
    b'mbe',
    b'ppc'
]

SUSPICIOUS_PROCESSES = [
    'xale', 'aale', 'mbe', 'mle', 'ppc',
    'a4le', 'a5le', 'a6le', 'a7le'
]

TERMINATED_TOOLS = [
    'tcpdump', 'strace', 'lsof', 'netstat', 
    'ss', 'top', 'htop', 'iotop'
]

class GayfemboyScanner:
    """Main scanner class for detecting Gayfemboy malware indicators"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings = []
        self.scan_stats = {
            'files_scanned': 0,
            'processes_checked': 0,
            'network_connections': 0,
            'suspicious_findings': 0,
            'malicious_findings': 0
        }
        self.os_type = platform.system().lower()
        
    def add_finding(self, severity: str, category: str, description: str, details: Dict = None):
        """Add a finding to the results"""
        finding = {
            'timestamp': datetime.datetime.now().isoformat(),
            'severity': severity,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            'category': category,
            'description': description,
            'details': details or {}
        }
        self.findings.append(finding)
        
        if severity in ['CRITICAL', 'HIGH']:
            self.scan_stats['malicious_findings'] += 1
        elif severity in ['MEDIUM', 'LOW']:
            self.scan_stats['suspicious_findings'] += 1
            
        logger.info(f"[{severity}] {category}: {description}")
        
    def check_file_hash(self, filepath: str) -> Optional[str]:
        """Calculate and check file hash against known malware"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                
            if file_hash in KNOWN_HASHES:
                self.add_finding(
                    'CRITICAL',
                    'KNOWN_MALWARE',
                    f'Known Gayfemboy malware detected: {filepath}',
                    {'hash': file_hash, 'file': filepath}
                )
                return file_hash
                
        except (IOError, OSError) as e:
            if self.verbose:
                logger.debug(f"Could not hash {filepath}: {e}")
        
        return None
        
    def scan_file_content(self, filepath: str):
        """Scan file content for suspicious strings"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read(1024 * 100)  # Read first 100KB
                
            for suspicious_string in SUSPICIOUS_STRINGS:
                if suspicious_string in content:
                    self.add_finding(
                        'HIGH',
                        'SUSPICIOUS_CONTENT',
                        f'Suspicious string found in {filepath}',
                        {'string': suspicious_string.decode('utf-8', errors='ignore'),
                         'file': filepath}
                    )
                    
            # Check for modified UPX headers
            if content[:4] == b'\x10\xF0\x00\x00' or content[:4] == b'YTS\x99' or content[:4] == b'1wom':
                self.add_finding(
                    'HIGH',
                    'MODIFIED_UPX',
                    f'Modified UPX packer detected in {filepath}',
                    {'file': filepath}
                )
                
        except (IOError, OSError) as e:
            if self.verbose:
                logger.debug(f"Could not scan {filepath}: {e}")
                
    def check_upx_modification(self, filepath: str) -> bool:
        """Check if file has modified UPX headers"""
        try:
            with open(filepath, 'rb') as f:
                header = f.read(256)
                
            # Check for modified UPX signatures
            if (b'\x10\xF0\x00\x00' in header or 
                b'YTS\x99' in header or 
                b'1wom' in header):
                return True
                
            # Check if it's UPX but with standard header (for comparison)
            if b'UPX!' in header:
                self.add_finding(
                    'LOW',
                    'STANDARD_UPX',
                    f'Standard UPX packed file found: {filepath}',
                    {'file': filepath}
                )
                
        except:
            pass
            
        return False
        
    def scan_directory(self, directory: str, recursive: bool = True):
        """Scan directory for suspicious files"""
        logger.info(f"Scanning directory: {directory}")
        
        path = Path(directory)
        if not path.exists():
            logger.error(f"Directory does not exist: {directory}")
            return
            
        pattern = '**/*' if recursive else '*'
        
        for filepath in path.glob(pattern):
            if filepath.is_file():
                self.scan_stats['files_scanned'] += 1
                
                # Check file name against suspicious patterns
                filename = filepath.name
                if filename in SUSPICIOUS_PROCESSES:
                    self.add_finding(
                        'HIGH',
                        'SUSPICIOUS_FILENAME',
                        f'Suspicious filename matches Gayfemboy pattern: {filepath}',
                        {'file': str(filepath)}
                    )
                    
                # Check file hash
                self.check_file_hash(str(filepath))
                
                # Check for ELF files and scan content
                try:
                    with open(filepath, 'rb') as f:
                        magic = f.read(4)
                    if magic == b'\x7fELF':
                        self.scan_file_content(str(filepath))
                        self.check_upx_modification(str(filepath))
                except:
                    pass
                    
    def check_running_processes(self):
        """Check for suspicious running processes"""
        logger.info("Checking running processes...")
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
                self.scan_stats['processes_checked'] += 1
                
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name']
                    
                    # Check for suspicious process names
                    if proc_name in SUSPICIOUS_PROCESSES:
                        self.add_finding(
                            'CRITICAL',
                            'SUSPICIOUS_PROCESS',
                            f'Suspicious process running: {proc_name}',
                            {'pid': proc_info['pid'], 
                             'name': proc_name,
                             'exe': proc_info.get('exe', 'unknown')}
                        )
                        
                    # Check if process executable is in temp directories
                    exe_path = proc_info.get('exe', '')
                    if exe_path and ('/tmp/' in exe_path or '/var/tmp/' in exe_path):
                        if any(s in exe_path for s in SUSPICIOUS_PROCESSES):
                            self.add_finding(
                                'HIGH',
                                'TEMP_EXECUTION',
                                f'Suspicious process running from temp: {exe_path}',
                                {'pid': proc_info['pid'], 'exe': exe_path}
                            )
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
        except Exception as e:
            logger.error(f"Error checking processes: {e}")
            
    def check_network_connections(self):
        """Check for suspicious network connections"""
        logger.info("Checking network connections...")
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                self.scan_stats['network_connections'] += 1
                
                # Check for suspicious ports
                if conn.laddr.port in SUSPICIOUS_PORTS:
                    self.add_finding(
                        'MEDIUM',
                        'SUSPICIOUS_PORT',
                        f'Connection on suspicious port: {conn.laddr.port}',
                        {'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                         'status': conn.status}
                    )
                    
                # Check for connections to malicious IPs
                if conn.raddr:
                    if conn.raddr.ip in MALICIOUS_IPS:
                        self.add_finding(
                            'CRITICAL',
                            'MALICIOUS_CONNECTION',
                            f'Connection to known malicious IP: {conn.raddr.ip}',
                            {'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                             'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                             'status': conn.status}
                        )
                        
                # Check for UDP binding on port 47272 (watchdog)
                if conn.type == socket.SOCK_DGRAM and conn.laddr.port == 47272:
                    self.add_finding(
                        'HIGH',
                        'WATCHDOG_PORT',
                        'Gayfemboy watchdog port detected (UDP 47272)',
                        {'local': f"{conn.laddr.ip}:{conn.laddr.port}"}
                    )
                    
        except Exception as e:
            logger.error(f"Error checking network connections: {e}")
            
    def check_dns_cache(self):
        """Check DNS cache for malicious domains"""
        logger.info("Checking DNS cache for malicious domains...")
        
        # Platform-specific DNS cache checking
        if self.os_type == 'darwin':  # macOS
            cmd = ['dscacheutil', '-cachedump']
        elif self.os_type == 'linux':
            # Try systemd-resolve first, then other methods
            cmd = ['systemd-resolve', '--statistics']
        else:
            logger.warning("DNS cache checking not supported on this platform")
            return
            
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.lower()
                
                for domain in MALICIOUS_DOMAINS:
                    if domain.lower() in output:
                        self.add_finding(
                            'HIGH',
                            'MALICIOUS_DNS',
                            f'Malicious domain found in DNS cache: {domain}',
                            {'domain': domain}
                        )
                        
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
            
    def check_hosts_file(self):
        """Check hosts file for malicious entries"""
        logger.info("Checking hosts file...")
        
        hosts_path = '/etc/hosts'
        if self.os_type == 'windows':
            hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
            
        try:
            with open(hosts_path, 'r') as f:
                content = f.read().lower()
                
            for domain in MALICIOUS_DOMAINS:
                if domain.lower() in content:
                    self.add_finding(
                        'MEDIUM',
                        'HOSTS_ENTRY',
                        f'Suspicious domain in hosts file: {domain}',
                        {'domain': domain}
                    )
                    
        except (IOError, OSError) as e:
            logger.warning(f"Could not read hosts file: {e}")
            
    def check_iptables_rules(self):
        """Check iptables for suspicious rules (Linux only)"""
        if self.os_type != 'linux':
            return
            
        logger.info("Checking iptables rules...")
        
        try:
            # Check if running as root
            if os.geteuid() != 0:
                logger.warning("Need root privileges to check iptables")
                return
                
            result = subprocess.run(
                ['iptables', '-L', '-n'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for rules related to malicious IPs
                for ip in MALICIOUS_IPS:
                    if ip in output:
                        self.add_finding(
                            'HIGH',
                            'IPTABLES_RULE',
                            f'Iptables rule contains malicious IP: {ip}',
                            {'ip': ip}
                        )
                        
                # Check for rules on suspicious ports
                for port in SUSPICIOUS_PORTS:
                    if f':{port}' in output or f'dpt:{port}' in output:
                        self.add_finding(
                            'MEDIUM',
                            'IPTABLES_PORT',
                            f'Iptables rule for suspicious port: {port}',
                            {'port': port}
                        )
                        
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
            
    def check_cron_jobs(self):
        """Check for suspicious cron jobs"""
        if self.os_type not in ['linux', 'darwin']:
            return
            
        logger.info("Checking cron jobs...")
        
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/',
            '/var/spool/cron/crontabs/'
        ]
        
        for location in cron_locations:
            try:
                if os.path.isfile(location):
                    with open(location, 'r') as f:
                        content = f.read()
                        self._check_cron_content(content, location)
                elif os.path.isdir(location):
                    for cron_file in Path(location).glob('*'):
                        if cron_file.is_file():
                            with open(cron_file, 'r') as f:
                                content = f.read()
                                self._check_cron_content(content, str(cron_file))
            except (IOError, OSError):
                pass
                
    def _check_cron_content(self, content: str, source: str):
        """Check cron content for suspicious entries"""
        suspicious_patterns = [
            'wget', 'curl', '/tmp/', 
            'xale', 'aale', 'mbe'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in content:
                for proc in SUSPICIOUS_PROCESSES:
                    if proc in content:
                        self.add_finding(
                            'HIGH',
                            'SUSPICIOUS_CRON',
                            f'Suspicious cron job found in {source}',
                            {'pattern': pattern, 'source': source}
                        )
                        break
                        
    def check_startup_items(self):
        """Check system startup items for persistence"""
        logger.info("Checking startup items...")
        
        if self.os_type == 'linux':
            startup_locations = [
                '/etc/rc.local',
                '/etc/init.d/',
                '/etc/systemd/system/',
                '/lib/systemd/system/'
            ]
        elif self.os_type == 'darwin':
            startup_locations = [
                '/Library/LaunchAgents/',
                '/Library/LaunchDaemons/',
                '~/Library/LaunchAgents/',
                '/System/Library/LaunchAgents/',
                '/System/Library/LaunchDaemons/'
            ]
        else:
            return
            
        for location in startup_locations:
            location = os.path.expanduser(location)
            try:
                if os.path.isfile(location):
                    with open(location, 'r') as f:
                        content = f.read()
                        for proc in SUSPICIOUS_PROCESSES:
                            if proc in content:
                                self.add_finding(
                                    'HIGH',
                                    'STARTUP_PERSISTENCE',
                                    f'Suspicious startup item: {location}',
                                    {'file': location, 'process': proc}
                                )
                elif os.path.isdir(location):
                    for item in Path(location).glob('*'):
                        if item.is_file():
                            try:
                                with open(item, 'r') as f:
                                    content = f.read()
                                    for proc in SUSPICIOUS_PROCESSES:
                                        if proc in content:
                                            self.add_finding(
                                                'HIGH',
                                                'STARTUP_PERSISTENCE',
                                                f'Suspicious startup item: {item}',
                                                {'file': str(item), 'process': proc}
                                            )
                            except:
                                pass
            except (IOError, OSError):
                pass
                
    def scan_logs(self):
        """Scan system logs for indicators"""
        logger.info("Scanning system logs...")
        
        log_locations = []
        
        if self.os_type == 'linux':
            log_locations = [
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/auth.log',
                '/var/log/secure'
            ]
        elif self.os_type == 'darwin':
            log_locations = [
                '/var/log/system.log',
                '/var/log/wifi.log'
            ]
            
        for log_file in log_locations:
            try:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        # Read last 10000 lines
                        lines = f.readlines()[-10000:]
                        content = ''.join(lines)
                        
                    # Check for terminated security tools
                    for tool in TERMINATED_TOOLS:
                        if f'killed {tool}' in content or f'terminated {tool}' in content:
                            self.add_finding(
                                'MEDIUM',
                                'TOOL_TERMINATION',
                                f'Security tool termination detected: {tool}',
                                {'tool': tool, 'log': log_file}
                            )
                            
                    # Check for suspicious process names in logs
                    for proc in SUSPICIOUS_PROCESSES:
                        if proc in content:
                            self.add_finding(
                                'MEDIUM',
                                'LOG_EVIDENCE',
                                f'Suspicious process in logs: {proc}',
                                {'process': proc, 'log': log_file}
                            )
                            
            except (IOError, OSError):
                pass
                
    def use_yara_rules(self, target_path: str):
        """Use YARA rules if available"""
        if not YARA_AVAILABLE:
            logger.warning("YARA module not available, skipping YARA scan")
            return
            
        logger.info("Running YARA scan...")
        
        # Default YARA rules path
        yara_rules_path = '/usr/local/share/yara-rules/malware/gayfemboy_detection.yar'
        
        if not os.path.exists(yara_rules_path):
            logger.warning(f"YARA rules not found at {yara_rules_path}")
            return
            
        try:
            rules = yara.compile(filepath=yara_rules_path)
            
            if os.path.isfile(target_path):
                matches = rules.match(target_path)
                if matches:
                    for match in matches:
                        self.add_finding(
                            'CRITICAL',
                            'YARA_MATCH',
                            f'YARA rule matched: {match.rule}',
                            {'file': target_path, 'rule': match.rule}
                        )
            elif os.path.isdir(target_path):
                for root, dirs, files in os.walk(target_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            matches = rules.match(filepath)
                            if matches:
                                for match in matches:
                                    self.add_finding(
                                        'CRITICAL',
                                        'YARA_MATCH',
                                        f'YARA rule matched: {match.rule}',
                                        {'file': filepath, 'rule': match.rule}
                                    )
                        except:
                            pass
                            
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
            
    def check_router_access(self, router_ip: str, username: str = 'admin', password: str = 'admin'):
        """Try to check router for infections (requires credentials)"""
        logger.info(f"Attempting to check router at {router_ip}...")
        
        # This is a basic check - in practice, you'd need proper router access
        try:
            # Check if router is reachable
            response = os.system(f"ping -c 1 {router_ip} > /dev/null 2>&1")
            if response != 0:
                logger.warning(f"Router at {router_ip} is not reachable")
                return
                
            # Try to connect to common management ports
            for port in [80, 443, 8080, 8443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((router_ip, port))
                    sock.close()
                    
                    if result == 0:
                        logger.info(f"Router management interface found on port {port}")
                        
                        # Warning about router security
                        self.add_finding(
                            'INFO',
                            'ROUTER_CHECK',
                            f'Router management accessible on {router_ip}:{port}',
                            {'ip': router_ip, 'port': port,
                             'note': 'Manual inspection recommended'}
                        )
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Router check error: {e}")
            
    def generate_report(self, output_file: str = None):
        """Generate scan report"""
        logger.info("Generating report...")
        
        report = {
            'scan_date': datetime.datetime.now().isoformat(),
            'system': {
                'os': platform.system(),
                'version': platform.version(),
                'hostname': socket.gethostname()
            },
            'statistics': self.scan_stats,
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'critical': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'high': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'medium': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'low': len([f for f in self.findings if f['severity'] == 'LOW']),
                'info': len([f for f in self.findings if f['severity'] == 'INFO'])
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        else:
            print("\n" + "="*50)
            print("SCAN REPORT")
            print("="*50)
            print(f"Scan Date: {report['scan_date']}")
            print(f"System: {report['system']['os']} {report['system']['version']}")
            print(f"\nStatistics:")
            for key, value in report['statistics'].items():
                print(f"  {key}: {value}")
            print(f"\nFindings Summary:")
            for key, value in report['summary'].items():
                if key != 'total_findings':
                    print(f"  {key.upper()}: {value}")
            print(f"  TOTAL: {report['summary']['total_findings']}")
            
            if self.findings:
                print("\n" + "="*50)
                print("DETAILED FINDINGS:")
                print("="*50)
                for finding in self.findings:
                    print(f"\n[{finding['severity']}] {finding['category']}")
                    print(f"  {finding['description']}")
                    if finding['details']:
                        for key, value in finding['details'].items():
                            print(f"    {key}: {value}")
                            
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Gayfemboy/Twinkfemboy Malware Detection Scanner'
    )
    parser.add_argument(
        '--scan-dir',
        default='/',
        help='Directory to scan (default: /)'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan (only common locations)'
    )
    parser.add_argument(
        '--no-yara',
        action='store_true',
        help='Skip YARA scanning'
    )
    parser.add_argument(
        '--router',
        help='Router IP address to check'
    )
    parser.add_argument(
        '--output',
        help='Output report to JSON file'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    print("""
╔══════════════════════════════════════════════════════╗
║   Gayfemboy/Twinkfemboy Malware Detection Scanner   ║
║            Defensive Security Tool v1.0              ║
╚══════════════════════════════════════════════════════╝
    """)
    
    scanner = GayfemboyScanner(verbose=args.verbose)
    
    # Check running processes
    scanner.check_running_processes()
    
    # Check network connections
    scanner.check_network_connections()
    
    # Check DNS and hosts
    scanner.check_dns_cache()
    scanner.check_hosts_file()
    
    # Check persistence mechanisms
    scanner.check_startup_items()
    scanner.check_cron_jobs()
    
    # Check system logs
    scanner.scan_logs()
    
    # Linux-specific checks
    if platform.system().lower() == 'linux':
        scanner.check_iptables_rules()
    
    # Directory scanning
    if args.quick:
        # Quick scan of common infection locations
        quick_dirs = ['/tmp', '/var/tmp', '/dev/shm', os.path.expanduser('~')]
        for directory in quick_dirs:
            if os.path.exists(directory):
                scanner.scan_directory(directory, recursive=True)
    else:
        # Full scan
        scanner.scan_directory(args.scan_dir, recursive=True)
    
    # YARA scanning
    if not args.no_yara and YARA_AVAILABLE:
        scanner.use_yara_rules(args.scan_dir)
    
    # Router checking
    if args.router:
        scanner.check_router_access(args.router)
    
    # Generate report
    scanner.generate_report(args.output)
    
    # Exit code based on findings
    if scanner.scan_stats['malicious_findings'] > 0:
        sys.exit(2)  # Malware detected
    elif scanner.scan_stats['suspicious_findings'] > 0:
        sys.exit(1)  # Suspicious activity detected
    else:
        sys.exit(0)  # Clean


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)