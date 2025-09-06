# Install YARA first
sudo bash yara-install.sh

# Run detection scan
sudo python3 detector.py --scan-dir / --output scan_report.json

# If infected, run remediation
sudo bash remediate.sh