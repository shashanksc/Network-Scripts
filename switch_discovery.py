"""
Network Switch Discovery Script - Integrated Version
====================================================
Scans network and discovers switches using proven detection logic.
Compatible with Windows 10, Python 3.11+

Requirements:
    - Nmap installed and in PATH
    - pip install python-nmap

Usage:
    python switch_discovery_integrated.py --subnet 10.10.0.0/16
"""

import nmap
import csv
import argparse
import sys
from datetime import datetime


class SwitchDiscovery:
    """Main class for discovering network switches using Nmap."""
    
    # Keywords to identify switches (case-insensitive)
    switch_keywords = [
        "aruba",
        "officeconnect",
        "hpe",
        "hp switch",
        "3com",
        "instant on",
        "goahead-webs",
        "switch",
        "web user login",
        "lighttpd",
        "hp",
        "instant on",
    ]

    # Exclude devices with these words
    exclude_keywords = [
        "hikvision",
        "dvr",
        "nvr",
        "anydesk",
        "rtsp"
    ]
    
    # Common ports found on network switches
    SWITCH_PORTS = [22, 23, 80, 443, 161, 554, 4443, 8080, 8443]
    
    def __init__(self, subnet: str, output_file: str = 'discovered_switches.csv'):
        """
        Initialize the switch discovery scanner.
        
        Args:
            subnet: Network subnet to scan (e.g., '10.10.0.0/16')
            output_file: Output CSV filename
        """
        self.subnet = subnet
        self.output_file = output_file
        self.nm = nmap.PortScanner()
        self.found_switches = []
        
    def log(self, message: str):
        """Print timestamped log message to console."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")
    
    def text_contains_any(self, text, keywords):
        """Helper: check if any keyword is present in text."""
        if not text:
            return False
        text = text.lower()
        return any(kw in text for kw in keywords)
    
    def collect_host_text(self, host_data):
        """Collect all text information from a host for keyword matching."""
        full_text = ""
        
        # Get hostname
        if 'hostnames' in host_data:
            for hostname in host_data['hostnames']:
                if 'name' in hostname:
                    full_text += hostname['name'] + " "
        
        # Get OS detection
        if 'osmatch' in host_data:
            for osmatch in host_data['osmatch']:
                if 'name' in osmatch:
                    full_text += osmatch['name'] + " "
        
        # Get vendor info
        if 'vendor' in host_data:
            for mac, vendor in host_data['vendor'].items():
                full_text += vendor + " "
        
        # Get all service information
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                # Add service name
                if 'name' in port_data:
                    full_text += port_data['name'] + " "
                
                # Add product
                if 'product' in port_data:
                    full_text += port_data['product'] + " "
                
                # Add version
                if 'version' in port_data:
                    full_text += port_data['version'] + " "
                
                # Add extrainfo
                if 'extrainfo' in port_data:
                    full_text += port_data['extrainfo'] + " "
                
                # Add script output
                if 'script' in port_data:
                    for script_name, script_output in port_data['script'].items():
                        full_text += script_output + " "
        
        return full_text
    
    def scan_network(self):
        """
        Perform Nmap scan across the specified subnet.
        """
        self.log(f"Starting network scan on subnet: {self.subnet}")
        self.log(f"Scanning for common switch ports: {self.SWITCH_PORTS}")
        
        # Build port list for scanning
        port_list = ','.join(map(str, self.SWITCH_PORTS))
        
        try:
            self.log("Initiating Nmap scan (this may take several minutes)...")
            
            # Enhanced scan with script scanning for better device detection
            scan_args = f'-sV -sC --version-intensity 7 -T4 --max-retries 2 -p {port_list}'
            
            self.nm.scan(
                hosts=self.subnet,
                arguments=scan_args
            )
            
            self.log(f"Scan completed. Processing {len(self.nm.all_hosts())} hosts...")
            
        except nmap.PortScannerError as e:
            self.log(f"ERROR: Nmap scan failed - {e}")
            self.log("Make sure Nmap is installed and in your PATH")
            sys.exit(1)
        except Exception as e:
            self.log(f"ERROR: Unexpected error during scan - {e}")
            sys.exit(1)
    
    def analyze_results(self):
        """
        Analyze Nmap scan results to identify potential switches.
        Uses the proven detection logic from the XML parser.
        """
        self.log("Analyzing scan results for potential switches...")
        
        # Sort hosts by IP address numerically
        all_hosts = sorted(self.nm.all_hosts(), key=lambda ip: tuple(int(part) for part in ip.split('.')))
        
        for host in all_hosts:
            host_data = self.nm[host]
            
            # Skip hosts that are down
            if host_data.state() != 'up':
                continue
            
            # Collect all text information from host
            full_text = self.collect_host_text(host_data)
            
            # Filter: Skip if contains exclude keywords
            if self.text_contains_any(full_text, self.exclude_keywords):
                self.log(f"✗ Excluded device: {host}")
                continue
            
            # Check if contains switch keywords
            if self.text_contains_any(full_text, self.switch_keywords):
                self.found_switches.append((host, "", ""))
                self.log(f"✓ Switch found: {host}")
        
        self.log(f"Analysis complete. Found {len(self.found_switches)} switch(es)")
    
    def export_to_csv(self):
        """
        Export discovered switches to CSV file.
        """
        if not self.found_switches:
            self.log("No switches found to export")
            return
        
        self.log(f"Exporting results to {self.output_file}...")
        
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "Serial No.", "MAC"])
                writer.writerows(self.found_switches)
            
            self.log(f"✓ Successfully exported {len(self.found_switches)} switch(es) to {self.output_file}")
            
        except Exception as e:
            self.log(f"ERROR: Failed to export CSV - {e}")
    
    def run(self):
        """
        Execute the complete switch discovery process.
        """
        self.log("=" * 60)
        self.log("Network Switch Discovery - Integrated Version")
        self.log("=" * 60)
        
        # Step 1: Scan network
        self.scan_network()
        
        # Step 2: Analyze results
        self.analyze_results()
        
        # Step 3: Export to CSV
        self.export_to_csv()
        
        self.log("=" * 60)
        self.log("Discovery process completed!")
        self.log("=" * 60)
        
        # Print summary
        if self.found_switches:
            print("\n" + "=" * 60)
            print("DISCOVERED SWITCHES SUMMARY")
            print("=" * 60)
            for ip, serial, mac in self.found_switches:
                print(f"IP Address: {ip}")
            print("=" * 60)
            print(f"✅ Found {len(self.found_switches)} switches. Saved to '{self.output_file}'")
        else:
            print("⚠️ No switches found.")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Discover network switches using proven detection logic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python switch_discovery_integrated.py --subnet 10.10.0.0/16
    python switch_discovery_integrated.py --subnet 192.168.1.0/24 --output my_switches.csv
    
Notes:
    - Nmap must be installed and in your PATH
    - Larger subnets will take longer to scan
    - Run as Administrator for best results
    
Detection Keywords (Switch):
    - aruba, officeconnect, hpe, hp switch, 3com
    - instant on, goahead-webs, switch, web user login
    - lighttpd, hp

Exclusion Keywords:
    - hikvision, dvr, nvr, anydesk, rtsp
        """
    )
    
    parser.add_argument(
        '--subnet',
        required=True,
        help='Network subnet to scan (e.g., 10.10.0.0/16, 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--output',
        default='discovered_switches.csv',
        help='Output CSV filename (default: discovered_switches.csv)'
    )
    
    args = parser.parse_args()
    
    # Validate subnet format (basic check)
    import re
    subnet_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    if not re.match(subnet_pattern, args.subnet):
        print("ERROR: Invalid subnet format. Use CIDR notation (e.g., 10.10.0.0/16)")
        sys.exit(1)
    
    # Create and run discovery
    discovery = SwitchDiscovery(
        subnet=args.subnet,
        output_file=args.output
    )
    
    try:
        discovery.run()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting...")
        sys.exit(0)


if __name__ == '__main__':
    main()
