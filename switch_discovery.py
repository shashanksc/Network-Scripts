#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import csv
import argparse
import subprocess
import sys
import time
from datetime import datetime


class SwitchParser:

    SWITCH_KEYWORDS = [
        "switch", "managed switch", "web switch", "cisco", "catalyst",
        "aruba", "officeconnect", "hpe", "hewlett packard", "hp switch",
        "procurve", "j9850a", "tp-link", "tplink", "tl-sg", "powerconnect",
        "dell switch", "netgear switch", "vlan", "layer 2", "layer 3",
        "switching", "ruckus"
    ]

    STRONG_TITLES = [
        "web switch", "aruba", "hp", "switch", "procurve", "officeconnect", "1920", "24G", "1930"
    ]

    EXCLUDE_KEYWORDS = [
        "hikvision", "dvr", "nvr", "ip camera", "camera", "onvif",
        "net video", "matrixipcamera", "rtsp", "webcam", "xmeye", "gsoap"
    ]

    MGMT_PORTS = {22, 23, 80, 443, 161, 8080, 8443, 4343, 4443}

    def __init__(self, xml_file=None, output_csv="discovered_switches.csv", subnet=None):
       
        self.xml_file = xml_file
        self.output_csv = output_csv
        self.subnet = subnet
        self.found_switches = []

    def check_nmap(self):
        try:
            result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print("✓", result.stdout.split("\n")[0])
                return True
            return False
        except FileNotFoundError:
            print("❌ nmap not installed")
            return False

    def run_scan(self):
        if not self.check_nmap():
            return False

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_subnet = self.subnet.replace("/", "_").replace(".", "_")
        self.xml_file = f"nmap_scan_{safe_subnet}_{timestamp}.xml"

        print("\n🔍 Starting scan:", self.subnet)
        print("📄 XML:", self.xml_file)

        cmd = [
            "nmap", "-sV", "-sC", "-T4", "--version-intensity", "7",
            "-p", "22,23,80,443,161,8080,8443,4343,4443",
            "-oX", self.xml_file, self.subnet
        ]

        start = time.time()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            if "Nmap scan report" in line:
                print(" ", line.strip())

        process.wait()
        elapsed = time.time() - start

        if process.returncode == 0:
            print(f"\n✅ Scan completed in {elapsed:.1f}s")
            return True
        print("❌ Scan failed")
        return False

    def contains_any(self, text, keywords):
        text = text.lower()
        for kw in keywords:
            if kw.lower() in text:
                return True
        return False

    def extract_host_info(self, host):
        info = {"ip": "", "hostname": "", "vendor": "", "open_ports": [], "text_parts": []}
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                info["ip"] = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                info["vendor"] = addr.get("vendor", "")

        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                info["hostname"] = hn.get("name", "")

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                try:
                    portid = int(port.get("portid"))
                    info["open_ports"].append(portid)
                except:
                    continue

                service = port.find("service")
                if service is not None:
                    for attr in ["name", "product", "version", "extrainfo", "devicetype", "ostype"]:
                        value = service.get(attr)
                        if value:
                            info["text_parts"].append(value)

                for script in port.findall("script"):
                    output = script.get("output")
                    if output:
                        info["text_parts"].append(output)
                    for elem in script.iter():
                        if elem.text and elem.text.strip():
                            info["text_parts"].append(elem.text.strip())
                        for value in elem.attrib.values():
                            if value:
                                info["text_parts"].append(str(value))

        info["text_parts"].append(info["hostname"])
        info["text_parts"].append(info["vendor"])

        cleaned = []
        for item in info["text_parts"]:
            if not item:
                continue
            item = str(item).strip().lower()
            if len(item) > 5000:
                continue
            cleaned.append(item)

        info["full_text"] = " ".join(cleaned)
        return info

    def classify_switch(self, host_info):
        text = host_info["full_text"]
        ports = set(host_info["open_ports"])
        score = 0
        reasons = []

        for kw in self.EXCLUDE_KEYWORDS:
            if kw in text:
                score -= 100
                reasons.append(f"exclude:{kw}")

        for kw in self.SWITCH_KEYWORDS:
            if kw in text:
                score += 40
                reasons.append(f"keyword:{kw}")
                break

        for kw in self.STRONG_TITLES:
            if kw in text:
                score += 30
                reasons.append(f"title:{kw}")
                break

        if 22 in ports:
            score += 15
            reasons.append("ssh")
        if 23 in ports:
            score += 20
            reasons.append("telnet")
        if 80 in ports or 443 in ports:
            score += 15
            reasons.append("web")
        if 161 in ports:
            score += 25
            reasons.append("snmp")

        mgmt_count = len(ports.intersection(self.MGMT_PORTS))
        if mgmt_count >= 3:
            score += 20
            reasons.append("multi-mgmt")

        if "camera" in text or "onvif" in text or "net video" in text:
            score -= 100
            reasons.append("camera-device")

        if score >= 80:
            return True, "high", score, reasons
        elif score >= 50:
            return True, "medium", score, reasons
        elif score >= 35:
            return True, "low", score, reasons
        return False, "excluded", score, reasons

    def parse(self):
        print("\n" + "=" * 80)
        print("PARSING RESULTS")
        print("=" * 80)

        tree = ET.parse(self.xml_file)
        root = tree.getroot()
        total_hosts = 0

        for host in root.findall("host"):
            total_hosts += 1
            host_info = self.extract_host_info(host)
            if not host_info["ip"]:
                continue

            is_switch, confidence, score, reasons = self.classify_switch(host_info)
            print(f"DEBUG {host_info['ip']} | score={score} | ports={host_info['open_ports']} | {', '.join(reasons)}")

            if is_switch:
                self.found_switches.append({
                    "ip": host_info["ip"],
                    "hostname": host_info["hostname"],
                    "vendor": host_info["vendor"],
                    "ports": ",".join(map(str, host_info["open_ports"])),
                    "confidence": confidence,
                    "score": score,
                    "reasons": ", ".join(reasons),
                })
                print(f"✓ Switch found: {host_info['ip']} ({confidence}) score={score}")

        print(f"\n📊 Scanned {total_hosts} hosts, found {len(self.found_switches)} switches")

    def export_csv(self):
        if not self.found_switches:
            print("⚠️ No switches found")
            return

        
        headers = ["switch_ip", "Hostname", "Vendor", "Open Ports", "Confidence", "Score", "Reasons"]

        with open(self.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for sw in self.found_switches:
                writer.writerow({
                    "switch_ip": sw["ip"],
                    "Hostname": sw["hostname"],
                    "Vendor": sw["vendor"],
                    "Open Ports": sw["ports"],
                    "Confidence": sw["confidence"],
                    "Score": sw["score"],
                    "Reasons": sw["reasons"],
                })

        print(f"\n✅ CSV exported: {self.output_csv}")

    def summary(self):
        print("\n" + "=" * 80)
        print("DISCOVERED SWITCHES")
        print("=" * 80)
        for sw in self.found_switches:
            print(f"\nIP: {sw['ip']}\nPorts: {sw['ports']}\nConfidence: {sw['confidence']}\nScore: {sw['score']}\nReasons: {sw['reasons']}")
        print("=" * 80)


import ipaddress

def scan_range(start_subnet: str, end_subnet: str, output_csv: str = "discovered_switches.csv"):
    """
    Scan a range of subnets and aggregate results into a single CSV.
    
    Args:
        start_subnet: Starting subnet in CIDR notation, e.g. "10.10.21.0/24"
        end_subnet:   Ending subnet in CIDR notation,   e.g. "10.10.40.0/24"
        output_csv:   Path to the aggregated output CSV file
    """
    start_net = ipaddress.ip_network(start_subnet, strict=False)
    end_net   = ipaddress.ip_network(end_subnet,   strict=False)

    if start_net.prefixlen != end_net.prefixlen:
        raise ValueError("Start and end subnets must have the same prefix length.")

    # Build the list of all subnets in range (inclusive)
    supernet   = start_net.supernet(new_prefix=start_net.prefixlen - 1)
    all_nets   = list(supernet.subnets(new_prefix=start_net.prefixlen))
    subnets_in_range = [
        str(net) for net in all_nets
        if start_net.network_address <= net.network_address <= end_net.network_address
    ]

    print(f"[*] Scanning {len(subnets_in_range)} subnets from {start_subnet} to {end_subnet}")

    all_switches = []   # accumulate rows across all scans

    for subnet in subnets_in_range:
        print(f"\n[+] Scanning subnet: {subnet}")
        sp = SwitchParser(subnet=subnet, output_csv=None)   # suppress per-subnet CSV
        if sp.run_scan():
            sp.parse()
            sp.summary()
            all_switches.extend(sp.switches)          
        else:
            print(f"[-] No results for {subnet}")

    # Write one combined CSV
    if all_switches:
        import csv
        keys = all_switches[0].keys() if isinstance(all_switches[0], dict) else vars(all_switches[0]).keys()
        with open(output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(
                row if isinstance(row, dict) else vars(row)
                for row in all_switches
            )
        print(f"\n[✓] Aggregated {len(all_switches)} switches → {output_csv}")
    else:
        print("\n[!] No switches found across the entire range.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("xml", nargs="?", help="Existing XML file")
    parser.add_argument("--scan",       help="Single subnet to scan, e.g. 10.10.20.0/24")
    parser.add_argument("--scan-range", nargs=2, metavar=("START", "END"),
                        help="Subnet range to scan, e.g. --scan-range 10.10.21.0/24 10.10.40.0/24")
    parser.add_argument("-o", "--output", default="discovered_switches.csv", help="CSV output file")
    args = parser.parse_args()

    if args.scan_range:
        scan_range(args.scan_range[0], args.scan_range[1], output_csv=args.output)

    elif args.scan:
        sp = SwitchParser(subnet=args.scan, output_csv=args.output)
        if sp.run_scan():
            sp.parse()
            sp.export_csv()
            sp.summary()

    elif args.xml:
        sp = SwitchParser(xml_file=args.xml, output_csv=args.output)
        sp.parse()
        sp.export_csv()
        sp.summary()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
