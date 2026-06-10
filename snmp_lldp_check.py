import re
import subprocess
import shutil
from pathlib import Path

# =========================================================
# CONFIGURATION
# =========================================================

SWITCH_LIST_FILE = "swsnmp.txt"
OUTPUT_FILE = "finallldp.txt"

SNMP_COMMUNITY = "public"

SNMP_TIMEOUT_SECONDS = 8

# LLDP Remote System Name
LLDP_REMOTE_SYSNAME_OID = "1.0.8802.1.1.2.1.4.1.1.9"

DEBUG_SAMPLE_LINES = 5


# =========================================================
# PARSE LLDP OUTPUT
# =========================================================

def parse_lldp_output(stdout_text):

    neighbors = []

    lines = stdout_text.splitlines()

    print(f"[dbg] LLDP raw line count: {len(lines)}")

    for idx, line in enumerate(lines, start=1):

        if idx <= DEBUG_SAMPLE_LINES:
            print(f"[dbg] raw[{idx}]: {line}")

        # Example:
        # .1.0.8802.1.1.2.1.4.1.1.9.5.1 = STRING: "SUM-CORE-SW"

        match = re.search(r'STRING:\s+"(.+?)"', line)

        if not match:
            continue

        neighbor = match.group(1).strip()

        if neighbor:
            neighbors.append(neighbor)

    # Remove duplicates
    neighbors = sorted(list(set(neighbors)))

    print(f"[dbg] parsed neighbors: {neighbors}")

    return neighbors


# =========================================================
# LLDP DISCOVERY
# =========================================================

def fetch_lldp_neighbors(switch_ip, community):

    print(f"\n[+] Polling LLDP Neighbors: {switch_ip}")

    if shutil.which("snmpwalk") is None:

        print("[-] snmpwalk binary not found")

        return {
            "status": "snmp_failed",
            "neighbors": []
        }

    cmd = [
        "snmpwalk",
        "-v2c",
        "-c", community,
        "-On",
        "-t", "2",
        "-r", "1",
        switch_ip,
        LLDP_REMOTE_SYSNAME_OID,
    ]

    print(f"[dbg] command: {' '.join(cmd)}")

    try:

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SNMP_TIMEOUT_SECONDS
        )

    except subprocess.TimeoutExpired:

        print(f"[-] Device {switch_ip}: timeout")

        return {
            "status": "snmp_failed",
            "neighbors": []
        }

    except Exception as e:

        print(f"[-] Device {switch_ip}: subprocess failed: {e}")

        return {
            "status": "snmp_failed",
            "neighbors": []
        }

    print(f"[dbg] return code: {result.returncode}")

    if result.stderr:
        print(f"[dbg] stderr: {result.stderr.strip()}")

    if result.returncode != 0:

        print(f"[-] Device {switch_ip}: SNMP failed")

        return {
            "status": "snmp_failed",
            "neighbors": []
        }

    neighbors = parse_lldp_output(result.stdout)

    if not neighbors:

        print(f"[-] Device {switch_ip}: no LLDP neighbors")

        return {
            "status": "lldp_failed",
            "neighbors": []
        }

    print(f"[+] Device {switch_ip}: neighbors found")

    return {
        "status": "success",
        "neighbors": neighbors
    }


# =========================================================
# MAIN EXECUTION
# =========================================================

def main():

    if not Path(SWITCH_LIST_FILE).exists():

        raise FileNotFoundError(
            f"Missing file: {SWITCH_LIST_FILE}"
        )

    with open(SWITCH_LIST_FILE, "r") as f:

        switch_ips = [
            line.strip()
            for line in f
            if line.strip()
        ]

    print(f"[+] Total switches loaded: {len(switch_ips)}")

    snmp_failed = []
    lldp_failed = []
    successful_devices = {}

    for ip in switch_ips:

        result = fetch_lldp_neighbors(
            ip,
            SNMP_COMMUNITY
        )

        if result["status"] == "snmp_failed":

            snmp_failed.append(ip)

        elif result["status"] == "lldp_failed":

            lldp_failed.append(ip)

        elif result["status"] == "success":

            successful_devices[ip] = result["neighbors"]

    # =====================================================
    # WRITE OUTPUT
    # =====================================================

    with open(OUTPUT_FILE, "w") as f:

        f.write("=== SNMP FAILED DEVICES ===\n")

        if snmp_failed:

            for ip in snmp_failed:
                f.write(f"{ip}\n")

        else:
            f.write("None\n")

        f.write("\n=== LLDP DISCOVERY FAILED ===\n")

        if lldp_failed:

            for ip in lldp_failed:
                f.write(f"{ip}\n")

        else:
            f.write("None\n")

        f.write("\n=== SUCCESSFUL LLDP DEVICES ===\n")

        if successful_devices:

            for ip, neighbors in successful_devices.items():

                f.write(f"\n{ip}\n")

                for neighbor in neighbors:

                    f.write(f"  -> {neighbor}\n")

        else:

            f.write("None\n")

    print(f"\n[+] Scan complete")
    print(f"[+] Output saved to: {OUTPUT_FILE}")


if __name__ == "__main__":

    main()
