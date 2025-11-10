import xml.etree.ElementTree as ET
import csv

# XML file from nmap
xml_file = "datacenter1.xml"

# Output CSV file
output_csv = "dc1.csv"

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

def text_contains_any(text, keywords):
    """Helper: check if any keyword is present in text."""
    text = text.lower()
    return any(kw in text for kw in keywords)

# Parse XML
tree = ET.parse(xml_file)
root = tree.getroot()

found_switches = []

for host in root.findall("host"):
    ip = ""
    full_text = ""

    # Get IP
    addr = host.find("address")
    if addr is not None and addr.get("addr"):
        ip = addr.get("addr")

    # Collect all service/banner info as text
    for elem in host.iter():
        if elem.text:
            full_text += elem.text + " "
        for key, value in elem.attrib.items():
            full_text += str(value) + " "

    # Filter
    if text_contains_any(full_text, exclude_keywords):
        continue  # skip unwanted devices

    if text_contains_any(full_text, switch_keywords):
        found_switches.append((ip,"", ""))

# Export to CSV
if found_switches:
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
       # writer.writerow(["IP Address", "Serial No.", "MAC"])
        writer.writerow(["IP","S/NO","Port","MAC","Name","vlan","Fibre","POE","Rack no","Location","Connected Devices","Remarks"])
        writer.writerows(found_switches)
    print(f"✅ Found {len(found_switches)} switches. Saved to '{output_csv}'")
else:
    print("⚠️ No switches found.")
