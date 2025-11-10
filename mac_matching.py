import PyPDF2
import re

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF file"""
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text()
            return text
    except Exception as e:
        print(f"Error reading PDF: {e}")
        return ""

def extract_mac_addresses(text):
    """Extract MAC addresses from text"""
    # Pattern matches MAC addresses in various formats:
    # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
    mac_pattern = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b'
    macs = re.findall(mac_pattern, text)
    
    # Normalize to uppercase and colon format for consistency
    normalized_macs = set()
    for mac in macs:
        normalized_mac = mac.upper().replace('-', ':')
        normalized_macs.add(normalized_mac)
    
    return normalized_macs

def read_text_file_macs(txt_path):
    """Read MAC addresses from text file (tab-separated format)"""
    try:
        with open(txt_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        macs = set()
        for line in lines:
            parts = line.strip().split('\t')
            if len(parts) >= 2:
                # Second column contains MAC address
                mac = parts[1].strip().upper()
                # Validate MAC address format
                if re.match(r'^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                    macs.add(mac)
        
        return macs
    except Exception as e:
        print(f"Error reading text file: {e}")
        return set()

def find_matching_macs(pdf_path, txt_path):
    """Find matching MAC addresses between PDF and text file"""
    
    # Extract MAC addresses from PDF
    print("Reading and extracting MAC addresses from PDF...")
    pdf_text = extract_text_from_pdf(pdf_path)
    pdf_macs = extract_mac_addresses(pdf_text)
    
    # Extract MAC addresses from text file
    print("Reading MAC addresses from text file...")
    txt_macs = read_text_file_macs(txt_path)
    
    # Find matching MAC addresses
    matching_macs = pdf_macs.intersection(txt_macs)
    
    # Find MACs only in PDF
    only_in_pdf = pdf_macs - txt_macs
    
    # Find MACs only in text file
    only_in_txt = txt_macs - pdf_macs
    
    # Display results
    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    print(f"Total MAC addresses in PDF: {len(pdf_macs)}")
    print(f"Total MAC addresses in text file: {len(txt_macs)}")
    print(f"Matching MAC addresses: {len(matching_macs)}")
    print(f"{'='*60}\n")
    
    if matching_macs:
        print("✓ MATCHING MAC ADDRESSES:")
        print("-" * 60)
        for mac in sorted(matching_macs):
            print(f"  {mac}")
        print()
    else:
        print("✗ No matching MAC addresses found.\n")
    
    if only_in_pdf:
        print(f"MAC addresses ONLY in PDF ({len(only_in_pdf)}):")
        print("-" * 60)
        for mac in sorted(only_in_pdf):
            print(f"  {mac}")
        print()
    
    if only_in_txt:
        print(f"MAC addresses ONLY in text file ({len(only_in_txt)}):")
        print("-" * 60)
        for mac in sorted(only_in_txt):
            print(f"  {mac}")
        print()
    
    return {
        'matching': matching_macs,
        'only_pdf': only_in_pdf,
        'only_txt': only_in_txt
    }

def save_results(results, output_file='mac_matching_results.txt'):
    """Save matching results to a file"""
    try:
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write("MAC ADDRESS MATCHING RESULTS\n")
            file.write("="*60 + "\n\n")
            
            file.write(f"MATCHING MAC ADDRESSES ({len(results['matching'])}):\n")
            file.write("-"*60 + "\n")
            for mac in sorted(results['matching']):
                file.write(f"{mac}\n")
            
            file.write(f"\n\nMAC ADDRESSES ONLY IN PDF ({len(results['only_pdf'])}):\n")
            file.write("-"*60 + "\n")
            for mac in sorted(results['only_pdf']):
                file.write(f"{mac}\n")
            
            file.write(f"\n\nMAC ADDRESSES ONLY IN TEXT FILE ({len(results['only_txt'])}):\n")
            file.write("-"*60 + "\n")
            for mac in sorted(results['only_txt']):
                file.write(f"{mac}\n")
        
        print(f"✓ Results saved to: {output_file}")
    except Exception as e:
        print(f"Error saving results: {e}")

# Main execution
if __name__ == "__main__":
    # Specify your file paths here
    pdf_file = "macip.pdf"  # Replace with your PDF file path
    text_file = "tofind.txt"  # Replace with your text file path
    
    # Find matching MAC addresses
    results = find_matching_macs(pdf_file, text_file)
    
    # Save results to file
    save_results(results)