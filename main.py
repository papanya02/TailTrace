import argparse
import subprocess
import sys
import logging
import os
import csv
from scapy.all import sniff, get_if_list, get_if_addr, IP, TCP, UDP, Raw, ICMP, ARP
from datetime import datetime
from termcolor import colored
import geoip2.database
import pandas as pd
import shutil

def install_package(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError:
        logging.error(f"Failed to install package {package}")
        sys.exit(1)

try:
    from scapy.all import sniff
except ImportError:
    logging.info("Scapy is not installed. Installing...")
    install_package("scapy")
    from scapy.all import sniff

def print_welcome_message():
    welcome_message = """
     █████████████████████████████████████████████████████████████████████                    
      
      |                         TailTrace                               |
      |                         /\_____/\                               |
      |                        /  o   o  \  < Meow! Network sniffed!    |
      |                       ( ==  ^  == )                             |
      |                        )         (                              |
      |                       (           )                             |
      |                      ( (  )   (  ) )                            |
      |                     (__(__)___(__)__)                           |
      |                                                                 |
      █████████████████████████████████████████████████████████████████████

      --=[ TailTrace v1.0.0 ]=--

      TailTrace tip: Never underestimate a cat's curiosity or a network packet.
    
    **************************************************************
    * TailTrace v1.0.0                                           *
    * License: MIT                                               *
    * Author: Andrii Tyshkevych                                  *
    * Description: A network traffic analyzer and capture tool.  *
    **************************************************************
    """

    print(welcome_message)

def detect_protocol(packet):
    """Detect the protocol type and identify modern protocols."""
    if packet.haslayer(UDP):
        if packet[UDP].dport in [443, 8443] or packet[UDP].sport in [443, 8443]:
            return "QUIC (HTTP/3)"
        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            return "DNS"
        if packet[UDP].dport in [67, 68] or packet[UDP].sport in [67, 68]:
            return "DHCP"
        if packet[UDP].dport == 161 or packet[UDP].sport == 161:
            return "SNMP"
        if packet[UDP].dport == 5060 or packet[UDP].sport == 5060:
            return "SIP"
        if packet[UDP].dport in [1883, 8883] or packet[UDP].sport in [1883, 8883]:
            return "MQTT"
        if packet[UDP].dport == 5683 or packet[UDP].sport == 5683:
            return "CoAP"
    if packet.haslayer(TCP):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            return "HTTP"
        if packet[TCP].dport in [443, 8443] or packet[TCP].sport in [443, 8443]:
            return "HTTPS"
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
            return "FTP"
        if packet[TCP].dport == 22 or packet[TCP].sport == 22:
            return "SSH"
        if packet[TCP].dport == 25 or packet[TCP].sport == 25:
            return "SMTP"
        if packet[TCP].dport == 110 or packet[TCP].sport == 110:
            return "POP3"
        if packet[TCP].dport == 143 or packet[TCP].sport == 143:
            return "IMAP"
        if packet[TCP].dport in [1883, 8883] or packet[TCP].sport in [1883, 8883]:
            return "MQTT (Secure)"
        if packet[TCP].dport == 3306 or packet[TCP].sport == 3306:
            return "MySQL"
        if packet[TCP].dport == 5432 or packet[TCP].sport == 5432:
            return "PostgreSQL"
        if packet[TCP].dport == 3389 or packet[TCP].sport == 3389:
            return "RDP"
        if packet[TCP].dport in [137, 139, 445] or packet[TCP].sport in [137, 139, 445]:
            return "SMB"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b"HTTP" in payload:
            return "HTTP"
        if b"SMTP" in payload:
            return "SMTP"
        if b"FTP" in payload:
            return "FTP"
        if b"SSH" in payload:
            return "SSH"
        if b"GET" in payload or b"POST" in payload:
            return "HTTP Request"
        if b"MQTT" in payload:
            return "MQTT"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(UDP):
        if packet[UDP].dport in [443, 8443] or packet[UDP].sport in [443, 8443]:
            return "QUIC (HTTP/3)"
        if packet[UDP].dport == 853 or packet[UDP].sport == 853:
            return "DNS-over-TLS"
        if packet[UDP].dport == 123 or packet[UDP].sport == 123:
            return "NTP"
        if packet[UDP].dport == 1194 or packet[UDP].sport == 1194:
            return "OpenVPN"
    if packet.haslayer(TCP):
        if packet[TCP].dport in [80, 8080] or packet[TCP].sport in [80, 8080]:
            return "HTTP/1.x"
        if packet[TCP].dport == 443 or packet[TCP].sport == 443:
            return "HTTPS"
        if packet[TCP].dport == 5246 or packet[TCP].sport == 5246:
            return "CAPWAP"
        if packet[TCP].dport == 3389 or packet[TCP].sport == 3389:
            return "RDP"
    if packet.haslayer(IP):
        if packet[IP].proto == 47:
            return "GRE"
        if packet[IP].proto == 50:
            return "ESP (IPsec)"
        if packet[IP].proto == 51:
            return "AH (IPsec)"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)
        if b"HTTP/2" in payload:
            return "HTTP/2"
        if b"BitTorrent" in payload:
            return "BitTorrent"
    return "Unknown"



def packet_callback(packet, csv_file=None):
    """Callback function to process each captured packet."""
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
    else:
        ip_src = ip_dst = "N/A"

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        src_port = dst_port = "N/A"

    detected_protocol = detect_protocol(packet)

    print(f"{datetime.now().strftime('%H:%M:%S.%f')[:-3]} | "
          f"{colored(ip_src, 'green')}:{src_port} -> "
          f"{colored(ip_dst, 'red')}:{dst_port} | "
          f"Proto: {colored(detected_protocol, 'yellow')} | "
          f"Len: {len(packet)} bytes")

    if csv_file:
        packet_info = {
            'Time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'Source': ip_src,
            'Destination': ip_dst,
            'Protocol': detected_protocol,
            'Length': len(packet),
            'Info': f"Src Port: {src_port} Dst Port: {dst_port}"
        }
        log_traffic_to_csv(csv_file, packet_info)

def log_traffic_to_csv(csv_file, packet_info):
    """Log captured packet data to a CSV file."""
    file_exists = os.path.isfile(csv_file)
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        if not file_exists:
            writer.writeheader()  
        writer.writerow(packet_info)

def capture_traffic(csv_file=None):
    """Capture network traffic from a specified interface."""
    interfaces = get_if_list()
    if not interfaces:
        print("No network interfaces found.")
        sys.exit(1)

    print("Available network interfaces:")
    interface_names = {}
    for idx, iface in enumerate(interfaces, 1):
        try:
            ip_addr = get_if_addr(iface)
            if ip_addr == "0.0.0.0":
                ip_addr = "No IP assigned"
            interface_names[idx] = (iface, ip_addr)
            print(f"{idx}. {iface} ({ip_addr})")
        except Exception as e:
            logging.warning(f"Could not get IP for interface {iface}: {e}")
            interface_names[idx] = (iface, 'Unknown')

    try:
        selected_idx = int(input("Select an interface by number: ")) - 1
        if selected_idx < 0 or selected_idx >= len(interface_names):
            raise ValueError("Invalid selection.")
        interface, iface_name = interface_names[selected_idx + 1]
    except (ValueError, IndexError):
        print("Invalid selection. Exiting.")
        sys.exit(1)

    print(f"Capturing traffic on interface {iface} ({iface_name})...")

    try:
        sniff(iface=interface, prn=lambda packet: packet_callback(packet, csv_file), store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        
        
 
def integrate_with_tool(tool_name):
    """Integrate with external tools like Wireshark, Nmap, or Suricata."""
    check_tool_installed(tool_name.lower())  

    if tool_name.lower() == "wireshark":
        print("Launching Wireshark...")
        try:
            subprocess.run(["wireshark"], check=True)
        except Exception as e:
            logging.error(f"Failed to launch Wireshark: {e}")
    elif tool_name.lower() == "nmap":
        target = input("Enter the target IP or range for Nmap scan: ").strip()
        if not target:
            print("Target IP or range is required for Nmap.")
            return
        print(f"Running Nmap scan on {target}...")
        try:
            subprocess.run(["nmap", target], check=True)
        except Exception as e:
            logging.error(f"Failed to run Nmap: {e}")
    elif tool_name.lower() == "suricata":
        config_file = input(
            "Enter the Suricata configuration file path (default: /etc/suricata/suricata.yaml): "
        ).strip() or "/etc/suricata/suricata.yaml"
        interface = input("Enter the network interface to monitor (default: any): ").strip() or "any"
        print(f"Starting Suricata IDS using config {config_file} on interface {interface}...")
        try:
            subprocess.run(["suricata", "-c", config_file, "-i", interface], check=True)
        except Exception as e:
            logging.error(f"Failed to start Suricata: {e}")
    else:
        print(f"Integration with {tool_name} is not supported.")

def check_tool_installed(tool_name):
    """Check if a tool is installed and available in PATH."""
    if not shutil.which(tool_name):
        print(f"Error: {tool_name} is not installed or not in PATH.")
        sys.exit(1)


def protocol_distribution(df):
    """Analyze protocol distribution."""
    print("\nProtocol Distribution:")
    print(df['Protocol'].value_counts())

def detect_large_packets(df):
    """Detect packets larger than 1000 bytes."""
    print("\nDetecting large packets:")
    large_packets = df[df['Length'] > 1000]
    if not large_packets.empty:
        print(large_packets[['Time', 'Source', 'Destination', 'Length']])
    else:
        print("No large packets detected.")

def analyze_geolocation(df):
    """Perform geolocation analysis."""
    try:
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        countries = []
        for ip in df['Source']:
            try:
                response = reader.country(ip)
                countries.append(response.country.name)
            except:
                countries.append("Unknown")
        df['Source Country'] = countries
        print("\nTraffic by Source Country:")
        print(df['Source Country'].value_counts())
    except Exception as e:
        print(f"Error in geolocation analysis: {e}")

def analyze_signatures(df):
    """Perform basic signature-based analysis to detect suspicious traffic."""
    print("\nAnalyzing signatures for suspicious traffic:")
    suspicious_ports = [4444, 5555, 6666]  
    suspicious_traffic = df[df['Info'].str.contains('|'.join(map(str, suspicious_ports)), na=False)]
    if not suspicious_traffic.empty:
        print("Suspicious traffic detected:")
        print(suspicious_traffic[['Time', 'Source', 'Destination', 'Info']])
    else:
        print("No suspicious traffic detected.")
        
def detect_dos_attacks(df):
    """Detection of DoS/DDoS attacks by the number of requests from the same source."""
    print("\nDetecting DoS/DDoS attacks:")
    dos_threshold = 1000  
    time_window = 10  
    df['Time'] = pd.to_datetime(df['Time'], format='%H:%M:%S.%f')
    df['Timestamp'] = df['Time'].astype('int64') // 10**9
    grouped = df.groupby(['Source', 'Timestamp']).size()
    potential_dos = grouped[grouped > dos_threshold]
    if not potential_dos.empty:
        print("Potential DoS/DDoS attacks detected:")
        print(potential_dos)
    else:
        print("No DoS/DDoS activity detected.")

def detect_port_scanning(df):
    """Port scanning detection."""
    print("\nDetecting port scanning:")
    port_scan_threshold = 10 
    grouped = df.groupby('Source')['Info'].apply(
        lambda x: len(set(port.split(':')[-1] for port in x if ':' in port))
    )
    potential_scans = grouped[grouped > port_scan_threshold]
    if not potential_scans.empty:
        print("Potential port scanning detected:")
        print(potential_scans)
    else:
        print("No port scanning activity detected.")

def detect_large_packets(df):
    """Large packet detection."""
    print("\nDetecting large packets:")
    large_packet_threshold = 1000  
    large_packets = df[df['Length'] > large_packet_threshold]
    if not large_packets.empty:
        print("Large packets detected:")
        print(large_packets[['Time', 'Source', 'Destination', 'Length']])
    else:
        print("No large packets detected.")
        
def analyze_latency(df):
    """Analyze packet latency."""
    print("\nAnalyzing packet latency:")
    if 'Time' not in df.columns or 'Source' not in df.columns or 'Destination' not in df.columns:
        print("Error: Required columns are missing in the CSV file.")
        return
    df['Time'] = pd.to_datetime(df['Time'], format='%H:%M:%S.%f')
    df['Latency'] = df['Time'].diff().dt.total_seconds()
    high_latency = df[df['Latency'] > 0.1]
    if not high_latency.empty:
        print("Packets with high latency:")
        print(high_latency[['Time', 'Source', 'Destination', 'Latency']])
    else:
        print("No high-latency packets detected.")        

def detect_unusual_protocols(df):
    """Detection of unusual protocols."""
    print("\nDetecting unusual protocols:")
    known_protocols = {'TCP', 'UDP', 'QUIC (HTTP/3)', 'MQTT', 'CoAP', '5G'}
    unusual_protocols = df[~df['Protocol'].isin(known_protocols)]
    if not unusual_protocols.empty:
        print("Unusual protocols detected:")
        print(unusual_protocols[['Time', 'Source', 'Destination', 'Protocol']])
    else:
        print("No unusual protocols detected.")
 

def analyze_csv(csv_file):
    """Analyze network traffic from a CSV file."""
    if not os.path.isfile(csv_file):
        print(f"Error: File {csv_file} does not exist.")
        return
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        return

    while True:
        print("\nSelect analysis option:")
        print("1) Protocol Distribution")
        print("2) Detect Large Packets")
        print("3) Geolocation Analysis")
        print("4) Signature-Based Analysis")
        print("5) Detect DoS/DDoS attacks")  
        print("6) Detect port scanning")
        print("7) Detect unusual protocols")
        print("8) Analyze latency")
        print("9) Return to previous menu")


        choice = input("Enter your choice: ")

        if choice == "1":
            protocol_distribution(df)
        elif choice == "2":
            detect_large_packets(df)
        elif choice == "3":
            analyze_geolocation(df)
        elif choice == "4":
            analyze_signatures(df)
        elif choice == "5":
            detect_dos_attacks(df)
        elif choice == "6":
            detect_port_scanning(df)
        elif choice == "7":
            detect_unusual_protocols(df)
        elif choice == "8":
            analyze_latency(df)
        elif choice == "9":    
            break
        else:
            print("Invalid choice. Please try again.")    
  
def main():
    print_welcome_message()

    while True:
        print("\nSelect an option:")
        print("1) Monitor traffic in console")
        print("2) Monitor traffic in console and log to CSV")
        print("3) Analyze traffic from a CSV file")
        print("4) Integrate with external tools")
        print("5) Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            capture_traffic()
        elif choice == "2":
            csv_file = input("Enter the CSV file path to log traffic: ")
            if not csv_file.endswith('.csv'):
                csv_file += '.csv'
            capture_traffic(csv_file)
        elif choice == "3":
            csv_file = input("Enter the path of the CSV file to analyze: ")
            analyze_csv(csv_file)
        elif choice == "4": 
            print("Select a tool to integrate with:")
            print("1) Wireshark")
            print("2) Nmap")
            print("3) Suricata")
            tool_choice = input("Enter your choice: ")
            if tool_choice == "1":
                integrate_with_tool("Wireshark")
            elif tool_choice == "2":
                integrate_with_tool("Nmap")
            elif tool_choice == "3":
                integrate_with_tool("Suricata")
            else:
                print("Invalid tool choice. Please try again.")
        elif choice == "5":       
                 print("Exiting TailTrace. Goodbye!")
                 break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

