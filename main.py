import argparse
import subprocess
import sys
import logging
import os
import csv
from scapy.all import sniff, get_if_list, get_if_addr, IP, TCP, UDP, Raw
from datetime import datetime
from termcolor import colored
import geoip2.database
import pandas as pd

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
      |                         /\_____\/\                               |
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
    * TailTrace v1.0.0                                            *
    * License: MIT                                               *
    * Author: Andrii Tyshkevych                                  *
    * Description: A network traffic analyzer and capture tool. *
    **************************************************************
    """

    print(welcome_message)

def detect_protocol(packet):
    """Detect the protocol type and identify modern protocols."""
    if packet.haslayer(UDP):
        if packet[UDP].dport == 443 or packet[UDP].sport == 443:
            return "QUIC (HTTP/3)"
    if packet.haslayer(TCP):
        if packet[TCP].dport == 1883 or packet[TCP].sport == 1883:
            return "MQTT"
    if packet.haslayer(UDP):
        if packet[UDP].dport == 5683 or packet[UDP].sport == 5683:
            return "CoAP"
    if packet.haslayer(UDP):
        if 2152 <= packet[UDP].dport <= 2172 or 2152 <= packet[UDP].sport <= 2172:
            return "5G"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
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

    packet_info = {
        'Time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'Source': ip_src,
        'Destination': ip_dst,
        'Protocol': detected_protocol,
        'Length': len(packet),
        'Info': f"Src Port: {src_port} Dst Port: {dst_port}"
    }

    print(f"\n{'-'*50}")
    print(f"Time          : {colored(packet_info['Time'], 'cyan')}")
    print(f"Source        : {colored(packet_info['Source'], 'green')}")
    print(f"Destination   : {colored(packet_info['Destination'], 'red')}")
    print(f"Protocol      : {colored(packet_info['Protocol'], 'yellow')}")
    print(f"Length        : {packet_info['Length']} bytes")
    print(f"Info          : {packet_info['Info']}")
    print(f"{'-'*50}")

    if csv_file:
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

    print("\nPerforming traffic analysis...")

    protocol_counts = df['Protocol'].value_counts()
    print("\nProtocol Distribution:")
    print(protocol_counts)

    print("\nDetecting anomalies...")
    if 'Length' in df.columns:
        large_packets = df[df['Length'] > 1000]
        if not large_packets.empty:
            print(f"\nLarge packets detected:")
            print(large_packets[['Time', 'Source', 'Destination', 'Length']])

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
        3

def main():
    print_welcome_message()

    while True:
        print("\nSelect an option:")
        print("1) Monitor traffic in console")
        print("2) Monitor traffic in console and log to CSV")
        print("3) Analyze traffic from a CSV file")
        print("4) Exit")

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
            print("Exiting TailTrace. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
