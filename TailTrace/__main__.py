import sys
sys.path.append('C:/Users/Админ/Desktop/TailTrace') 

import argparse
from tailtrace.sniffer import start_sniffing  # Захоплення трафіку
from tailtrace.analyzer import analyze_packet  # Аналіз одного пакета в реальному часі

def main():
    
    parser = argparse.ArgumentParser(description="TailTrace - Network Monitoring Tool")
    parser.add_argument("-t", "--target", type=str, required=True, help="IP address or URL to monitor")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    target = args.target
    verbose = args.verbose

    print(f"[INFO] Starting real-time monitoring for target: {target}")
    if verbose:
        print("[INFO] Verbose mode enabled")

    try:
        
        for packet in start_sniffing(target, verbose):
            analysis_result = analyze_packet(packet)

            if analysis_result:
                print(f"[ALERT] {analysis_result}")

    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped by user.")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
