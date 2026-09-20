import argparse
import re
from collections import Counter, defaultdict

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    DNS,
    DNSQR,
    ICMP,
    IP,
    Raw,
    TCP,
    UDP,
    rdpcap,
    sniff,
)
from tabulate import tabulate

class NetworkAnalyzer:
    def __init__(self):
        self.total_packets = 0
        self.ip_counter = Counter()
        self.protocol_counter = Counter()
        self.syn_attempts = defaultdict(set)
        self.anomalies = []

    def process_packet(self, packet):
        self.total_packets +=1

        # ARP traffic
        if ARP in packet:
            self.protocol_counter['ARP'] += 1
            return

        # IP Packet
        if IP not in packet:
            self.protocol_counter['Other'] += 1
            return

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        self.ip_counter[source_ip] += 1
        self.ip_counter[destination_ip] += 1

        # ICMP
        if ICMP in packet:
            self.protocol_counter["ICMP"] += 1
            return 

        # TCP
        if TCP in packet:
            self.inspect_tcp(packet, source_ip, destination_ip)
            return

        # UDP
        if UDP in packet:
            self.inspect_udp(packet, source_ip, destination_ip)
            return

        # other
        self.protocol_counter["Other"] += 1

    # TCP
    def inspect_tcp(self, packet, source_ip, destination_ip):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        flags = packet[TCP].flags

        if flags & 0x02 and not (flags & 0x10):
            self.syn_attempts[source_ip].add((destination_ip, dport))
  
        if sport in (80, 8080) or dport in (80, 8080):
            self.protocol_counter['HTTP'] += 1
            self.inspect_http(packet, source_ip, destination_ip)

        elif sport == 443 or dport == 443:
            self.protocol_counter['HTTP/TLS'] += 1
            return

        elif sport in (20, 21) or dport in (20, 21):
            self.protocol_counter['FTP'] += 1
            self.inspect_ftp(packet, source_ip, destination_ip)

        elif sport == 22 or dport == 22:
            self.protocol_counter['SSH'] += 1
            return

        else:
            self.protocol_counter['TCP'] += 1

    # UDP
    def inspect_udp(self, packet, source_ip, destination_ip):
        sport = packet[UDP].sport
        dport = packet[UDP].dport

        if sport == 53 or dport == 53:
            self.protocol_counter['DNS'] += 1
            self.inspect_dns(packet, source_ip, destination_ip)
        elif sport in (67, 68) or dport in (67, 68):
            self.protocol_counter['DHCP'] += 1
        elif sport == 443 or dport == 443:
            self.protocol_counter['QUIC/HTTP3'] += 1
        elif sport == 123 or dport == 123:
            self.protocol_counter['NTP'] += 1
        else:
            self.protocol_counter['UDP'] += 1

    # HTTP
    def inspect_http(self, packet, source_ip, destination_ip):
        if Raw not in packet:
            return

        try:
            payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
        except Exception:
            return

        patterns = [
            r'username=',
            r'user=',
            r'password=',
            r'passwd=',
            r'pass',
        ]

        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                self.add_anomaly("HIGH", "HTTP Cleartext Credentials", source_ip, destination_ip, "Possible credentials transmitted over unencrypted HTTP",)
                break

    # FTP
    def inspect_ftp(self, packet, source_ip, destination_ip):
        if Raw not in packet:
            return

        try:
            payload = bytes(packet[Raw].load).decode('utf-8', errors='ignore')
        except Exception:
            return

        if re.search(r'\bUSER\s+\S+', payload, re.IGNORECASE):
            self.add_anomaly(
            "HIGH",
            "FTP Cleartext Username",
            source_ip,
            destination_ip,
            "FTP username transmitted without encryption",
            )

        elif re.search("\bPASS\s+\S+", payload, re.IGNORECASE):
            self.add_anomaly(
                "HIGH",
                "FTP Cleartext Password",
                source_ip,
                destination_ip,
                "FTP password transmitted without encryption",
            )

    # DNS
    def inspect_dns(self, packet, source_ip, destination_ip):
        if DNS not in packet or DNSQR not in packet:
            return

        try:
            payload = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
        except Exception:
            return

        if len(payload) >= 50:
            self.add_anomaly(
                "MEDIUM",
                "Possible DNS Tunneling",
                source_ip,
                destination_ip,
                f"DNS query length: {len(payload)} characters",
            )

    def add_anomaly(self, severity, anomaly_type, source, destination, details):
        anomaly = {
            'severity': severity,
            "type": anomaly_type,
            "source": source,
            "destination": destination,
            "details": details,
        }
        if anomaly not in self.anomalies:
            self.anomalies.append(anomaly)

    def detect_port_scans(self):
        for src, targets in self.syn_attempts.items():
            unique_ports = {port for _, port in targets}
            if len(unique_ports) >= 10:
                sorted_ports = sorted(unique_ports)

                self.add_anomaly(
                    "MEDIUM",
                    "Possible SYN Port Scan",
                    src,
                    "Multiple ports",
                    (
                        f'SYN packets detected against '
                        f'{len(unique_ports)} unique ports: '
                        f'{sorted_ports[:15]}'
                    ),
                )

    def report(self):
        print('\nTOP ACTIVE IP ADDRESSES')
        top_ips = self.ip_counter.most_common(10)
        if top_ips:
            print(tabulate(top_ips, headers=['IP', 'Count'], tablefmt='grid'))
        else:
            print("No IP traffic detected")

        print("\nPROTOCOL DISTRIBUTION")
        protocols = self.protocol_counter.most_common()
        if protocols:
            print(tabulate(protocols, headers=['Protocol', 'Count'], tablefmt='grid'))
        else:
            print('No protocols detected')

        print('\nDETECTED ANOMALIES')

        if not self.anomalies:
            print("No suspicious activity detected")

        else:
            anomaly_table = [
                [
                    anomaly['severity'], anomaly['type'], anomaly['source'], anomaly['destination'], anomaly['details'],
                ]
                for anomaly in self.anomalies
            ]

            print(tabulate(anomaly_table, headers=['Severity', 'Type', 'Source', 'Destination', 'Details',], tablefmt='grid'))

def main():
    parser = argparse.ArgumentParser(description="Simple packet analyzer")
    parser.add_argument("-r", "--read", help="Read packets from pcap file")
    parser.add_argument("-i", "--iface", help="Sniff live on interface")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to sniff (0 = infinite)")
    args = parser.parse_args()

    analyzer = NetworkAnalyzer()

    if args.read:
        packets = rdpcap(args.read)
        for pkt in packets:
            analyzer.process_packet(pkt)
    elif args.iface:
        sniff(iface=args.iface, prn=analyzer.process_packet, count=args.count)
    else:
        print("Specify -r <pcap file> or -i <interface>")
        return

    analyzer.detect_port_scans()
    analyzer.report()

if __name__ == "__main__":
    main()