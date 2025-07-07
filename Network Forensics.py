import pyshark
from transformers import pipeline
import json

class PCAPVulnerabilityAssessmentAI:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.suspicious_packets = []
        print("[*] Loading pre-trained AI model...")
        self.anomaly_detector = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

    def analyze_packets(self):
        print("[*] Loading PCAP file...")
        try:
            capture = pyshark.FileCapture(self.pcap_file)
            for packet in capture:
                try:
                    if 'HTTP' in packet:
                        self.analyze_http(packet)
                    elif 'FTP' in packet:
                        self.analyze_ftp(packet)
                    elif 'SMTP' in packet:
                        self.analyze_smtp(packet)
                    elif 'DNS' in packet:
                        self.analyze_dns(packet)
                    elif 'DHCP' in packet:
                        self.analyze_dhcp(packet)
                    elif 'SSL' in packet or 'TLS' in packet:
                        self.analyze_ssl_tls(packet)
                    elif 'SSH' in packet:
                        self.analyze_ssh(packet)
                    elif 'ICMP' in packet:
                        self.analyze_icmp(packet)
                    elif 'ARP' in packet:
                        self.analyze_arp(packet)
                    elif 'SNMP' in packet:
                        self.analyze_snmp(packet)
                    elif 'NTP' in packet:
                        self.analyze_ntp(packet)
                    elif 'IP' in packet or 'IPv6' in packet:
                        self.analyze_ip(packet)
                    elif 'TCP' in packet:
                        self.analyze_tcp(packet)
                    elif 'UDP' in packet:
                        self.analyze_udp(packet)
                except Exception as e:
                    print(f"[!] Error analyzing packet: {e}")
                    continue
        except Exception as e:
            print(f"[!] Error loading PCAP file: {e}")

    def analyze_http(self, packet):
        payload = getattr(packet.http, 'file_data', '')
        if self.detect_vulnerability(payload):
            self.flag_packet(packet, "HTTP", payload)

    def analyze_ftp(self, packet):
        command = getattr(packet.ftp, 'request_command', '')
        args = getattr(packet.ftp, 'request_arg', '')
        payload = f"{command} {args}".strip()
        if self.detect_vulnerability(payload):
            self.flag_packet(packet, "FTP", payload)

    def analyze_smtp(self, packet):
        payload = getattr(packet.smtp, 'mail_from', '')
        if self.detect_vulnerability(payload):
            self.flag_packet(packet, "SMTP", payload)

    def analyze_dns(self, packet):
        query = getattr(packet.dns, 'qry_name', '')
        if self.detect_vulnerability(query):
            self.flag_packet(packet, "DNS", query)

    def analyze_dhcp(self, packet):
        self.flag_packet(packet, "DHCP", "DHCP packet observed")

    def analyze_ssl_tls(self, packet):
        self.flag_packet(packet, "SSL/TLS", "Encrypted SSL/TLS communication")

    def analyze_ssh(self, packet):
        self.flag_packet(packet, "SSH", "Encrypted SSH communication")

    def analyze_icmp(self, packet):
        payload = getattr(packet.icmp, 'data', '')
        self.flag_packet(packet, "ICMP", payload)

    def analyze_arp(self, packet):
        sender_ip = getattr(packet.arp, 'src_proto_ipv4', '')
        target_ip = getattr(packet.arp, 'dst_proto_ipv4', '')
        payload = f"ARP request from {sender_ip} to {target_ip}"
        self.flag_packet(packet, "ARP", payload)

    def analyze_snmp(self, packet):
        payload = getattr(packet.snmp, 'variable_bindings', '')
        if self.detect_vulnerability(payload):
            self.flag_packet(packet, "SNMP", payload)

    def analyze_ntp(self, packet):
        self.flag_packet(packet, "NTP", "NTP synchronization packet")

    def analyze_ip(self, packet):
        self.flag_packet(packet, "IP", "IP layer packet detected")

    def analyze_tcp(self, packet):
        payload = getattr(packet.tcp, 'payload', '')
        if self.detect_vulnerability(payload):
            self.flag_packet(packet, "TCP", payload)

    def analyze_udp(self, packet):
        payload = getattr(packet.udp, 'payload', '')
        if self.detect_vulnerability(payload):
            self.flag_packet(packet, "UDP", payload)

    def detect_vulnerability(self, text):
        if not text:
            return False
        result = self.anomaly_detector(text[:512])  # Truncate text to model input limit
        label = result[0]["label"]
        return label == "LABEL_1"  # Malicious payload label

    def flag_packet(self, packet, protocol, payload):
        self.suspicious_packets.append({
            "timestamp": packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else "N/A",
            "protocol": protocol,
            "source_ip": getattr(packet.ip, 'src', None) if hasattr(packet, 'ip') else None,
            "destination_ip": getattr(packet.ip, 'dst', None) if hasattr(packet, 'ip') else None,
            "payload": payload
        })

    def generate_report(self):
        report_file = 'vulnerability_report.json'
        print(f"[*] Writing report to {report_file}...")
        with open(report_file, 'w') as f:
            json.dump(self.suspicious_packets, f, indent=4)
        print("[*] Report generation complete!")

    def run(self):
        self.analyze_packets()
        self.generate_report()


# Main execution
if __name__ == "__main__":
    pcap_file = input("Enter the path to the PCAP file: ")
    tool = PCAPVulnerabilityAssessmentAI(pcap_file)
    tool.run()
