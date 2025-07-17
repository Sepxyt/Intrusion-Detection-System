from scapy.all import sniff, IP, TCP


blacklisted_ips = ['192.168.1.100']  # Add real blacklists
syn_packets = {}

def detect_intrusion(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_flags = packet[TCP].flags


        if tcp_flags == 'S':
            syn_packets[ip_src] = syn_packets.get(ip_src, 0) + 1
            if syn_packets[ip_src] > 10:
                print(f"[!] Potential SYN scan from {ip_src}")


        if ip_src in blacklisted_ips:
            print(f"[!] Packet from blacklisted IP: {ip_src} -> {ip_dst}")


        if tcp_flags == 'FPU':
            print(f"[!] Possible Xmas scan from {ip_src}")

print("[*] Starting basic IDS...")
sniff(prn=detect_intrusion, store=0)
