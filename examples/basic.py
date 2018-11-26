"""
    Script goes through packets in pcap and counts
    basic statistics.
"""

import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

ethernet_packets = 0
ipv4_packets = 0
ipv6_packets = 0
tcp_packets = 0
udp_packets = 0

pcap = disspcap.Pcap(f'{dir_path}/pcaps/dns_icmp_tcp.pcap')
packet = pcap.next_packet()

while packet:
    if (packet.ethernet):
        ethernet_packets += 1

    if (packet.ipv4):
        ipv4_packets += 1

    if (packet.ipv6):
        ipv6_packets += 1

    if (packet.udp):
        udp_packets += 1

    if (packet.tcp):
        tcp_packets += 1

    packet = pcap.next_packet()


print(f'Number of ethernet packets {ethernet_packets}')
print(f'Number of ipv4 packets {ipv4_packets}')
print(f'Number of ipv6 packets {ipv6_packets}')
print(f'Number of udp packets {udp_packets}')
print(f'Number of tcp packets {tcp_packets}')
