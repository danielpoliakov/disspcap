"""
    Script examines first packet in pcap up to 
    transport layer and prints out payload.
"""

import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

pcap = disspcap.Pcap(f'{dir_path}/pcaps/ipv6_smpt.pcap')
packet = pcap.next_packet()

if (packet.ethernet):
    print(f'Source MAC: {packet.ethernet.source}')
    print(f'Destination MAC: {packet.ethernet.destination}')
    print(f'Ether type: {packet.ethernet.type}\n')

if (packet.ipv6):
    print(f'Source IPv6: {packet.ipv6.source}')
    print(f'Destination IPv6: {packet.ipv6.destination}')
    print(f'Destination IPv6: {packet.ipv6.destination}')
    print(f'IPv6 next header: {packet.ipv6.next_header}\n')

if (packet.tcp):
    print(f'Source port: {packet.tcp.source_port}')
    print(f'Destination port: {packet.tcp.destination_port}\n')

print(f'Payload: {packet.payload}')
