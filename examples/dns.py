"""
    Script goes through DNS query responses and prints formatted sections
    answers, authoritative servers, additional RRs.
"""

import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

i = 1
pcap = disspcap.Pcap(f'{dir_path}/pcaps/dns_example.pcap')
packet = pcap.next_packet()

while packet:
    if packet.dns:
        if packet.dns.qr == 1:
            print(f'\nPacket #{i}:')

            print('  Answers: ')
            for ans in packet.dns.answers:
                print(f'    {ans}')

            print('  Authoritatives: ')
            for auth in packet.dns.authoritatives:
                print(f'    {auth}')

            print('  Additionals: ')
            for add in packet.dns.additionals:
                print(f'    {add}')

    i += 1
    packet = pcap.next_packet()
