import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/fault_dns.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_ok_dns():
    assert packets[0].dns.is_incomplete is False
    assert packets[0].dns.questions[0] == 'google.com A'


def test_malformed_dns():
    assert packets[1].dns.is_incomplete is True
    assert packets[1].dns.questions[0] == 'google.com A'
    assert packets[1].dns.authority_count == 15039
