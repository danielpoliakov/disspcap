import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/fault_data.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_binary_data_starting_with_GET():
    assert packets[0].http.request_method == ''
