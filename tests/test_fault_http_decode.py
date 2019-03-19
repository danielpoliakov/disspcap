import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/fault_http_decode.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_valid_request_part():
    assert packets[0].http.request_method == 'POST'
    assert packets[0].http.request_uri == '/ioad.exe'
    assert packets[0].http.version == 'HTTP/1.1'


def test_invalid_user_agent():
    user_agent = ('%98%a4%91%03%e8%c4%91%037 Professional 32 bit | '
                  'CPU: Intel(R) Xeon(R) Platinum 8160 CPU @ 2.10GHz')
    assert packets[0].http.headers['User-Agent'] == user_agent


def test_non_ascii_trigger():
    assert packets[0].http.non_ascii is True
