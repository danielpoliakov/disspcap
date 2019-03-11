import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/http.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_http_methods():
    assert packets[0].http.request_method == 'GET'
    assert packets[7].http.request_method == 'POST'
    assert packets[12].http.request_method == ''


def test_http_versions():
    assert packets[0].http.version == 'HTTP/1.1'
    assert packets[12].http.version == 'HTTP/1.1'
    assert packets[15].http.version == ''


def test_http_status_code():
    assert packets[1].http.status_code == '200'
    assert packets[10].http.status_code == '404'
    assert packets[37].http.status_code == '204'


def test_response_phrase():
    assert packets[1].http.response_phrase == 'OK'
    assert packets[10].http.response_phrase == 'Not Found'
    assert packets[37].http.response_phrase == 'No Content'
