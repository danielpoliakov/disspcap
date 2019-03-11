import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

udp_packets = []
tcp_packets = []


def setup_module():
    udp_pcap = disspcap.Pcap(f'{dir_path}/pcaps/dns.pcap')

    packet = udp_pcap.next_packet()
    while packet:
        udp_packets.append(packet)
        packet = udp_pcap.next_packet()

    tcp_pcap = disspcap.Pcap(f'{dir_path}/pcaps/http.pcap')

    packet = tcp_pcap.next_packet()
    while packet:
        tcp_packets.append(packet)
        packet = tcp_pcap.next_packet()


def test_udp_payloads_1():
    payload = (b'F\xf9\x01\x00\x00\x01\x00\x00\x00'
               b'\x00\x00\x01\x07youtube\x03com\x00'
               b'\x00\x01\x00\x01\x00\x00)\x02\x00'
               b'\x00\x00\x00\x00\x00\x00')
    assert udp_packets[0].udp.payload == payload


def test_udp_payloads_2():
    payload = (b'l\xa7\x81\x80\x00\x01\x00\x01\x00'
               b'\x00\x00\x01\x03www\x07youtube\x03'
               b'com\x00\x00\x05\x00\x01\xc0\x0c\x00'
               b'\x05\x00\x01\x00\x00\x1c\xa5\x00\x16'
               b'\nyoutube-ui\x01l\x06google\xc0\x18'
               b'\x00\x00)\x0f\xa0\x00\x00\x00\x00\x00\x00')
    assert udp_packets[3].udp.payload == payload


def test_udp_payloads_3():
    payload = (b'\xfdV\x81\x80\x00\x01\x00\x01\x00\x00\x00'
               b'\x01\x03159\x03177\x03229\x03147'
               b'\x07in-addr\x04arpa\x00\x00\x0c\x00'
               b'\x01\xc0\x0c\x00\x0c\x00\x01\x00\x00'
               b'8?\x00\x12\x03ehw\x03fit\x05vutbr\x02'
               b'cz\x00\x00\x00)\x0f\xa0\x00\x00'
               b'\x00\x00\x00\x00')
    assert udp_packets[13].udp.payload == payload


def test_tcp_payloads_0():
    payload = (b'GET / HTTP/1.1\r\nHost: su.fit.vutbr.cz'
               b'\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu;'
               b' Linux x86_64; rv:65.0) Gecko/20100101 '
               b'Firefox/65.0\r\nAccept: text/html,'
               b'application/xhtml+xml,application/xml;'
               b'q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language:'
               b' en-US,en;q=0.5\r\nAccept-Encoding: gzip,'
               b' deflate\r\nConnection: keep-alive\r\nCookie:'
               b' cookieOK=1; csrftoken=dwYojZmnAVuHA'
               b'ybopbVm3YBgwhbxLps9T4wjHzbQt8ZNmlfn8Ky'
               b'QXAzUHwuoOaYh\r\nUpgrade-Insecure-Requests: 1\r\n\r\n')
    assert tcp_packets[0].tcp.payload == payload
