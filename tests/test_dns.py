import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/dns.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_dns_questions():
    assert packets[0].dns.qr == 0
    assert packets[2].dns.qr == 0
    assert packets[4].dns.qr == 0
    assert packets[6].dns.qr == 0
    assert packets[0].dns.questions[0] == 'youtube.com A'
    assert packets[2].dns.questions[0] == 'www.youtube.com CNAME'
    assert packets[4].dns.questions[0] == 'google.com SOA'
    assert packets[6].dns.questions[0] == 'google.com AAAA'


def test_dns_additionals():
    assert packets[5].dns.additionals[0] == 'ns1.google.com A 216.239.32.10'
    assert packets[5].dns.additionals[1] == ('ns1.google.com AAAA '
                                             '2001:4860:4802:32::a')


def test_dns_a():
    assert packets[1].dns.answers[0] == 'youtube.com A 172.217.23.206'


def test_dns_cname():
    assert packets[3].dns.answers[0] == ('www.youtube.com CNAME '
                                         'youtube-ui.l.google.com')


def test_dns_soa():
    assert packets[5].dns.answers[0] == ('google.com SOA "ns1.google.com '
                                         'dns-admin.google.com 237687157 900 '
                                         '900 1800 60"')


def test_dns_ptr():
    assert packets[13].dns.answers[0] == ('159.177.229.147.in-addr.arpa PTR '
                                          'ehw.fit.vutbr.cz')


def test_dns_aaaa():
    assert packets[16].dns.answers[0] == ('ehw.fit.vutbr.cz AAAA '
                                          '2001:67c:1220:8b0::93e5:b19f')
