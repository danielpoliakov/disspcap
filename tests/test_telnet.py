import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/telnet.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_data():
    assert packets[26].telnet.data.strip() == 'OpenBSD/i386 (oof) (ttyp2)'
    assert packets[28].telnet.data == 'login: '
    assert packets[35].telnet.data == 'Password:'
    assert packets[50].telnet.data.strip() == '/sbin/ping www.yahoo.com'
    assert packets[86].telnet.data.strip() == 'exit'


def test_is_command():
    assert packets[3].telnet.is_command is True
    assert packets[4].telnet.is_command is True
    assert packets[11].telnet.is_command is True
    assert packets[14].telnet.is_command is True
    assert packets[42].telnet.is_command is True
    assert packets[70].telnet.is_command is True


def test_not_command():
    assert packets[26].telnet.is_command is False
    assert packets[28].telnet.is_command is False
    assert packets[35].telnet.is_command is False
    assert packets[50].telnet.is_command is False
    assert packets[86].telnet.is_command is False


def test_is_data():
    assert packets[26].telnet.is_data is True
    assert packets[28].telnet.is_data is True
    assert packets[35].telnet.is_data is True
    assert packets[50].telnet.is_data is True
    assert packets[86].telnet.is_data is True


def test_not_data():
    assert packets[3].telnet.is_data is False
    assert packets[4].telnet.is_data is False
    assert packets[11].telnet.is_data is False
    assert packets[14].telnet.is_data is False
    assert packets[42].telnet.is_data is False
    assert packets[70].telnet.is_data is False


def test_empty():
    assert packets[7].telnet.is_empty is True
    assert packets[15].telnet.is_empty is True
    assert packets[29].telnet.is_empty is True
