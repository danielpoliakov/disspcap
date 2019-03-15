import os
import disspcap

dir_path = os.path.dirname(os.path.realpath(__file__))

packets = []


def setup_module():
    pcap = disspcap.Pcap(f'{dir_path}/pcaps/irc.pcap')
    packet = pcap.next_packet()

    while packet:
        packets.append(packet)
        packet = pcap.next_packet()


def test_irc_prefix():
    assert packets[0].irc.messages[0].prefix == ''
    assert packets[1].irc.messages[0].prefix == ''
    assert packets[3].irc.messages[0].prefix == 'irc.example.net'
    assert packets[15].irc.messages[0].prefix == 'daniel!~daniel@172.17.0.1'
    assert packets[15].irc.messages[1].prefix == 'irc.example.net'


def test_irc_commands():
    assert packets[0].irc.messages[0].command == 'CAP'
    assert packets[1].irc.messages[0].command == 'NICK'
    assert packets[2].irc.messages[0].command == 'USER'
    assert packets[7].irc.messages[0].command == '001'
    assert packets[7].irc.messages[1].command == '002'
    assert packets[7].irc.messages[2].command == '003'
    assert packets[7].irc.messages[3].command == '004'
    assert packets[7].irc.messages[4].command == '005'
    assert packets[7].irc.messages[5].command == '005'
    assert packets[7].irc.messages[6].command == '251'
    assert packets[10].irc.messages[0].command == 'PING'
    assert packets[14].irc.messages[0].command == 'JOIN'
    assert packets[22].irc.messages[0].command == 'PRIVMSG'
    assert packets[24].irc.messages[0].command == 'QUIT'


def test_irc_params():
    assert packets[0].irc.messages[0].params[0] == 'LS'
    assert packets[5].irc.messages[0].params[0] == 'daniel'
    assert packets[5].irc.messages[0].params[1] == 'ACK'
    assert packets[10].irc.messages[0].params[0] == 'irc.example.net'
    assert packets[14].irc.messages[0].params[0] == '#testchannel'


def test_irc_trailing():
    assert packets[3].irc.messages[0].trailing == 'multi-prefix'
    assert packets[7].irc.messages[4].trailing == ('are supported on'
                                                   ' this server')
    assert packets[22].irc.messages[0].trailing == 'Hello world.'
    assert packets[24].irc.messages[0].trailing == 'leaving'
