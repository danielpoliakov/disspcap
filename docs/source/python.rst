======
Python
======

Basics
******

.. code::

    >>> import disspcap
    >>> pcap = disspcap.Pcap('path_to_pcap')
    >>> packet = pcap.next_packet()


Now we can inspect packet.

.. code::

    >>> packet.ethernet.source
    73:15:B8:A6:58:73
    >>> packet.ethernet.type
    IPv4
    >>> packet.ipv4.destination
    105.190.108.167
    >>> packet.ipv4.protocol
    TCP
    >>> packet.tcp.destination_port
    22

    
Examples
********

Simple statistics
-----------------

.. code::

    import disspcap

    ethernet_packets = 0
    ipv4_packets = 0
    ipv6_packets = 0
    tcp_packets = 0
    udp_packets = 0

    pcap = disspcap.Pcap('path_to_pcap')
    packet = pcap.next_packet()

    while packet:
        if (packet.ethernet):
            ethernet_packets += 1

        if (packet.ipv4):
            ipv4_packets += 1

        if (packet.ipv6):
            ipv6_packets += 1

        if (packet.udp):
            udp_packets += 1

        if (packet.tcp):
            tcp_packets += 1

        packet = pcap.next_packet()


    print(f'Number of ethernet packets {ethernet_packets}')
    print(f'Number of ipv4 packets {ipv4_packets}')
    print(f'Number of ipv6 packets {ipv6_packets}')
    print(f'Number of udp packets {udp_packets}')
    print(f'Number of tcp packets {tcp_packets}')


DNS
---

.. code::

    import disspcap

    i = 1
    pcap = disspcap.Pcap('path_to_pcap')
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