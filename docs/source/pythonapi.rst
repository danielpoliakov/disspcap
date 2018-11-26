=============
Python API
=============

Pcap
****

.. class:: Pcap

    Holds pcap file information and provides
    methods for pcap manipulation.

    .. method:: __init__(file)

        :param file: Path to pcap.

    .. method:: next_packet()
        
        :returns: Next :class:`Packet` parsed out of pcap file.


Packet
******

.. class:: Packet

    .. attribute:: ethernet

        :class:`Ethernet` object or :code:`None`.

    .. attribute:: ipv4

        :class:`IPv4` object or :code:`None`.

    .. attribute:: ipv6

        :class:`IPv6` object or :code:`None`.

    .. attribute:: udp

        :class:`UDP` object or :code:`None`.

    .. attribute:: tcp

        :class:`TCP` object or :code:`None`.

    .. attribute:: dns

        :class:`DNS` object or :code:`None`.

    .. attribute:: payload_length

        Length of payload transport protocol.

    .. attribute:: payload

        Payload of :code:`bytes` following transport protocol.

    
Ethernet
********

.. class:: Ethernet

    .. attribute:: source

        Source MAC address. (e.g. :code:`'54:75:d0:c9:0b:81'`)

    .. attribute:: destination

        Destination MAC address. (e.g. :code:`'54:75:d0:c9:0b:81'`)

    .. attribute:: type

        :code:`'IPv4'`, :code:`'IPv6'` or :code:`'ARP'`


IPv4
****

.. class:: IPv4

    .. attribute:: source

        Source IPv4 address. (e.g. :code:`'192.168.0.1'`)

    .. attribute:: destination

        Destination IPv4 address. (e.g. :code:`'192.168.0.1'`)

    .. attribute:: protocol

        Next protocol. (e.g. :code:`'TCP'`, :code:`'UDP'`, :code:`'IGMP'`...)

    .. attribute:: header_length

        IPv4 header length.


IPv6
****

.. class:: IPv6

    .. attribute:: source

        Source IPv6 address. (e.g. :code:`'fe80::0202:b3ff:fe1e:8329'`)

    .. attribute:: destination

        Destination IPv6 address. (e.g. :code:`'fe80::0202:b3ff:fe1e:8329'`)

    .. attribute:: next_header

        Next header type. (e.g. :code:`'TCP'`, :code:`'UDP'`, :code:`'IGMP'`...)


UDP
***

.. class:: UDP

    .. attribute:: source_port

        Source port number.

    .. attribute:: destination_port

        Destination port number.


TCP
***

.. class:: TCP

    .. attribute:: source_port

        Source port number.

    .. attribute:: destination_port

        Destination port number.


DNS
***

.. class:: DNS

    .. attribute:: qr

        :code:`0` (Query) or :code:`1` (Response).

    .. attribute:: question_count

        Number of question entries.

    .. attribute:: answer_count

        Number of answer entries.

    .. attribute:: authority_count

        Number of entries in authoritative NS section.

    .. attribute:: additional_count

        Number of additional resource records.

    .. attribute:: answers

        Answer RRs. List of strings formatted as:
        :code:`['google.com A 172.217.23.206', ...]`

    .. attribute:: authoritatives

        Authoritative NS RRs. List of strings formatted as:
        :code:`['google.com NS ns4.google.com', ...]`

    .. attribute:: additionals

        Additional RRs. List of strings formatted as:
        :code:`['google.com A 172.217.23.206', ...]`
