=============
C++ API
=============

Pcap
****

.. class:: Pcap

    Holds pcap file information and provides
    methods for pcap manipulation.

    .. method:: Pcap()

        Default constructor of a new Pcap::Pcap object.
        Needs opening afterwards.

    .. method:: Pcap(const std::string& filename)
        
        Constructs Pcap objects, opens pcap file and initializes data.

        :param file_name: Path to pcap.

    .. method:: void open_pcap(const std::string& filename)

        Opens pcap. Only needed if Pcap object created with default constructor.

        :param file_name: Path to pcap.

    .. method:: std::unique_ptr<Packet> next_packet()

        Read next packet from a pcap file. Returns nullptr if no more packets.

        :returns: Next :class:`Packet` parsed out of pcap file.


    

Packet
******

.. class:: Packet

    .. method:: Packet(uint8_t* data, unsigned int length)

        Constructor of a new Packet :class:`Packet` object.

        :param data: Pointer to start of pcap bytes.
        :param length: Length of read packet.

    .. method:: const Ethernet* ethernet() const

        :returns: :class:`Ethernet` object or :code:`nullptr`.

    .. method:: const IPv4* ipv4() const

        :returns: :class:`IPv4` object or :code:`nullptr`.

    .. method:: const IPv6* ipv6() const

        :returns: :class:`IPv6` object or :code:`nullptr`.

    .. method:: const UDP* udp() const

        :returns: :class:`UDP` object or :code:`nullptr`.

    .. method:: const TCP* tcp() const

        :returns: :class:`TCP` object or :code:`nullptr`.

    .. method:: const DNS* dns() const

        :returns: :class:`DNS` object or :code:`nullptr`.

    .. method:: const IRC* irc() const
      
        :returns: :class:`IRC` object or :code:`nullptr`.

    .. method:: const Telnet* telnet() const

        :returns: :class:`Telnet` object or :code:`nullptr`.

    .. method:: const HTTP* http() const
      
        :returns: :class:`HTTP` object or :code:`nullptr`.

    .. method:: unsigned int length() const

        :returns: Packet length.

    .. method:: unsigned int payload_length() const

        :returns: Payload length (packet data following transport protocols).

    .. method:: uint8_t* payload()

        :returns: Payload data.


    
Ethernet
********

.. class:: Ethernet

    .. method:: const std::string& source() const

        :returns: Source MAC address. (e.g. :code:`"54:75:d0:c9:0b:81"`)

    .. method:: const std::string& destination() const

        :destination: Source MAC address. (e.g. :code:`"54:75:d0:c9:0b:81"`)

    .. method:: const std::string& type() const

        :returns: :code:`"IPv4"`, :code:`"IPv6"` or :code:`"ARP"`



IPv4
****

.. class:: IPv4

    .. method:: const std::string& source() const

        :returns: Source IPv4 address. (e.g. :code:`"192.168.0.1"`)

    .. method:: const std::string& destination() const

        :returns: Destination IPv4 address. (e.g. :code:`"192.168.0.1"`)

    .. method:: const std::string& protocol() const

        :returns: Next protocol. (e.g., :code:`"TCP"`, :code:`"UDP"`, :code:`"ICMP"`...)

    .. method:: const std::string& header_length() const

        :returns: IPv4 header length.


IPv6
****

.. class:: IPv6

    .. method:: const std::string& source() const

        :returns: Source IPv6 address. (e.g. :code:`"fe80::0202:b3ff:fe1e:8329"`)

    .. method:: const std::string& destination() const

        :returns: Destination IPv6 address. (e.g. :code:`"fe80::0202:b3ff:fe1e:8329"`)

    .. method:: const std::string& next_header() const

        :returns: Next header type. (e.g., :code:`"TCP"`, :code:`"UDP"`, :code:`"ICMP"`...)


UDP
***

.. class:: UDP

    .. method:: unsigned int source_port() const

        :returns: Source port number.

    .. method:: unsigned int destination_port() const

        :returns: Destination port number.


TCP
***

.. class:: TCP

    .. method:: unsigned int source_port() const

        :returns: Source port number.

    .. method:: unsigned int destination_port() const

        :returns: Destination port number.


DNS
***

.. class:: DNS

    .. method:: unsigned int qr() const

        :returns: :code:`0` (Query) or :code:`1` (Response).

    .. method:: unsigned int question_count() const

       :returns:  Number of question entries.

    .. method:: unsigned int answer_count() const

        :returns: Number of answer entries.

    .. method:: unsigned int authority_count() const

        :returns: Number of entries in authoritative NS section.

    .. method:: unsigned int additional_count() const

        :returns: Number of additional resource records.

    .. method:: const std::vector<std::string>& answers() const

        :returns: Answer RRs. Vector of std::string formatted as: :code:`"google.com A 172.217.23.206"`

    .. method:: const std::vector<std::string>& authoritatives() const

        :returns: Authoritative NS RRs. Vector of std::string formatted as: :code:`"google.com NS ns4.google.com"`

    .. method:: const std::vector<std::string>& additionals() const

        :returns: Additional RRs. Vector of std::string formatted as: :code:`"google.com A 172.217.23.206"`


IRC
***

.. class:: IRC

    .. method:: const std::vector<struct irc_message> messages() const

        :returns: Vector of IRC messages.


Telnet
******

.. class:: Telnet

    .. method:: bool is_command() const

        :returns: :code:`true` if Telnet packet is a command.

    .. method:: bool is_data() const

        :returns: :code:`true` if Telnet packet contains message data.

    .. method:: const std::string& data() const

        :returns: Captured Telnet data.


HTTP
****

.. class:: HTTP

    .. method:: bool is_request() const

        :returns: :code:`true` if packet is an HTTP request.

    .. method:: bool is_response() const
      
        :returns: :code:`true` if packet is an HTTP response.

    .. method:: bool non_ascii() const
      
        :returns: :code:`true` if packet contains non ascii symbols in the header.

    .. method:: const std::string& request_method() const
      
        :returns: Request method type (e.g. :code:`"GET"`).

    .. method:: const std::string& request_uri() const
      
        :returns: Request URI value.

    .. method:: const std::string& http_version() const
      
        :returns: HTTP version (e.g. :code:`"HTTP/1.1"`).

    .. method:: const std::string& response_phrase() const
      
        :returns: Response phrase value.

    .. method:: const std::string& status_code() const
      
        :returns: String status code.

    .. method:: std::map<std::string, std::string> headers() const
      
        :returns: Dictionary with HTTP headers values.

    .. method:: uint8_t* body()
      
        :returns: HTTP body data.

    .. method:: unsigned int body_length() const
      
        :returns: Length of the data.

