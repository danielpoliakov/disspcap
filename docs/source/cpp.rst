===
C++
===

Basics
******

.. code:: c++

    #include <disspcap/pcap.h>
    #include <disspcap/packet.h>
    #include <iostream>

    using namespace disspcap;

    int main(int argc, char* argv[])
    {

        Pcap pcap("path_to_pcap");

        auto packet = pcap.next_packet();

        if (packet->ethernet()) {
            std::cout << packet->ethernet()->source() << std::endl;
            std::cout << packet->ethernet()->destination() << std::endl;
            std::cout << packet->ethernet()->type() << std::endl;
        }

        if (packet->ipv4()) {
            std::cout << packet->ipv4()->source() << std::endl;
            std::cout << packet->ipv4()->destination() << std::endl;
            std::cout << packet->ipv4()->protocol() << std::endl;
        }

        if (packet->ipv6()) {
            std::cout << packet->ipv6()->source() << std::endl;
            std::cout << packet->ipv6()->destination() << std::endl;
            std::cout << packet->ipv6()->next_header() << std::endl;
        }

        if (packet->udp()) {
            std::cout << packet->udp()->source_port() << std::endl;
            std::cout << packet->udp()->destination_port() << std::endl;
        }

        if (packet->tcp()) {
            std::cout << packet->tcp()->source_port() << std::endl;
            std::cout << packet->tcp()->destination_port() << std::endl;
        }

        return 0;
    }