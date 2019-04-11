/**
 * @file common.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Common functions for disspcap library.
 * @version 0.1
 * @date 2018-12-10
 * 
 * @copyright Copyright (c) 2018
 */

#include "common.h"

#include <unordered_map>

#include "packet.h"
#include "pcap.h"

namespace disspcap {

/**
 * @brief Reads pcap and returns most common ip address.
 * 
 * @param pcap_path Path to pcap.
 * @return std::string Most common IP.
 */
std::string most_common_ip(std::string pcap_path)
{
    Pcap pcap(pcap_path);

    std::unordered_map<std::string, int> addresses;

    std::unique_ptr<Packet> packet;

    while ((packet = pcap.next_packet()) != nullptr) {
        if (packet->ipv4()) {
            ++addresses[packet->ipv4()->source()];
            ++addresses[packet->ipv4()->destination()];
        } else if (packet->ipv6()) {
            ++addresses[packet->ipv6()->source()];
            ++addresses[packet->ipv6()->destination()];
        }
    }

    std::string most_common_ip = "";
    int most_common_val        = 0;

    for (auto& ip : addresses) {
        if (ip.second > most_common_val) {
            most_common_val = ip.second;
            most_common_ip  = ip.first;
        }
    }

    return most_common_ip;
}

/**
 * @brief Constructs hexadecimal representation string.
 * 
 * @param number Number to represent.
 * @return std::string String - e.g. "\x98".
 */
std::string string_hexa(unsigned char number)
{
    const char hex_arr[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    std::string hexa = "%";
    hexa += hex_arr[number / 16];
    hexa += hex_arr[number % 16];

    return hexa;
}
}