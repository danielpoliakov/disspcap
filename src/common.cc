/**
 * @file common.cc
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
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
}