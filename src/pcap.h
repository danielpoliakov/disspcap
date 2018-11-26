/**
 * @file pcap.h
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief Pcap handler.
 * @version 0.1
 * @date 2018-10-22
 *
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://www.tcpdump.org/pcap.html
 */

#ifndef DISSPCAP_PCAP_H
#define DISSPCAP_PCAP_H

#include <memory>
#include <pcap.h>
#include <stdint.h>
#include <string>

#include "packet.h"

namespace disspcap {

/**
 * @brief Pcap class for manipulating pcap files.
 */
class Pcap {
public:
    Pcap();
    Pcap(const std::string& filename);
    ~Pcap();
    void open_pcap(const std::string& filename);
    std::unique_ptr<Packet> next_packet();
    int last_packet_length() const;

private:
    pcap_t* pcap_;
    struct pcap_pkthdr* last_header_;
    char error_buffer_[PCAP_ERRBUF_SIZE];
};
}

#endif
