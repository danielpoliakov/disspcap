/**
 * @file live_capture.h
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Live capture of packets.
 * @version 0.1
 * @date 2018-11-16
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://www.tcpdump.org/pcap.html
 */

#ifndef DISSPCAP_LIVE_CAPTURE_H
#define DISSPCAP_LIVE_CAPTURE_H

#include <pcap.h>

#include "packet.h"

namespace disspcap {

/**
 * @brief Packet sniffer from interface.
 */
class LiveSniffer {
public:
    LiveSniffer();
    ~LiveSniffer();
    void start_sniffing(const std::string& interface);
    void stop_sniffing();
    std::unique_ptr<Packet> next_packet();
    int last_packet_length() const;

private:
    pcap_t* handle_;
    struct pcap_pkthdr* last_header_;
    char error_buffer_[PCAP_ERRBUF_SIZE];
};
}

#endif