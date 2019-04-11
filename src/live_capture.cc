/**
 * @file live_capture.cc
 * @author Daniel Uhricek (danile.uhricek@gypri.cz)
 * @brief Live capture of packets.
 * @version 0.1
 * @date 2018-11-16
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://www.tcpdump.org/pcap.html
 */

#include "live_capture.h"

namespace disspcap {

/**
 * @brief Construct a new Live Sniffer:: Live Sniffer object.
 * 
 * @param interface Interface name.
 */
LiveSniffer::LiveSniffer()
    : last_header_{ new struct pcap_pkthdr }
{
}

/**
 * @brief Open interface for sniffing.
 */
void LiveSniffer::start_sniffing(const std::string& interface)
{
    char* arg     = const_cast<char*>(interface.c_str());
    this->handle_ = pcap_open_live(arg, BUFSIZ, 0, 1000, this->error_buffer_);

    if (!this->handle_) {
        throw std::runtime_error("Could not start sniffing.");
    }
}

LiveSniffer::~LiveSniffer()
{
    this->stop_sniffing();
}

/**
 * @brief Closes interface for sniffing.
 */
void LiveSniffer::stop_sniffing()
{
    pcap_close(this->handle_);
}

/**
 * @brief Reads next packet from interface.
 * 
 * @return std::unique_ptr<Packet> Next packet object.
 */
std::unique_ptr<Packet> LiveSniffer::next_packet()
{
    uint8_t* data = const_cast<uint8_t*>(pcap_next(this->handle_, this->last_header_));
    auto packet   = std::unique_ptr<Packet>(new Packet(data, this->last_header_->len));
    if (packet->raw_data() == nullptr) {
        return nullptr;
    }
    return packet;
}

/**
 * @brief Returns length of last captured packet.
 * 
 * @return int Packet length.
 */
int LiveSniffer::last_packet_length() const
{
    return this->last_header_->len;
}
}