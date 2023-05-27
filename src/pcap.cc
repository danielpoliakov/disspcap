/**
 * @file pcap.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Pcap handler.
 * @version 0.1
 * @date 2018-10-22
 *
 * @copyright Copyright (c) 2018
 *
 * Based on:
 * https://www.tcpdump.org/pcap.html
 */

#include "pcap.h"

#include <stdexcept>

namespace disspcap {

/**
 * @brief Default construct a new Pcap:: Pcap object.
 *
 * Constructs Pcap object without initialization.
 */
Pcap::Pcap()
    : last_header_{ new struct pcap_pkthdr }
{
}

/**
 * @brief Construct a new Pcap:: Pcap object.
 *
 * Constructs Pcap objects, opens pcap file and initializes data.
 */
Pcap::Pcap(const std::string& filename)
    : last_header_{ new struct pcap_pkthdr }
{
    this->open_pcap(filename);
}

/**
 * @brief Destroy the Pcap:: Pcap object.
 *
 * Destructs Pcap objects, closes pcap file and deletes
 * allocated data.
 */
Pcap::~Pcap()
{
    pcap_close(this->pcap_);
    delete this->last_header_;
}

/**
 * @brief Opens pcap.
 *
 * @param filename Pcap file.
 */
void Pcap::open_pcap(const std::string& filename)
{
    char* arg   = const_cast<char*>(filename.c_str());
    this->pcap_ = pcap_open_offline(arg, this->error_buffer_);

    if (!this->pcap_) {
        throw std::runtime_error("Could not open pcap file.");
    }
}

/**
 * @brief Read next packet from a pcap file. Returns nullptr if no more packets.
 *
 * @return Packet& Reference to next packet object.
 */
std::unique_ptr<Packet> Pcap::next_packet()
{
    uint8_t* data = const_cast<uint8_t*>(pcap_next(this->pcap_, this->last_header_));
    auto packet   = std::unique_ptr<Packet>(new Packet(data, this->last_header_->len, this->last_header_->ts));
    if (packet->raw_data() == nullptr) {
        return nullptr;
    }
    return packet;
}

/**
 * @brief Returns length of last processed packet.
 *
 * @return int Packet length.
 */
int Pcap::last_packet_length() const
{
    return this->last_header_->len;
}
}
