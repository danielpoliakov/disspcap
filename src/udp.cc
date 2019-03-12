/**
 * @file udp.cc
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief UDP protocol related.
 * @version 0.1
 * @date 2018-10-25
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://www.ietf.org/rfc/rfc768.txt
 */

#include "udp.h"

#include <arpa/inet.h>
#include <cstring>

namespace disspcap {

/**
 * @brief Construct a new UDP::UDP object and runs parser.
 * 
 * @param data Packets data (starting w/ UDP).
 */
UDP::UDP(uint8_t* data)
    : raw_header_{ reinterpret_cast<udp_header*>(data) }
    , base_ptr_{ data }
{
    this->parse();
}

/**
 * @brief Destroy the UDP::UDP object.
 */
UDP::~UDP()
{
    if (this->payload_) {
        delete[] this->payload_;
    }
}

/**
 * @brief Getter of source port value.
 * 
 * @return unsigned int UDP source port.
 */
unsigned int UDP::source_port() const
{
    return this->source_port_;
}

/**
 * @brief Getter of destination port value.
 * 
 * @return unsigned int destination port.
 */
unsigned int UDP::destination_port() const
{
    return this->destination_port_;
}

/**
 * @brief Getter of length value.
 * 
 * @return unsigned int Length of UDP header + data.
 */
unsigned int UDP::length() const
{
    return this->length_;
}

/**
 * @brief Getter of checksum value.
 * 
 * @return int Header checksum.
 */
unsigned int UDP::checksum() const
{
    return this->checksum_;
}

/**
 * @brief Getter of payload length value.
 * 
 * @return unsigned int Length of UDP data (excluding header).
 */
unsigned int UDP::payload_length() const
{
    return this->length_ - UDP_LEN;
}

/**
 * @brief Returns pointer to data where next_header / payload begins.
 * 
 * @return uint8_t* Pointer to payload data.
 */
uint8_t* UDP::payload()
{
    return this->payload_;
}

/**
 * @brief Parses UDP header.
 */
void UDP::parse()
{
    this->source_port_      = ntohs(this->raw_header_->source_port);
    this->destination_port_ = ntohs(this->raw_header_->destination_port);
    this->length_           = ntohs(this->raw_header_->length);
    this->checksum_         = ntohs(this->raw_header_->checksum);

    /* allocate and load payload */
    this->payload_ = new uint8_t[this->payload_length()];
    std::memcpy(this->payload_, this->base_ptr_ + UDP_LEN, this->payload_length());
}
}