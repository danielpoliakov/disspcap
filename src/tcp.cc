/**
 * @file tcp.cc
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief 
 * @version 0.1
 * @date 2018-11-02
 * 
 * @copyright Copyright (c) 2018
 */

#include "tcp.h"

#include <arpa/inet.h>

namespace disspcap {

/**
 * @brief Construct a new TCP::TCP object and runs parser.
 * 
 * @param data Packets data (starting w/ TCP).
 */
TCP::TCP(uint8_t* data)
    : raw_header_{ reinterpret_cast<tcp_header*>(data) }
{
    this->parse();
}

/**
 * @brief Getter of source port value.
 * 
 * @return unsigned int TCP source port.
 */
unsigned int TCP::source_port() const
{
    return this->source_port_;
}

/**
 * @brief Getter of destination port value.
 * 
 * @return unsigned int TCP destination port.
 */
unsigned int TCP::destination_port() const
{
    return this->destination_port_;
}

/**
 * @brief Getter of sequence number value.
 * 
 * @return unsigned int Sequence number.
 */
unsigned int TCP::seq_number() const
{
    return this->seq_number_;
}

/**
 * @brief Getter of acknowledgement number value.
 * 
 * @return unsigned int Acknowledgement number.
 */
unsigned int TCP::ack_number() const
{
    return this->ack_number_;
}

/**
 * @brief Getter of checksum value.
 * 
 * @return unsigned int TCP header checksum.
 */
unsigned int TCP::checksum() const
{
    return this->checksum_;
}

/**
 * @brief Getter of urgent pointer value.
 * Valid only if urgent control number is set.
 * 
 * @return unsigned int Urgent pointer.
 */
unsigned int TCP::urgent_pointer() const
{
    return this->urgent_pointer_;
}

/**
 * @brief Getter of data offset value.
 * Equeals TCP header length.
 * 
 * @return unsigned int Data offset.
 */
unsigned int TCP::data_offset() const
{
    return this->data_offset_;
}

/**
 * @brief Getter of payload.
 * 
 * @return const uint8_t* Pointer to first byte of payload.
 */
uint8_t* TCP::payload()
{
    return this->payload_;
}

/**
 * @brief Parses TCP header.
 */
void TCP::parse()
{
    this->source_port_      = ntohs(this->raw_header_->source_port);
    this->destination_port_ = ntohs(this->raw_header_->destination_port);
    this->seq_number_       = ntohl(this->raw_header_->sequence_number);
    this->ack_number_       = ntohl(this->raw_header_->acknowledgment_number);
    this->checksum_         = ntohs(this->raw_header_->checksum);
    this->urgent_pointer_   = 42; /* TODO */

    this->data_offset_ = this->raw_header_->data_offset__reserved >> 4;
    this->payload_     = reinterpret_cast<uint8_t*>(this->raw_header_) + (this->data_offset_ * 4);
}
}