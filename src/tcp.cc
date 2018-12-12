/**
 * @file tcp.cc
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief 
 * @version 0.1
 * @date 2018-11-02
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc793
 * https://tools.ietf.org/html/rfc3168
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
 * @brief Getter of FLAGS value.
 * 
 * @return unsigned int bit array from TCP header.
 */
unsigned int TCP::flags() const
{
    return this->flags_;
}

/**
 * @brief Congestion Window Reduced flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::cwr() const
{
    return this->flags_ >> 7;
}

/**
 * @brief ECN-Echo flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::ece() const
{
    return (this->flags_ >> 6) & 1;
}

/**
 * @brief Urgent flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::urg() const
{
    return (this->flags_ >> 5) & 1;
}

/**
 * @brief Acknowledgement flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::ack() const
{
    return (this->flags_ >> 4) & 1;
}

/**
 * @brief Push flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::psh() const
{
    return (this->flags_ >> 3) & 1;
}

/**
 * @brief Reset flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::rst() const
{
    return (this->flags_ >> 2) & 1;
}

/**
 * @brief Syn flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::syn() const
{
    return (this->flags_ >> 1) & 1;
}

/**
 * @brief Fin flag.
 * 
 * @return true Flag set.
 * @return false Flag not set.
 */
bool TCP::fin() const
{
    return this->flags_ & 1;
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

    this->flags_ = this->raw_header_->control_bits;

    this->data_offset_ = this->raw_header_->data_offset__reserved >> 4;
    this->payload_     = reinterpret_cast<uint8_t*>(this->raw_header_) + (this->data_offset_ * 4);
}
}