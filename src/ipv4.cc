/**
 * @file ip.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief IP protocol related.
 * @version 0.1
 * @date 2018-10-25
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc791
 * https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
 */

#include "ipv4.h"

#include <arpa/inet.h>

namespace disspcap {

/**
 * @brief Construct a new IPv4::IPv4 object and runs parser.
 *
 * @param data Packets data (starting w/ IPv4).
 */
IPv4::IPv4(uint8_t* data)
    : raw_header_{ reinterpret_cast<ipv4_header*>(data) }
{
    this->parse();
}

/**
 * @brief Getter of source value.
 *
 * @return const std::string& Source IP address.
 */
const std::string& IPv4::source() const
{
    return this->source_;
}

/**
 * @brief Getter of destination value.
 *
 * @return const std::string& Destination IP address.
 */
const std::string& IPv4::destination() const
{
    return this->destination_;
}

/**
 * @brief Getter of protocol value.
 *
 * @return const std::string& Next protocol.
 */
const std::string& IPv4::protocol() const
{
    return this->protocol_;
}

/**
 * @brief Getter of header length value.
 *
 * @return int Total IP header length.
 */
unsigned int IPv4::header_length() const
{
    return this->header_length_;
}

/**
 * @brief Getter of payload length value.
 * 
 * @return unsigned int Payload length - see IPv4::payload().
 */
unsigned int IPv4::payload_length() const
{
    return this->payload_length_;
}

/**
 * @brief Returns pointer to data where next_header / payload begins.
 * 
 * @return uint8_t* Pointer to payload data.
 */
uint8_t* IPv4::payload()
{
    return this->payload_;
}

/**
 * @brief Parses ipv4 header.
 */
void IPv4::parse()
{
    /* next protocol */
    switch (this->raw_header_->protocol) {
    case IP_ICMP:
        this->protocol_ = "ICMP";
        break;
    case IP_IGMP:
        this->protocol_ = "IGMP";
        break;
    case IP_TCP:
        this->protocol_ = "TCP";
        break;
    case IP_UDP:
        this->protocol_ = "UDP";
        break;
    default:
        this->protocol_ = "UNKNOWN";
    }

    /* header length */
    this->header_length_ = this->raw_header_->version__ihl & 0xf;

    struct in_addr tmp_addr;
    char buf[INET_ADDRSTRLEN];

    /* source ip */
    tmp_addr.s_addr = this->raw_header_->source_addr;

    if (inet_ntop(AF_INET, &tmp_addr, buf, INET_ADDRSTRLEN) == nullptr) {
        this->source_ = "INVALID";
    } else {
        this->source_ = std::string(buf);
    }

    /* destination ip */
    tmp_addr.s_addr = this->raw_header_->destination_addr;

    if (inet_ntop(AF_INET, &tmp_addr, buf, INET_ADDRSTRLEN) == nullptr) {
        this->destination_ = "INVALID";
    } else {
        this->destination_ = std::string(buf);
    }

    /* set payload  */
    this->payload_        = reinterpret_cast<uint8_t*>(this->raw_header_) + this->header_length_ * 4;
    this->payload_length_ = ntohs(this->raw_header_->total_length) - this->header_length_ * 4;
}
}