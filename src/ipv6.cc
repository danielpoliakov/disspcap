/**
 * @file ipv6.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief IPv6 related.
 * @version 0.1
 * @date 2018-11-03
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc2460
 * https://tools.ietf.org/html/rfc5952
 */

#include "ipv6.h"

#include <arpa/inet.h>

namespace disspcap {

/**
 * @brief Construct a new IPv6::IPv6 object and runs parser.
 * 
 * @param data Packets data (starting w/ IPv6).
 */
IPv6::IPv6(uint8_t* data)
    : raw_header_{ reinterpret_cast<ipv6_header*>(data) }
{
    this->parse();
}

/**
 * @brief Getter for next header value.
 * 
 * @return const std::string& Next header (or IPv6 option header).
 */
const std::string& IPv6::next_header() const
{
    return this->next_header_;
}

/**
 * @brief Getter for source address value.
 * 
 * @return const std::string& Source IPv6 address.
 */
const std::string& IPv6::source() const
{
    return this->source_;
}

/**
 * @brief Getter for destination address value.
 * 
 * @return const std::string& Destination IPv6 address.
 */
const std::string& IPv6::destination() const
{
    return this->destination_;
}

/**
 * @brief Getter for hop limit value.
 * 
 * @return unsigned int Hop limit.
 */
unsigned int IPv6::hop_limit() const
{
    return this->hop_limit_;
}

/**
 * @brief Getter of payload length value (see IPv6::payload()).
 * 
 * @return unsigned int Payload length.
 */
unsigned int IPv6::payload_length() const
{
    return this->payload_length_;
}

/**
 * @brief Returns pointer to data where next_header / payload begins.
 * 
 * @return uint8_t* Pointer to payload data.
 */
uint8_t* IPv6::payload()
{
    return this->payload_;
}

void IPv6::parse()
{
    /* next header */
    this->next_header_ = parse_next_header(this->raw_header_->next_header);

    /* hop limit */
    this->hop_limit_ = this->raw_header_->hop_limit;

    struct in6_addr tmp_addr;
    char buf[INET6_ADDRSTRLEN];

    /* source address */
    for (unsigned int i = 0; i < 8; i++) {
        tmp_addr.__in6_u.__u6_addr16[i] = this->raw_header_->source_addr[i];
    }

    if (inet_ntop(AF_INET6, &tmp_addr, buf, INET6_ADDRSTRLEN) == nullptr) {
        this->source_ = "INVALID";
    } else {
        this->source_ = std::string(buf);
    }

    /* destination address */
    for (unsigned int i = 0; i < 8; i++) {
        tmp_addr.__in6_u.__u6_addr16[i] = this->raw_header_->destination_addr[i];
    }

    if (inet_ntop(AF_INET6, &tmp_addr, buf, INET6_ADDRSTRLEN) == nullptr) {
        this->destination_ = "INVALID";
    } else {
        this->destination_ = std::string(buf);
    }

    /* get through extension headers and set payload */
    this->payload_        = reinterpret_cast<uint8_t*>(this->raw_header_) + IPV6_LEN;
    this->payload_length_ = ntohs(this->raw_header_->payload_length);

    uint8_t next = this->raw_header_->next_header;
    struct ipv6_hop_by_hop_header* hop_by_hop;
    struct ipv6_routing_header* routing;
    struct ipv6_destination_header* destination;
    unsigned int extension_len;
    unsigned int escape_counter = 0;

    while (next != IP_UDP || next != IP_TCP || next != IP_NO_NEXT) {
        switch (next) {
        case IP_IPV6_HOPOPT:
            hop_by_hop    = reinterpret_cast<ipv6_hop_by_hop_header*>(this->payload_);
            extension_len = (hop_by_hop->hdr_ext_len + 1) * 8;
            next          = hop_by_hop->next_header;
            this->payload_ += extension_len;
            this->payload_length_ -= extension_len;
            break;
        case IP_IPV6_ROUTE:
            routing       = reinterpret_cast<ipv6_routing_header*>(this->payload_);
            extension_len = (routing->hdr_ext_len + 1) * 8;
            next          = routing->next_header;
            this->payload_ += extension_len;
            this->payload_length_ -= extension_len;
            break;
        case IP_IPV6_DESTOPT:
            destination   = reinterpret_cast<ipv6_destination_header*>(this->payload_);
            extension_len = (destination->hdr_ext_len + 1) * 8;
            next          = destination->next_header;
            this->payload_ += extension_len;
            this->payload_length_ -= extension_len;
            break;
        case IP_IPV6_FRAG:
        default:
            ++escape_counter;
            break;
        }

        if (escape_counter >= 10)
            break;
    }

    this->next_header_ = parse_next_header(next);
}

/**
 * @brief Parses next header value.
 * 
 * @param next_header Next header 8-bit representation.
 * @return std::string String representation of next header.
 */
std::string parse_next_header(uint8_t next_header)
{

    switch (next_header) {
    case IP_IPV6_HOPOPT:
        return "IPv6 Hop-by-Hop";
    case IP_ICMP:
        return "ICMP";
    case IP_ICMPV6:
        return "ICMPv6";
    case IP_IGMP:
        return "IGMP";
    case IP_TCP:
        return "TCP";
    case IP_UDP:
        return "UDP";
    case IP_IPV6:
        return "IPv6";
    case IP_IPV6_ROUTE:
        return "IPv6 Routing";
    case IP_IPV6_FRAG:
        return "IPv6 Fragment";
    case IP_IPV6_AUTH:
        return "IPv6 Authentication";
    case IP_IPV6_DESTOPT:
        return "IPv6 Destination";
    case IP_IPV6_MOB:
        return "IPv6 Mobility";
    case IP_IPV6_HOSTID:
        return "IPv6 Host ID";
    default:
        return "UNKNOWN";
    }
}
}