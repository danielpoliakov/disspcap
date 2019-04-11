/**
 * @file ipv4.h
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

#ifndef DISSPCAP_IPV4_H_
#define DISSPCAP_IPV4_H_

#include <stdint.h>
#include <string>

namespace disspcap {

const uint8_t IP_IPV6_HOPOPT  = 0x00; /**< IPv6 Hop-by-Hop option. */
const uint8_t IP_ICMP         = 0x01; /**< Internet Control Message Protocol. */
const uint8_t IP_ICMPV6       = 0x3A; /**< Internet Control Message Protocol. */
const uint8_t IP_IGMP         = 0x02; /**< Internet Group Management Protocol. */
const uint8_t IP_TCP          = 0x06; /**< Transmission Control Protocol. */
const uint8_t IP_UDP          = 0x11; /**< User Datagram Protocol. */
const uint8_t IP_IPV6         = 0x29; /**< IPv6 encapsulation. */
const uint8_t IP_IPV6_ROUTE   = 0x2B; /**< IPv6 Routing Header. */
const uint8_t IP_IPV6_FRAG    = 0x2C; /**< IPv6 Fragment Header. */
const uint8_t IP_IPV6_AUTH    = 0x33; /**< IPv6 Authentication Header. */
const uint8_t IP_IPV6_DESTOPT = 0x3C; /**< IPv6 Destination options. */
const uint8_t IP_IPV6_MOB     = 0x87; /**< IPv6 Mobility header. */
const uint8_t IP_IPV6_HOSTID  = 0x8B; /**< IPv6 Host Identity protocol. */
const uint8_t IP_NO_NEXT      = 0x3B; /**< No next header. */

/**
 * @brief IPv4 header struct.
 */
struct ipv4_header {
    uint8_t version__ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_addr;
    uint32_t destination_addr;
} __attribute__((packed));

/**
 * @brief IPv4 class holding IPv4 header information.
 */
class IPv4 {
public:
    IPv4(uint8_t* data);
    const std::string& source() const;
    const std::string& destination() const;
    const std::string& protocol() const;
    unsigned int header_length() const;
    unsigned int payload_length() const;
    uint8_t* payload();

private:
    std::string source_;
    std::string destination_;
    std::string protocol_;
    unsigned int header_length_;
    unsigned int payload_length_;
    struct ipv4_header* raw_header_;
    uint8_t* payload_;
    void parse();
};
}

#endif