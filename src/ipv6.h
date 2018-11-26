/**
 * @file ipv6.h
 * @author Daniel Uhricek (xuhric00fit.vutbr.cz)
 * @brief IPv6 protocol related.
 * @version 0.1
 * @date 2018-11-03
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc2460
 * https://tools.ietf.org/html/rfc5952
 */

#ifndef DISSPCAP_IPV6_H_
#define DISSPCAP_IPV6_H_

#include <stdint.h>
#include <string>

#include "ipv4.h"

namespace disspcap {

const uint8_t IPV6_LEN = 40; /**< IPv6 header length. */

/* Function declarations */
std::string parse_next_header(uint8_t next_header);

/**
 * @brief IPv6 header struct.
 */
struct ipv6_header {
    uint32_t version__trafic_class__flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint16_t source_addr[8];
    uint16_t destination_addr[8];
} __attribute__((packed));

/**
 * @brief Hop-by-Hop Options Header.
 */
struct ipv6_hop_by_hop_header {
    uint8_t next_header;
    uint8_t hdr_ext_len;
} __attribute__((packed));

/**
 * @brief Routing Header.
 */
struct ipv6_routing_header {
    uint8_t next_header;
    uint8_t hdr_ext_len;
    uint8_t routing_type;
    uint8_t segments_left;
} __attribute__((packed));

/**
 * @brief Destination Options Header.
 */
struct ipv6_destination_header {
    uint8_t next_header;
    uint8_t hdr_ext_len;
} __attribute__((packed));

/**
 * @brief IPv6 class holding IPv6 header information.
 */
class IPv6 {
public:
    IPv6(uint8_t* data);
    const std::string& next_header() const;
    const std::string& source() const;
    const std::string& destination() const;
    unsigned int hop_limit() const;
    unsigned int payload_length() const;
    uint8_t* payload();

private:
    std::string next_header_;
    std::string source_;
    std::string destination_;
    unsigned int hop_limit_;
    unsigned int payload_length_;
    struct ipv6_header* raw_header_;
    uint8_t* payload_;
    void parse();
};
}

#endif