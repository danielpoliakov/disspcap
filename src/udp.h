/**
 * @file udp.h
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

#ifndef DISSPCAP_UDP_H_
#define DISSPCAP_UDP_H_

#include <stdint.h>
#include <string>

namespace disspcap {

const uint8_t UDP_LEN = 8; /**< UDP header length. */

/**
 * @brief UDP header struct.
 */
struct udp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

/**
 * @brief UDP class holding UDP related information.
 */
class UDP {
public:
    UDP(uint8_t* data);
    unsigned int source_port() const;
    unsigned int destination_port() const;
    unsigned int length() const;
    unsigned int checksum() const;
    unsigned int payload_length() const;
    uint8_t* payload();

private:
    unsigned int source_port_;
    unsigned int destination_port_;
    unsigned int length_;
    unsigned int checksum_;
    struct udp_header* raw_header_;
    uint8_t* payload_;
    void parse();
};
}

#endif