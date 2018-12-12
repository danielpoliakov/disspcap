/**
 * @file tcp.h
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief TCP protocol related.
 * @version 0.1
 * @date 2018-11-02
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc793
 * https://tools.ietf.org/html/rfc3168
 */

#ifndef DISSPCAP_TCP_H_
#define DISSPCAP_TCP_H_

#include <stdint.h>
#include <string>

namespace disspcap {

/**
 * @brief TCP header struct.
 */
struct tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset__reserved;
    uint8_t control_bits;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

/**
 * @brief TCP class holding TCP related information.
 */
class TCP {
public:
    TCP(uint8_t* data);
    unsigned int source_port() const;
    unsigned int destination_port() const;
    unsigned int seq_number() const;
    unsigned int ack_number() const;
    unsigned int checksum() const;
    unsigned int urgent_pointer() const;
    unsigned int data_offset() const;
    unsigned int flags() const;
    bool cwr() const;
    bool ece() const;
    bool urg() const;
    bool ack() const;
    bool psh() const;
    bool rst() const;
    bool syn() const;
    bool fin() const;
    uint8_t* payload();

private:
    unsigned int source_port_;
    unsigned int destination_port_;
    unsigned int seq_number_;
    unsigned int ack_number_;
    unsigned int checksum_;
    unsigned int urgent_pointer_;
    unsigned int data_offset_;
    unsigned int flags_;
    uint8_t* payload_;
    struct tcp_header* raw_header_;
    void parse();
};
}

#endif