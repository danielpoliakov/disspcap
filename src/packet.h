/**
 * @file packet.h
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief Contains packet related representations. 
 * @version 0.1
 * @date 2018-10-23
 * 
 * @copyright Copyright (c) 2018
 */

#ifndef DISSPCAP_PACKET_H
#define DISSPCAP_PACKET_H

#include <map>
#include <memory>
#include <string>

#include "dns.h"
#include "ethernet.h"
#include "http.h"
#include "ipv4.h"
#include "ipv6.h"
#include "irc.h"
#include "tcp.h"
#include "udp.h"

namespace disspcap {

/**
 * @brief Class representing packet information (headers + data).
 */
class Packet {
public:
    Packet(uint8_t* data, unsigned int length);
    ~Packet();
    unsigned int length() const;
    unsigned int payload_length() const;
    const Ethernet* ethernet() const;
    const IPv4* ipv4() const;
    const IPv6* ipv6() const;
    const UDP* udp() const;
    const TCP* tcp() const;
    const DNS* dns() const;
    const HTTP* http() const;
    const IRC* irc() const;
    uint8_t* raw_data();
    uint8_t* payload();

private:
    unsigned int length_;
    unsigned int payload_length_;
    uint8_t* raw_data_;
    uint8_t* payload_;
    Ethernet* ethernet_;
    IPv4* ipv4_;
    IPv6* ipv6_;
    UDP* udp_;
    TCP* tcp_;
    DNS* dns_;
    HTTP* http_;
    IRC* irc_;
    void parse();
};
}

#endif