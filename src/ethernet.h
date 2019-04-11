/**
 * @file ethernet.h
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Ethernet protocol related.
 * @version 0.1
 * @date 2018-10-22
 *
 * @copyright Copyright (c) 2018
 */

#ifndef DISSPCAP_ETHERNET_H_
#define DISSPCAP_ETHERNET_H_

#include <stdint.h>
#include <string>

namespace disspcap {

const int ETH_LENGTH   = 14; /**< Ethernet header length. */
const int ETH_ADDR_LEN = 6;  /**< MAC address length. */
const int VLAN_LEN     = 4;  /**< VLAN - 802.1Q header length. */

const uint16_t ETH_IPv4  = 0x0800; /**< Ethernet IPv4 type value. */
const uint16_t ETH_IPv6  = 0x86DD; /**< Ethernet IPv6 type value. */
const uint16_t ETH_ARP   = 0x0806; /**< Ethernet ARP type value. */
const uint16_t ETH_8021Q = 0x8100; /**< Ethernet 802.1Q type value. */

std::string str_mac(uint8_t*);

/**
 * @brief Ethernet header struct.
 */
struct ethernet_header {
    uint8_t destination[ETH_ADDR_LEN];
    uint8_t source[ETH_ADDR_LEN];
    uint16_t type;
} __attribute__((packed));

/**
 * @brief 802.1Q header sruct.
 */
struct vlan_header_8021q {
    uint16_t pri__dei__id;
    uint16_t type;
} __attribute__((packed));

/**
 * @brief Ethernet class holding ethernet header information.
*/
class Ethernet {
public:
    Ethernet(uint8_t* data);
    const std::string& destination() const;
    const std::string& source() const;
    const std::string& type() const;
    uint8_t* payload() const;

private:
    std::string destination_;
    std::string source_;
    std::string type_;
    struct ethernet_header* raw_header_;
    uint8_t* payload_;
    void parse();
    void handle_vlan();
};
}

#endif
