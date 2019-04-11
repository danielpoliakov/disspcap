/**
 * @file ethernet.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Ethernet protocol related.
 * @version 0.1
 * @date 2018-10-24
 * 
 * @copyright Copyright (c) 2018
 */

#include "ethernet.h"

#include <arpa/inet.h>

namespace disspcap {

/**
 * @brief Construct a new Ethernet:: Ethernet object and runs parser.
 * 
 * @param data Packets data.
 */
Ethernet::Ethernet(uint8_t* data)
    : raw_header_{ reinterpret_cast<ethernet_header*>(data) }
{
    this->parse();
}

/**
 * @brief Getter of destination value.
 * 
 * @return const std::string& Destination MAC address.
 */
const std::string& Ethernet::destination() const
{
    return this->destination_;
}

/**
 * @brief Getter of source value.
 * 
 * @return const std::string& Source MAC address.
 */
const std::string& Ethernet::source() const
{
    return this->source_;
}

/**
 * @brief Getter of type value. (IPv4, IPv6, ARP...)
 * 
 * @return const std::string& Type of packet.
 */
const std::string& Ethernet::type() const
{
    return this->type_;
}

/**
 * @brief Returns pointer to data where next_header / payload begins.
 * 
 * @return uint8_t* Pointer to payload data.
 */
uint8_t* Ethernet::payload() const
{
    return this->payload_;
}

/**
 * @brief Parses ethernet header.
 */
void Ethernet::parse()
{
    /* source MAC address */
    this->source_ = str_mac(this->raw_header_->source);

    /* destination MAC address */
    this->destination_ = str_mac(this->raw_header_->destination);

    /* set payload pointer */
    this->payload_ = reinterpret_cast<uint8_t*>(this->raw_header_) + ETH_LENGTH;

    /* next header type */
    switch (ntohs(this->raw_header_->type)) {
    case ETH_IPv4:
        this->type_ = "IPv4";
        break;
    case ETH_IPv6:
        this->type_ = "IPv6";
        break;
    case ETH_ARP:
        this->type_ = "ARP";
        break;
    case ETH_8021Q:
        this->handle_vlan();
        break;
    default:
        this->type_ = "UNKNOWN";
    }
}

/**
 * @brief 802.1Q VLAN handler.
 */
void Ethernet::handle_vlan()
{
    struct vlan_header_8021q* vlan = reinterpret_cast<struct vlan_header_8021q*>(this->payload_);
    this->payload_ += VLAN_LEN;

    switch (ntohs(vlan->type)) {
    case ETH_IPv4:
        this->type_ = "IPv4";
        break;
    case ETH_IPv6:
        this->type_ = "IPv6";
        break;
    case ETH_ARP:
        this->type_ = "ARP";
        break;
    case ETH_8021Q:
        this->handle_vlan();
        break;
    default:
        this->type_ = "UNKNOWN";
    }
}

/**
 * @brief Converts uint8_t* to string MAC address.
 * 
 * @param n Array of uint8_t.
 * @return std::string String representation of MAC address.
 */
std::string str_mac(uint8_t* n)
{
    const char hex_arr[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    std::string mac_addr;

    for (int i = 0; i < ETH_ADDR_LEN; ++i) {
        mac_addr += hex_arr[n[i] / 16];
        mac_addr += hex_arr[n[i] % 16];
        if (i != ETH_ADDR_LEN - 1) {
            mac_addr += ':';
        }
    }

    return mac_addr;
}
}