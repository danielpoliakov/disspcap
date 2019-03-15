/**
 * @file packet.c
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief Contains packet related representations.
 * @version 0.1
 * @date 2018-10-23
 * 
 * @copyright Copyright (c) 2018
 */

#include "packet.h"

#include "ethernet.h"

namespace disspcap {

/**
 * @brief Construct a new Packet:: Packet object and runs parser.
 * 
 * @param length Packet length.
 */
Packet::Packet(uint8_t* data, unsigned int length)
    : length_{ length }
    , payload_length_{ length }
    , raw_data_{ data }
    , ethernet_{ nullptr }
    , ipv4_{ nullptr }
    , ipv6_{ nullptr }
    , udp_{ nullptr }
    , tcp_{ nullptr }
    , dns_{ nullptr }
    , http_{ nullptr }
    , irc_{ nullptr }
{
    if (!data) {
        return;
    }

    this->parse();
}

/**
 * @brief Destroy the Packet:: Packet object.
 * 
 * Releases allocated memory for headers.
 */
Packet::~Packet()
{
    if (this->ethernet_)
        delete this->ethernet_;

    if (this->ipv4_)
        delete this->ipv4_;

    if (this->ipv6_)
        delete this->ipv6_;

    if (this->udp_)
        delete this->udp_;

    if (this->tcp_)
        delete this->tcp_;

    if (this->dns_)
        delete this->dns_;

    if (this->http_)
        delete this->http_;

    if (this->irc_)
        delete this->irc_;
}

/**
 * @brief Getter of packet length value.
 * 
 * @return int Packet length.
 */
unsigned int Packet::length() const
{
    return this->length_;
}

/**
 * @brief Getter of payload length value.
 * 
 * @return int Payload length (see Packet::payload()).
 */
unsigned int Packet::payload_length() const
{
    return this->payload_length_;
}

/**
 * @brief Getter of payload data (after last recognized header).
 *
 * @return uint8_t* Pointer to payload data.
 */
uint8_t* Packet::payload()
{
    return this->payload_;
}

/**
 * @brief Getter of raw data pointer.
 * 
 * @return uint8_t* Pointer to raw data of packet.
 */
uint8_t* Packet::raw_data()
{
    return this->raw_data_;
}

/**
 * @brief Getter of ethernet header.
 * 
 * @return const Ethernet* Ethernet header object.
 */
const Ethernet* Packet::ethernet() const
{
    return this->ethernet_;
}

/**
 * @brief Getter of IPv4 header.
 * 
 * @return const IPv4* IPv4 header object.
 */
const IPv4* Packet::ipv4() const
{
    return this->ipv4_;
}

/**
 * @brief Getter of IPv6 header.
 * 
 * @return const IPv6* IPv6 header object.
 */
const IPv6* Packet::ipv6() const
{
    return this->ipv6_;
}

/**
 * @brief Getter of UDP header.
 * 
 * @return const UDP* UDP header object.
 */
const UDP* Packet::udp() const
{
    return this->udp_;
}

/**
 * @brief Getter of TCP header.
 * 
 * @return const TCP* TCP header object.
 */
const TCP* Packet::tcp() const
{
    return this->tcp_;
}

/**
 * @brief Getter of DNS data.
 * 
 * @return const DNS* DNS object.
 */
const DNS* Packet::dns() const
{
    return this->dns_;
}

/**
 * @brief Getter of HTTP data.
 * 
 * @return const HTTP* HTTP object.
 */
const HTTP* Packet::http() const
{
    return this->http_;
}

/**
 * @brief Getter of IRC data.
 * 
 * @return const IRC* IRC object.
 */
const IRC* Packet::irc() const
{
    return this->irc_;
}

/**
 * @brief Parses raw data into protocol headers.
 */
void Packet::parse()
{
    this->payload_        = this->raw_data_;
    this->payload_length_ = this->length_;

    /* parse ethernet */
    this->ethernet_ = new Ethernet(this->raw_data_);

    if (!this->ethernet_) {
        return;
    }

    this->payload_        = this->ethernet_->payload();
    this->payload_length_ = this->length_ - ETH_LENGTH;

    std::string next_header;

    /* parse ip */
    if (this->ethernet_->type() == "IPv4") {
        this->ipv4_           = new IPv4(this->payload_);
        this->payload_        = this->ipv4_->payload();
        this->payload_length_ = this->ipv4_->payload_length();
        next_header           = this->ipv4_->protocol();
    } else if (this->ethernet_->type() == "IPv6") {
        this->ipv6_           = new IPv6(this->payload_);
        this->payload_        = this->ipv6_->payload();
        this->payload_length_ = this->ipv6_->payload_length();
        next_header           = this->ipv6_->next_header();
    }

    /* parse udp/tcp */
    if (next_header == "UDP") {
        this->udp_            = new UDP(this->payload_);
        this->payload_        = this->udp_->payload();
        this->payload_length_ = this->udp_->payload_length();
    } else if (next_header == "TCP") {
        this->tcp_            = new TCP(this->payload_, this->payload_length_);
        this->payload_        = this->tcp_->payload();
        this->payload_length_ = this->payload_length_ - this->tcp_->data_offset() * 4;
    }

    if (this->udp_) {
        if (this->udp_->source_port() == 53 || this->udp_->destination_port() == 53) {
            /* DNS */
            this->dns_ = new DNS(this->payload_, this->payload_length_);
        }
    }

    if (this->tcp_) {
        if (this->tcp_->source_port() == 53 || this->tcp_->destination_port() == 53) {
            /* DNS */
            uint16_t dns_length = this->payload_[0];
            dns_length <<= 8;
            dns_length += this->payload_[1];

            if (dns_length <= this->payload_length_) {
                this->dns_ = new DNS(this->payload_ + 2, this->payload_length_ - 2);
            }
        }

        if (this->tcp_->source_port() == 80 || this->tcp_->destination_port() == 80) {
            /* HTTP */
            this->http_ = new HTTP(this->payload_, this->payload_length_);
        }

        if (this->tcp_->source_port() == 6667 || this->tcp_->destination_port() == 6667) {
            /* IRC */
            this->irc_ = new IRC(this->payload_, this->payload_length_);
        }
    }
}
}