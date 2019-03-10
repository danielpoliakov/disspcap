/**
 * @file dns.h
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief DNS protocol related.
 * @version 0.1
 * @date 2018-11-16
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on: 
 * https://www.ietf.org/rfc/rfc1035.txt
 */

#ifndef DISSPCAP_DNS_H
#define DISSPCAP_DNS_H

#include <stdint.h>
#include <string>
#include <vector>

namespace disspcap {

const uint8_t DNS_HDR_LEN = 12; /**< DNS header length. */

/**
 * @brief DNS header part struct.
 */
struct dns_header {
    uint16_t id;
    uint8_t qr__opcode__aa__tc__rd__ra;
    uint8_t z__rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

/**
 * @brief DNS question struct.
 */
struct dns_question {
    uint16_t type;
    uint16_t rr_class;
} __attribute__((packed));

/**
 * @brief DNS resource record struct.
 */
struct dns_rr {
    uint16_t type;
    uint16_t rr_class;
    uint32_t ttl;
    uint16_t rdlength;
} __attribute__((packed));

/**
 * @brief DNS SOA rdata struct.
 */
struct dns_soa {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} __attribute__((packed));

/**
 * @brief DNS RSSIG rdata struct.
 */
struct dns_rssig {
    uint16_t type_covered;
    uint8_t algorithm;
    uint8_t labels;
    uint32_t original_ttl;
    uint32_t signature_expiration;
    uint32_t signature_incepition;
    uint16_t key_tag;
} __attribute__((packed));

/**
 * @brief DNS DS rdata struct.
 */
struct dns_ds {
    uint16_t key_tag;
    uint8_t algorithm;
    uint8_t digest_type;
} __attribute__((packed));

/**
 * @brief DNS DNSKEY rdata struct.
 */
struct dns_dnskey {
    uint16_t flags;
    uint8_t protocol;
    uint8_t algorithm;
} __attribute__((packed));

/**
 * @brief DNS class holding DNS related information.
 */
class DNS {
public:
    DNS(uint8_t* data, int data_length);
    unsigned int qr() const;
    unsigned int question_count() const;
    unsigned int answer_count() const;
    unsigned int authority_count() const;
    unsigned int additional_count() const;
    const std::vector<std::string>& questions() const;
    const std::vector<std::string>& answers() const;
    const std::vector<std::string>& authoritatives() const;
    const std::vector<std::string>& additionals() const;

private:
    unsigned int qr_;
    unsigned int question_count_;
    unsigned int answer_count_;
    unsigned int authority_count_;
    unsigned int additional_count_;
    struct dns_header* raw_header_;
    int remaining_length_;
    uint8_t* ptr_;
    uint8_t* base_ptr_;
    std::vector<std::string> questions_;
    std::vector<std::string> answers_;
    std::vector<std::string> authoritatives_;
    std::vector<std::string> additionals_;
    void parse();
    std::string parse_name(uint8_t* ptr = nullptr);
    std::string parse_type(uint16_t type);
    std::string parse_rdata(uint16_t type, uint16_t length);
    std::string parse_dnssec_algorithm(uint8_t algorithm);
    std::string parse_digest_type(uint8_t digest_type);
};
}

#endif