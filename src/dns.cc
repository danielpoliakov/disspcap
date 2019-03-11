/**
 * @file dns.cc
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief DNS protocol related.
 * @version 0.1
 * @date 2018-11-16
 * 
 * @copyright Copyright (c) 2018
 * 
 * Based on:
 * https://www.ietf.org/rfc/rfc1035.txt
 * https://www.ietf.org/rfc/rfc4034.txt
 * https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
 * https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
 */

#include "dns.h"

#include <arpa/inet.h>
#include <memory>

namespace disspcap {

/**
 * @brief Construct a new DNS::DNS object and runs parser.
 * 
 * @param data Packets data (starting w/ DNS).
 * @param data_length Data length.
 */
DNS::DNS(uint8_t* data, int data_length)
    : raw_header_{ reinterpret_cast<dns_header*>(data) }
    , remaining_length_(data_length)
    , base_ptr_(data)
{
    this->parse();
}

/**
 * @brief Getter of query x response value.
 * 
 * @return unsigned int 0 for query, 1 for response.
 */
unsigned int DNS::qr() const
{
    return this->qr_;
}

/**
 * @brief Getter of number of entries in question section.
 * 
 * @return unsigned int Number of entries.
 */
unsigned int DNS::question_count() const
{
    return this->question_count_;
}

/**
 * @brief Getter of number of entries in answer section.
 * 
 * @return unsigned int Number of entries.
 */
unsigned int DNS::answer_count() const
{
    return this->answer_count_;
}

/**
 * @brief Getter of number of entries in authority section.
 * 
 * @return unsigned int Number of entries.
 */
unsigned int DNS::authority_count() const
{
    return this->authority_count_;
}

/**
 * @brief Getter of number of entries in additional section.
 * 
 * @return unsigned int Number of entries.
 */
unsigned int DNS::additional_count() const
{
    return this->additional_count_;
}

/**
 * @brief Getter of questions.
 * 
 * @return const std::vector<std::string>& Parsed questions.
 */
const std::vector<std::string>& DNS::questions() const
{
    return this->questions_;
}

/**
 * @brief Getter of answers.
 * 
 * @return const std::vector<std::string>& Parsed answers.
 */
const std::vector<std::string>& DNS::answers() const
{
    return this->answers_;
}

/**
 * @brief Getter of authoritative nameservers.
 * 
 * @return const std::vector<std::string>& Parsed nameservers RRs.
 */
const std::vector<std::string>& DNS::authoritatives() const
{
    return this->authoritatives_;
}

/**
 * @brief Getter of additionals resource records.
 * 
 * @return const std::vector<std::string>& Parsed additoinal RRs.
 */
const std::vector<std::string>& DNS::additionals() const
{
    return this->additionals_;
}

/**
 * @brief Parses DNS.
 */
void DNS::parse()
{
    /* malform packet check */
    if (remaining_length_ < DNS_HDR_LEN)
        return;

    /* header */
    this->qr_               = this->raw_header_->qr__opcode__aa__tc__rd__ra >> 7;
    this->question_count_   = ntohs(this->raw_header_->qdcount);
    this->answer_count_     = ntohs(this->raw_header_->ancount);
    this->authority_count_  = ntohs(this->raw_header_->nscount);
    this->additional_count_ = ntohs(this->raw_header_->arcount);

    /* skip header */
    ptr_ = base_ptr_ + DNS_HDR_LEN;
    remaining_length_ -= DNS_HDR_LEN;

    /* malform packet check */
    if (remaining_length_ <= 0)
        return;

    /* parse questions */
    for (unsigned int i = 0; i < this->question_count_; ++i) {
        std::string ans = this->parse_name();

        struct dns_question* question = reinterpret_cast<dns_question*>(ptr_);
        ans += " " + this->parse_type(ntohs(question->type));
        ptr_ += sizeof(struct dns_question);

        this->questions_.push_back(ans);
    }

    /* parse answers */
    for (unsigned int i = 0; i < this->answer_count_; ++i) {
        std::string ans = this->parse_name();

        struct dns_rr* rr = reinterpret_cast<dns_rr*>(ptr_);

        ans += " " + this->parse_type(ntohs(rr->type));
        ptr_ += sizeof(struct dns_rr);
        ans += " " + this->parse_rdata(ntohs(rr->type), ntohs(rr->rdlength));

        this->answers_.push_back(ans);
    }

    /* parse authoritative servers */
    for (unsigned int i = 0; i < this->authority_count_; ++i) {
        std::string ans = this->parse_name();

        struct dns_rr* rr = reinterpret_cast<dns_rr*>(ptr_);

        ans += " " + this->parse_type(ntohs(rr->type));
        ptr_ += sizeof(struct dns_rr);
        ans += " " + this->parse_rdata(ntohs(rr->type), ntohs(rr->rdlength));

        this->authoritatives_.push_back(ans);
    }

    /* parse additionals rrs */
    for (unsigned int i = 0; i < this->additional_count_; ++i) {
        std::string ans = this->parse_name();

        struct dns_rr* rr = reinterpret_cast<dns_rr*>(ptr_);

        ans += " " + this->parse_type(ntohs(rr->type));
        ptr_ += sizeof(struct dns_rr);
        ans += " " + this->parse_rdata(ntohs(rr->type), ntohs(rr->rdlength));

        this->additionals_.push_back(ans);
    }
}

/**
 * @brief Parses domain names.
 * 
 * @return std::string String representation of domain name.
 */
std::string DNS::parse_name(uint8_t* ptr)
{
    std::string name = "";
    uint8_t* p;
    uint8_t* end_p = nullptr;

    if (!ptr) {
        p = this->ptr_;
    } else {
        p = ptr;
    }

    unsigned int len      = 0;
    unsigned int i        = 0;
    unsigned int watchdog = 0;

    /* name ends w/ 0x00 */
    while (*p) {
        len = *p;

        if (len < 0xc0) {
            /* is string part */
            ++p;

            for (i = 0; i < len; i++) {
                name += *p;
                ++p;
            }

            name += ".";
        } else {
            /* is offset */
            uint16_t offset = *p;

            offset <<= 8;
            ++p;
            offset += *p;
            offset &= 16383;

            /* is endbyte - offset only backwards */
            if (!end_p) {
                end_p = p + 1;
            }

            p = base_ptr_ + offset;
        }

        /* infinite loop watchdog - pointers */
        if (++watchdog > 256) {
            break;
        }
    }

    /* no offset pointers were encountered */
    if (!end_p) {
        end_p = p + 1;
    }

    if (!ptr) {
        ptr_ = end_p;
    }

    if (name.length() == 0) {
        name += ".";
    } else {
        name.pop_back();
    }

    return name;
}

/**
 * @brief Parses type.
 * 
 * @param type Type of RR.
 * @return std::string String representation of type. (e.g. A, MX, NS)
 */
std::string DNS::parse_type(uint16_t type)
{
    switch (type) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 3:
        return "MD";
    case 4:
        return "MF";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 7:
        return "MB";
    case 8:
        return "MG";
    case 9:
        return "MR";
    case 10:
        return "NULL";
    case 11:
        return "WKS";
    case 12:
        return "PTR";
    case 13:
        return "HINFO";
    case 14:
        return "MINFO";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 33:
        return "SRV";
    case 28:
        return "AAAA";
    case 41:
        return "OPT";
    case 43:
        return "DS";
    case 46:
        return "RRSIG";
    case 47:
        return "NSSEC";
    case 48:
        return "DNSKEY";
    case 50:
        return "NSEC3";
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Parses data of resource record.
 * 
 * @param type Type of RR.
 * @return std::string String representation of data.
 */
std::string DNS::parse_rdata(uint16_t type, uint16_t length)
{
    const char hex_arr[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    std::string data = "";
    std::string tmp  = "";

    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;
    struct dns_soa* soa_ptr;
    struct dns_rssig* rssig_ptr;
    struct dns_ds* ds_ptr;
    struct dns_dnskey* dnskey_ptr;

    time_t time_tmp;
    char time_buf[sizeof "2011-10-08T07:07:09Z"];

    char ipv4_buf[INET_ADDRSTRLEN];
    char ipv6_buf[INET6_ADDRSTRLEN];
    uint32_t ip_addr = 0;

    uint8_t* bkup;

    unsigned int tmp_length;
    int16_t preference;

    switch (type) {
    case 1:
        /* A */
        for (int i = 0; i < 4; i++) {
            ip_addr += ptr_[i];
            if (i != 3)
                ip_addr = ip_addr << 8;
        }
        ip_addr = ntohl(ip_addr);

        /* convert ip */
        ipv4_addr.s_addr = ip_addr;
        if (inet_ntop(AF_INET, &ipv4_addr, ipv4_buf, INET_ADDRSTRLEN) == nullptr) {
            data = "INVALID IP";
        } else {
            data = std::string(ipv4_buf);
        }

        ptr_ += length;
        return data;

    case 2:
        /* NS */
        data = this->parse_name(ptr_);
        ptr_ += length;
        return data;

    case 5:
        /* CNAME */
        data = this->parse_name(ptr_);
        ptr_ += length;
        return data;

    case 6:
        /* SOA */
        bkup = ptr_;
        tmp  = this->parse_name(); /* mname */
        data += '"' + tmp + " ";
        tmp = this->parse_name(); /* rname */
        data += tmp + " ";

        soa_ptr = reinterpret_cast<dns_soa*>(ptr_);

        data += std::to_string(ntohl(soa_ptr->serial)) + " ";
        data += std::to_string(ntohl(soa_ptr->refresh)) + " ";
        data += std::to_string(ntohl(soa_ptr->retry)) + " ";
        data += std::to_string(ntohl(soa_ptr->expire)) + " ";
        data += std::to_string(ntohl(soa_ptr->minimum));
        data += '"';

        ptr_ = bkup + length;

        return data;

    case 12:
        /* PTR */
        data = this->parse_name(); /* ptrdname */
        return data;

    case 15:
        /* MX */
        bkup = ptr_;

        /* load prefernce */
        preference = ptr_[0];
        preference <<= 8;
        preference += ptr_[1];

        data = std::to_string(preference) + " ";
        ptr_ += 2;
        data += this->parse_name();

        ptr_ = bkup + length;
        return data;

    case 28:
        /* AAAA */
        for (unsigned int i = 0; i < 16; ++i) {
            ipv6_addr.__in6_u.__u6_addr8[i] = ptr_[i];
        }

        /* convert ip */
        if (inet_ntop(AF_INET6, &ipv6_addr, ipv6_buf, INET6_ADDRSTRLEN) == nullptr) {
            data = "INVALID IPv6";
        } else {
            data = std::string(ipv6_buf);
        }

        ptr_ += length;
        return data;

    case 43:
        /* DS */
        bkup   = ptr_;
        ds_ptr = reinterpret_cast<dns_ds*>(ptr_);
        data   = '"' + std::to_string(ntohs(ds_ptr->key_tag)) + " ";

        data += this->parse_dnssec_algorithm(ds_ptr->algorithm) + " ";
        data += this->parse_digest_type(ds_ptr->digest_type) + " ";

        ptr_ += sizeof(struct dns_ds);

        tmp_length = length - (ptr_ - bkup);

        for (unsigned int i = 0; i < tmp_length; ++i) {
            data += hex_arr[ptr_[i] / 16];
            data += hex_arr[ptr_[i] % 16];
        }

        data += '"';

        ptr_ = bkup + length;
        return data;

    case 46:
        /* RSSIG */
        bkup = ptr_;

        rssig_ptr = reinterpret_cast<dns_rssig*>(ptr_);

        tmp = this->parse_type(ntohs(rssig_ptr->type_covered));
        data += '"' + tmp + " ";

        tmp = this->parse_dnssec_algorithm(rssig_ptr->algorithm);
        data += tmp + " ";

        data += std::to_string(rssig_ptr->labels) + " ";
        data += std::to_string(ntohl(rssig_ptr->original_ttl)) + " ";

        time_tmp = ntohl(rssig_ptr->signature_expiration);
        strftime(time_buf, sizeof(time_buf), "%FT%T", localtime(&time_tmp));
        data += std::string(time_buf) + " ";

        time_tmp = ntohl(rssig_ptr->signature_incepition);
        strftime(time_buf, sizeof(time_buf), "%FT%T", localtime(&time_tmp));
        data += std::string(time_buf) + " ";

        data += std::to_string(ntohs(rssig_ptr->key_tag)) + " ";
        ptr_ += sizeof(struct dns_rssig);

        data += this->parse_name() + " ";

        tmp_length = length - (ptr_ - bkup);

        for (unsigned int i = 0; i < tmp_length; ++i) {
            data += hex_arr[ptr_[i] / 16];
            data += hex_arr[ptr_[i] % 16];
        }

        data += '"';

        ptr_ = bkup + length;
        return data;

    case 47:
        /* NSEC */
        bkup = ptr_;

        data = '"' + this->parse_name() + " ";

        tmp_length = length - (ptr_ - bkup);

        for (unsigned int i = 0; i < tmp_length; ++i) {
            data += hex_arr[ptr_[i] / 16];
            data += hex_arr[ptr_[i] % 16];
        }

        data += '"';

        ptr_ = bkup + length;
        return data;

    case 48:
        /* DNSKEY */
        bkup       = ptr_;
        dnskey_ptr = reinterpret_cast<dns_dnskey*>(ptr_);

        data += "\"0x";

        /* flags */
        for (unsigned int i = 0; i < 2; ++i) {
            data += hex_arr[ptr_[i] / 16];
            data += hex_arr[ptr_[i] % 16];
        }

        /* protocol and algorithm */
        data += " " + std::to_string(dnskey_ptr->protocol);
        data += " " + this->parse_dnssec_algorithm(dnskey_ptr->algorithm) + " ";

        ptr_ += sizeof(struct dns_dnskey);

        tmp_length = length - (ptr_ - bkup);

        /* public key */
        for (unsigned int i = 0; i < tmp_length; ++i) {
            data += hex_arr[ptr_[i] / 16];
            data += hex_arr[ptr_[i] % 16];
        }

        data += '"';

        ptr_ = bkup + length;
        return data;

    default:
        for (unsigned int i = 0; i < length; ++i) {
            data += hex_arr[ptr_[i] / 16];
            data += hex_arr[ptr_[i] % 16];
        }

        ptr_ += length;
        return data;
    }
}

/**
 * @brief Parses DNSSEC algorithm field.
 * 
 * @param algorithm 8-bit algorithm field.
 * @return std::string String representation of algorithm.
 */
std::string DNS::parse_dnssec_algorithm(uint8_t algorithm)
{
    switch (algorithm) {
    case 1:
        return "RSA/MD5";
    case 2:
        return "DH";
    case 3:
        return "DSA/SHA-1";
    case 4:
        return "ECC";
    case 6:
        return "DSA-NSEC3-SHA1";
    case 5:
        return "RSA/SHA-1";
    case 7:
        return "RSASHA1-NSEC3-SHA1";
    case 8:
        return "RSA/SHA-256";
    case 10:
        return "RSA/SHA-512";
    case 12:
        return "ECC-GOST";
    case 13:
        return "ECDSAP256SHA256";
    case 14:
        return "ECDSAP384SHA384";
    case 15:
        return "ED25519";
    case 16:
        return "ED448";
    case 252:
        return "INDIRECT";
    case 253:
        return "PRIVATEDNS";
    case 254:
        return "PRIVATEOID";
    default:
        return "UNKNOWN";
    }
}

/**
 * @brief Parses DS digest type.
 * 
 * @param digest_type 8-bit digest type.
 * @return std::string 
 */
std::string DNS::parse_digest_type(uint8_t digest_type)
{
    switch (digest_type) {
    case 1:
        return "SHA-1";
    case 2:
        return "SHA-256";
    case 3:
        return "ECC-GOST";
    case 4:
        return "SHA-384";
    default:
        return "UNKNOWN";
    }
}
}