/**
 * @file irc.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief IRC protocol related.
 * @version 0.1
 * @date 2019-03-12
 * 
 * @copyright Copyright (c) 2019
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc2812
 */

#include "irc.h"
#include "common.h"

namespace disspcap {

/**
 * @brief Construct a new IRC::IRC object and runs parser.
 * 
 * @param data Packets data (starting w/ IRC).
 * @param data_length Data length.
 */
IRC::IRC(uint8_t* data, int data_length)
    : ptr_{ data }
    , base_ptr_{ data }
    , end_ptr_{ data + data_length }
{
    this->parse();
}

/**
 * @brief IRC messages getter.
 * 
 * @return const std::vector<struct irc_message> IRC messages.
 */
const std::vector<struct irc_message> IRC::messages() const
{
    return this->messages_;
}

/**
 * @brief Main parse IRC method.
 */
void IRC::parse()
{
    while (this->end_ptr_ - this->ptr_ > 0) {
        struct irc_message message;

        if (*this->ptr_ == ':') {
            /* has prefix */
            ++this->ptr_;
            message.prefix = this->next_string();
        }

        message.command = this->next_string();

        /* params */
        std::string param = this->next_string();

        while (1) {
            if (param == "") {
                /* end of params */
                break;
            }

            if (param[0] == ':') {
                /* trailing - reinterpret */
                this->ptr_ -= param.length();
                message.trailing = this->next_line();
                break;
            }

            message.params.push_back(param);

            param = this->next_string();
        }

        this->messages_.push_back(message);
    }
}

/**
 * @brief Read next string of IRC data.
 * 
 * @param limitter String end - default SP.
 * @return std::string Found string.
 */
std::string IRC::next_string(char limitter)
{
    uint8_t* p       = this->ptr_;
    unsigned int len = 0;

    while (*p && *p != limitter && p < this->end_ptr_) {
        if (!isprint(static_cast<int>(*p))) {
            break;
        }
        ++p;
        ++len;
    }

    std::string str = std::string(reinterpret_cast<const char*>(this->ptr_), len);

    /* skip limitter */
    this->ptr_ = p + 1;

    return str;
}

/**
 * @brief Read next line of IRC data.
 * 
 * @return std::string Line.
 */
std::string IRC::next_line()
{
    uint8_t* p       = this->ptr_;
    unsigned int len = 0;

    while (*p && p < this->end_ptr_ - 1) {
        if (*p == '\r' && *(p + 1) == '\n') {
            break;
        }
        ++p;
        ++len;
    }

    std::string str = std::string(reinterpret_cast<const char*>(this->ptr_), len);

    /* skip CRLF */
    this->ptr_ = p + 2;

    /* check printables */
    for (unsigned int i = 0; i < str.length(); ++i) {
        unsigned char repr = static_cast<unsigned char>(str[i]);

        if (!isprint(repr)) {
            str.replace(i, 1, string_hexa(repr));
        }
    }

    return str;
}
}