/**
 * @file telnet.cc
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Telnet protocol related.
 * @version 0.1
 * @date 2019-04-11
 * 
 * @copyright Copyright (c) 2019
 */

#include "telnet.h"
#include "common.h"

namespace disspcap {

/**
 * @brief Construct a new Telnet:: Telnet object and runs parser.
 * 
 * @param data Packets data (starting w/ Telnet).
 * @param data_length Data length.
 */
Telnet::Telnet(uint8_t* data, int data_length)
    : is_command_{ false }
    , data_{ "" }
    , ptr_{ data }
    , base_ptr_{ data }
    , end_ptr_{ data + data_length }
{
    if (!data || data_length < 1)
        return;

    this->parse();
}

/**
 * @brief Is Telnet packet command.
 * 
 * @return true Command
 * @return false Data.
 */
bool Telnet::is_command() const
{
    return this->is_command_;
}

/**
 * @brief Is Telnet packet data.
 * 
 * @return true Data.
 * @return false Command.
 */
bool Telnet::is_data() const
{
    return !this->is_command_;
}

bool Telnet::is_empty() const
{
    return this->data_ == "";
}

/**
 * @brief Telnet data getter.
 * 
 * @return const Telnet::std::string& Telnet data.
 */
const std::string& Telnet::data() const
{
    return this->data_;
}

/**
 * @brief Main parse Telnet method.
 */
void Telnet::parse()
{
    /* is command? (commands starts w/ 0xff - IAC) */
    if (*(this->ptr_) == 255) {
        this->is_command_ = true;

        /* not yet implemented parsing commands */
        return;
    }

    /* is data */
    this->is_command_ = false;
    this->parse_data();
}

/**
 * @brief Parses raw Telnet data.
 */
void Telnet::parse_data()
{
    for (uint8_t* p = this->ptr_; p < this->end_ptr_; ++p) {
        unsigned char repr = static_cast<unsigned char>(*p);

        if (isprint(repr) or isspace(repr)) {
            this->data_ += *p;
        } else {
            this->data_ += string_hexa(repr);
        }
    }
}
}