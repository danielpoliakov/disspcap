/**
 * @file irc.h
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

#ifndef DISSPCAP_IRC_H
#define DISSPCAP_IRC_H

#include <stdint.h>
#include <string>
#include <vector>

namespace disspcap {

/**
 * @brief Struct holding message information.
 */
struct irc_message {
    std::string prefix;
    std::string command;
    std::vector<std::string> params;
    std::string trailing;
};

/**
 * @brief IRC class holding IRC messages.
 */
class IRC {
public:
    IRC(uint8_t* data, int data_length);
    const std::vector<struct irc_message> messages() const;

private:
    std::vector<struct irc_message> messages_;
    uint8_t* ptr_;
    uint8_t* base_ptr_;
    uint8_t* end_ptr_;
    void parse();
    std::string next_string(char limitter = ' ');
    std::string next_line();
};
}

#endif