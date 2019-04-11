/**
 * @file telnet.h
 * @author Daniel Uhricek (you@domain.com)
 * @brief Telnet protocol related.
 * @version 0.1
 * @date 2019-04-11
 * 
 * @copyright Copyright (c) 2019
 */

#ifndef DISSPCAP_TELNET_H
#define DISSPCAP_TELNET_H

#include <map>
#include <stdint.h>
#include <string>

namespace disspcap {

/**
 * @brief Commands codes.
 */
const std::map<int, std::string> TELNET_COMMANDS = {
    { 240, "SE" },
    { 241, "NOP" },
    { 242, "DM" },
    { 243, "BRK" },
    { 244, "IP" },
    { 245, "AO" },
    { 246, "AYT" },
    { 247, "EC" },
    { 248, "EL" },
    { 249, "GA" },
    { 250, "SB" },
    { 251, "WILL" },
    { 252, "WONT" },
    { 253, "DO" },
    { 254, "DONT" },
    { 255, "IAC" }
};

/**
 * @brief Telnet message class.
 */
class Telnet {
public:
    Telnet(uint8_t* data, int data_length);
    bool is_command() const;
    bool is_data() const;
    bool is_empty() const;
    const std::string& data() const;

private:
    bool is_command_;
    std::string data_;
    uint8_t* ptr_;
    uint8_t* base_ptr_;
    uint8_t* end_ptr_;
    void parse();
    void parse_data();
};
}

#endif