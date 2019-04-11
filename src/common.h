/**
 * @file common.h
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief Common functions for disspcap library.
 * @version 0.1
 * @date 2018-12-10
 * 
 * @copyright Copyright (c) 2018
 */

#ifndef DISSPCAP_COMMON_H_
#define DISSPCAP_COMMON_H_

#include <string>

namespace disspcap {

std::string most_common_ip(std::string pcap_path);
std::string string_hexa(unsigned char);
}

#endif