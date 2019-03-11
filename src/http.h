/**
 * @file http.h
 * @author Daniel Uhricek (daniel.uhricek@gypri.cz)
 * @brief HTTP protocol related.
 * @version 0.1
 * @date 2019-03-10
 * 
 * @copyright Copyright (c) 2019
 * 
 * Based on:
 * https://tools.ietf.org/html/rfc2616
 */

#ifndef DISSPCAP_HTTP_H
#define DISSPCAP_HTTP_H

#include <stdint.h>
#include <string>
#include <vector>

namespace disspcap {

/**
 * @brief Request methods.
 */
const std::vector<std::string> REQ_METHODS = {
    "OPTIONS", "GET", "HEAD", "POST", "PUT",
    "DELETE", "TRACE", "CONNECT"
};

/**
 * @brief Protocol versions.
 */
const std::vector<std::string> PROTO_VERSIONS = {
    "HTTP/0.9", "HTTP/1.0", "HTTP/1.1",
    "HTTP/2.0", "HTTP/3.0"
};

/**
 * @brief HTTP class holding HTTP related information.
 */
class HTTP {
public:
    HTTP(uint8_t* data, int data_length);
    bool is_request() const;
    bool is_response() const;
    const std::string& request_method() const;
    const std::string& request_uri() const;
    const std::string& http_version() const;
    const std::string& response_phrase() const;
    const std::string& status_code() const;
    const std::vector<std::string>& headers() const;
    uint8_t* body();
    unsigned int body_length() const;

private:
    std::string req_method_;
    std::string req_uri_;
    std::string protocol_;
    std::string response_phrase_;
    std::string status_code_;
    std::vector<std::string> headers_;
    unsigned int req_res_;
    uint8_t* ptr_;
    uint8_t* base_ptr_;
    uint8_t* end_ptr_;
    uint8_t* body_;
    unsigned int body_length_;
    void parse();
    void parse_headers();
    std::string next_string(char limitter = ' ');
    std::string next_line();
    std::string parse_req_method();
    std::string parse_protocol();
};
}

#endif
