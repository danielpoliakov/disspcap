/**
 * @file http.cc
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

#include "http.h"

#include <algorithm>
#include <cctype>
#include <iterator>

namespace disspcap {

/**
 * @brief Construct a new HTTP::HTTP object and runs parser.
 * 
 * @param data Packets data (starting w/ HTTP).
 * @param data_length Data length.
 */
HTTP::HTTP(uint8_t* data, int data_length)
    : ptr_{ data }
    , base_ptr_{ data }
    , end_ptr_{ data + data_length }
    , body_{ nullptr }
{
    if (!data)
        return;

    this->parse();
}

/**
 * @brief HTTP message is request.
 * 
 * @return true Is request.
 * @return false Is not request.
 */
bool HTTP::is_request() const
{
    return this->req_res_ == 0;
}

/**
 * @brief HTTP message is response.
 * 
 * @return true Is response.
 * @return false Is not response.
 */
bool HTTP::is_response() const
{
    return this->req_res_ == 1;
}

/**
 * @brief Getter of HTTP request method. (GET, POST, ...)
 * 
 * @return const std::string& Request method.
 */
const std::string& HTTP::request_method() const
{
    return this->req_method_;
}

/**
 * @brief Getter of request URI.
 * 
 * @return const std::string& Request URI.
 */
const std::string& HTTP::request_uri() const
{
    return this->req_uri_;
}

/**
 * @brief Getter of HTTP version.
 * 
 * @return const std::string& HTTP version (e.g. HTTP/1.1).
 */
const std::string& HTTP::http_version() const
{
    return this->protocol_;
}

/**
 * @brief Getter of response phrase.
 * 
 * @return const std::string& Response phrase (e.g. OK).
 */
const std::string& HTTP::response_phrase() const
{
    return this->response_phrase_;
}

/**
 * @brief Getter of response status code.
 * 
 * @return const std::string& Status code (e.g. 200, 404, ...).
 */
const std::string& HTTP::status_code() const
{
    return this->status_code_;
}

/**
 * @brief Getter of HTTP headers.
 * 
 * @return const std::vector<std::string>& Array of headers.
 */
const std::vector<std::string>& HTTP::headers() const
{
    return this->headers_;
}

/**
 * @brief Getter of message body.
 * 
 * @return uint8_t* 
 */
uint8_t* HTTP::body()
{
    return this->body_;
}

/**
 * @brief Getter of body length.
 * 
 * @return unsigned int Body length.
 */
unsigned int HTTP::body_length() const
{
    return this->body_length_;
}

/**
 * @brief Main parse HTTP method.
 */
void HTTP::parse()
{
    /* request method */
    this->req_method_ = this->parse_req_method();

    if (this->req_method_ == "") {
        this->ptr_      = this->base_ptr_;
        this->protocol_ = this->parse_protocol();

        if (this->protocol_ == "") {
            /* no headers */
            this->req_res_ = 2;
            return;
        }

        /* response */
        this->req_res_         = 1;
        this->status_code_     = this->next_string();
        this->response_phrase_ = this->next_line();
        this->parse_headers();
        this->body_        = this->ptr_;
        this->body_length_ = this->end_ptr_ - this->ptr_;

    } else {
        /* request */
        this->req_res_  = 0;
        this->req_uri_  = this->next_string();
        this->protocol_ = this->next_line();
        this->parse_headers();
        this->body_        = this->ptr_;
        this->body_length_ = this->end_ptr_ - this->ptr_;
    }
}

/**
 * @brief Read next string of HTTP data.
 * 
 * @param limitter String end - default SP.
 * @return std::string Found string.
 */
std::string HTTP::next_string(char limitter)
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
 * @brief Read next line of HTTP data.
 * 
 * @return std::string Line.
 */
std::string HTTP::next_line()
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

    return str;
}

/**
 * @brief Parses out request method (GET, POST, ...).
 * 
 * @return std::string HTTP request method.
 */
std::string HTTP::parse_req_method()
{
    std::string method = this->next_string();

    for (unsigned int i = 0; i < REQ_METHODS.size(); ++i) {
        if (method == REQ_METHODS[i]) {
            return method;
        }
    }

    return "";
}

/**
 * @brief Parses out protocol version ( e.g. HTTP/1.1).
 * 
 * @return std::string HTTP protocol version.
 */
std::string HTTP::parse_protocol()
{
    std::string proto = this->next_string();

    for (unsigned int i = 0; i < PROTO_VERSIONS.size(); ++i) {
        if (proto == PROTO_VERSIONS[i]) {
            return proto;
        }
    }

    return "";
}

/**
 * @brief Parses out headers information.
 * 
 * Fills this->headers_ vector.
 */
void HTTP::parse_headers()
{
    for (std::string header = next_line(); header != ""; header = next_line()) {
        this->headers_.push_back(header);
    }
}
}
