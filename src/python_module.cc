/**
 * @file python_module.cpp
 * @author Daniel Uhricek (xuhric00@fit.vutbr.cz)
 * @brief Interface to python using pybind11.
 * @version 0.1
 * @date 2018-10-30
 * 
 * @copyright Copyright (c) 2018
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "common.h"
#include "dns.h"
#include "ethernet.h"
#include "http.h"
#include "ipv4.h"
#include "ipv6.h"
#include "irc.h"
#include "packet.h"
#include "pcap.h"
#include "tcp.h"
#include "udp.h"

using namespace disspcap;

namespace py = pybind11;

PYBIND11_MODULE(disspcap, m)
{
    m.doc() = R"doc(
        Disspcap library - pcap dissector
        -----------------------

        .. currentmodule:: disspcap

        .. autosummary::
           :toctree: _generate
    )doc";

    m.def("most_common_ip", &most_common_ip, "Returns most common ip in pcap.");

    py::class_<irc_message>(m, "irc_message")
        .def_readonly("prefix", &irc_message::prefix)
        .def_readonly("command", &irc_message::command)
        .def_readonly("params", &irc_message::params)
        .def_readonly("trailing", &irc_message::trailing);

    py::class_<IRC>(m, "IRC")
        .def_property_readonly("messages", &IRC::messages);

    py::class_<HTTP>(m, "HTTP")
        .def_property_readonly("is_request", &HTTP::is_request)
        .def_property_readonly("is_response", &HTTP::is_response)
        .def_property_readonly("non_ascii", &HTTP::non_ascii)
        .def_property_readonly("request_method", &HTTP::request_method)
        .def_property_readonly("request_uri", &HTTP::request_uri)
        .def_property_readonly("version", &HTTP::http_version)
        .def_property_readonly("response_phrase", &HTTP::response_phrase)
        .def_property_readonly("status_code", &HTTP::status_code)
        .def_property_readonly("headers", &HTTP::headers)
        .def_property_readonly("body_length", &HTTP::body_length)
        .def_property_readonly("body", [](HTTP& http) {
            uint8_t* bytes = http.body();
            if (bytes == nullptr) {
                return py::bytes("");
            }
            return py::bytes((char*)bytes, http.body_length());
        });

    py::class_<DNS>(m, "DNS")
        .def_property_readonly("qr", &DNS::qr)
        .def_property_readonly("is_incomplete", &DNS::is_incomplete)
        .def_property_readonly("question_count", &DNS::question_count)
        .def_property_readonly("answer_count", &DNS::answer_count)
        .def_property_readonly("authority_count", &DNS::authority_count)
        .def_property_readonly("additional_count", &DNS::additional_count)
        .def_property_readonly("questions", &DNS::questions)
        .def_property_readonly("answers", &DNS::answers)
        .def_property_readonly("authoritatives", &DNS::authoritatives)
        .def_property_readonly("additionals", &DNS::additionals);

    py::class_<Ethernet>(m, "Ethernet")
        .def_property_readonly("destination", &Ethernet::destination)
        .def_property_readonly("source", &Ethernet::source)
        .def_property_readonly("type", &Ethernet::type);

    py::class_<IPv4>(m, "IPv4")
        .def_property_readonly("destination", &IPv4::destination)
        .def_property_readonly("source", &IPv4::source)
        .def_property_readonly("protocol", &IPv4::protocol)
        .def_property_readonly("header_length", &IPv4::header_length);

    py::class_<IPv6>(m, "IPv6")
        .def_property_readonly("next_header", &IPv6::next_header)
        .def_property_readonly("source", &IPv6::source)
        .def_property_readonly("destination", &IPv6::destination)
        .def_property_readonly("hop_limit", &IPv6::hop_limit);

    py::class_<UDP>(m, "UDP")
        .def_property_readonly("source_port", &UDP::source_port)
        .def_property_readonly("destination_port", &UDP::destination_port)
        .def_property_readonly("payload_length", &UDP::payload_length)
        .def_property_readonly("payload", [](UDP& udp) {
            uint8_t* bytes = udp.payload();
            if (bytes == nullptr) {
                return py::bytes("");
            }

            return py::bytes((char*)bytes, udp.payload_length());
        });

    py::class_<TCP>(m, "TCP")
        .def_property_readonly("source_port", &TCP::source_port)
        .def_property_readonly("destination_port", &TCP::destination_port)
        .def_property_readonly("seq_number", &TCP::seq_number)
        .def_property_readonly("ack_number", &TCP::ack_number)
        .def_property_readonly("checksum", &TCP::checksum)
        .def_property_readonly("urgent_pointer", &TCP::urgent_pointer)
        .def_property_readonly("flags", &TCP::flags)
        .def_property_readonly("cwr", &TCP::cwr)
        .def_property_readonly("ece", &TCP::ece)
        .def_property_readonly("urg", &TCP::urg)
        .def_property_readonly("ack", &TCP::ack)
        .def_property_readonly("psh", &TCP::psh)
        .def_property_readonly("rst", &TCP::rst)
        .def_property_readonly("syn", &TCP::syn)
        .def_property_readonly("fin", &TCP::fin)
        .def_property_readonly("payload_length", &TCP::payload_length)
        .def_property_readonly("payload", [](TCP& tcp) {
            uint8_t* bytes = tcp.payload();
            if (bytes == nullptr) {
                return py::bytes("");
            }

            return py::bytes((char*)bytes, tcp.payload_length());
        });

    py::class_<Packet>(m, "Packet")
        .def_property_readonly("ethernet", &Packet::ethernet)
        .def_property_readonly("ipv4", &Packet::ipv4)
        .def_property_readonly("ipv6", &Packet::ipv6)
        .def_property_readonly("udp", &Packet::udp)
        .def_property_readonly("tcp", &Packet::tcp)
        .def_property_readonly("dns", &Packet::dns)
        .def_property_readonly("http", &Packet::http)
        .def_property_readonly("irc", &Packet::irc);

    py::class_<Pcap>(m, "Pcap")
        .def(py::init())
        .def(py::init<const std::string&>())
        .def("open_pcap", &Pcap::open_pcap)
        .def("next_packet", &Pcap::next_packet)
        .def_property_readonly("last_packet_length", &Pcap::last_packet_length);
}