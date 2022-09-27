#pragma once

#include <iostream>     // std::cin, std::cout, std::string, ...
#include <fstream>      // std::ifstream
#include <unistd.h>     // close
#include <sys/socket.h> // socket, AF_INET
#include <sys/types.h>  // some historical (BSD) implementations required this header file, and portable applications are probably wise to include it.
#include <arpa/inet.h>  // inet_ntop
#include <sys/ioctl.h>  // ioctl
#include <net/if.h>     // ifreq
#include <cstdint>      // uint8_t
#include <cstring>      // strncpy
#include <pcap.h>       // pcap

#include "mac.hpp"
#include "ip.hpp"
#include "ethhdr.hpp"
#include "arphdr.hpp"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

#define CREATE_SOCKET_ERROR_MSG "Error: Error while create socket\n"
#define IOCTL_ERROR_MSG "Error: Error while ioctl\n"
#define SEND_PACKET_ERROR_MSG "Error: Error while send packet\n"
#define CLOSE_ERROR_MSG "Error: Error while close file descriptor\n"
#define GET_MAC_ERROR_MSG "Error: Error while get local MAC address\n"

#define PCAP_RECEIVE_PACKET_ERROR "Error : Error while pcap_next_ex: "

bool getMyInfo(const std::string& interface, Mac& MAC, Ip& IP);
bool getMACByIP(pcap_t* pcap, Mac& MAC, const Ip& IP, const Mac& myMAC, const Ip& myIP);

bool sendPacketARP(pcap_t* pcap, 
                   const Mac& destMAC, const Mac& sourceMAC,
                   const Mac& sendMAC, const Ip& sendIP, 
                   const Mac& targetMAC, const Ip& targetIP, 
                   ArpHdr::Mode mode);

bool attackARP(pcap_t* pcap, 
               const Mac& sendMAC, const Ip& sendIP, 
               const Mac& myMAC, const Ip& targetIP);

void printInfo(const Mac& myMAC, const Ip& myIP, 
               const Mac& sendMAC, const Ip& sendIP, 
               const Ip& targetIP);