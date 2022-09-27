# send-arp
## Objective
* Change sender's ARP table

## Component
* sendARP.hpp
    * provide several APIs related to sending ARP packets

## Requirements
* Write the programs using C/C++ programming language
* Find attacker's local IP and MAC address
* Find sender's MAC address from IP by using ARP request
* Use pcap library to send and receive packets

## Reference
* https://stackoverflow.com/questions/6767296/how-to-get-local-ip-and-mac-address-c
* https://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program
* https://blog.silnex.kr/network-basic-ioctl함수와-ifreq구조체/