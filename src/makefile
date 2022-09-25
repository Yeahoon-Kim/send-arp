CC = g++
CFLAGS = -W -Wall
OBJECTS = ./ip.o ./mac.o ./arphdr.o ./ethhdr.o ./send-arp.o ./main.o
TARGET = ../bin/send-arp
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(@) $(OBJECTS) $(LIBS)

main.o: ./mac.hpp ./mac.cpp ./ip.hpp ./ip.cpp ./ethhdr.hpp ./ethhdr.cpp ./arphdr.hpp ./arphdr.cpp ./send-arp.hpp ./send-arp.cpp ./main.cpp
send-arp.o: ./mac.hpp ./mac.cpp ./ip.hpp ./ip.cpp ./ethhdr.hpp ./ethhdr.cpp ./arphdr.hpp ./arphdr.cpp ./send-arp.hpp ./send-arp.cpp
arphdr.o: ./mac.hpp ./mac.cpp ./ip.hpp ./ip.cpp ./arphdr.hpp ./arphdr.cpp ./arphdr.cpp
ethhdr.o: ./mac.hpp ./mac.cpp ./ethhdr.hpp ./ethhdr.cpp ./ethhdr.cpp
ip.o: ./ip.hpp ./ip.cpp
mac.o : ./mac.hpp ./mac.cpp

clean:
	rm -f $(TARGET)
	rm -f *.o

.PHONY: all clean