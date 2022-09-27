CC = g++
CFLAGS = -W -Wall -O2 -DNDEBUG
DEBUGFLAGS = -g -O0 -DDEBUG
OBJECTS = ./ip.o ./mac.o ./arphdr.o ./ethhdr.o ./send-arp.o ./main.o
TARGET = ../bin/send-arp
DTARGET = ../bin/send-arp-test
LIBS = -lpcap

all: $(TARGET)
debug: $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(@) $(OBJECTS) $(LIBS)

$(DTARGET): $(OBJECTS)
	$(CC) $(DEBUGFLAGS) -o $(@) $(OBJECTS) $(LIBS)

main.o: ./main.cpp
send-arp.o: ./send-arp.hpp ./send-arp.cpp
arphdr.o:  ./arphdr.hpp ./arphdr.cpp
ethhdr.o: ./ethhdr.hpp ./ethhdr.cpp
ip.o: ./ip.hpp ./ip.cpp
mac.o : ./mac.hpp ./mac.cpp

clean:
	rm -f $(TARGET)
	rm -f $(DTARGET)
	rm -f *.o

.PHONY: all clean