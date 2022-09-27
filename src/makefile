CXX = g++
CXXFLAGS = -W -Wall -O2
DEBUGFLAGS = -W -Wall -g -O0
OBJECTS = ./ip.o ./mac.o ./arphdr.o ./ethhdr.o ./send-arp.o ./main.o
DOBJECTS = ./ip-test.o ./mac-test.o ./arphdr-test.o ./ethhdr-test.o ./send-arp-test.o ./main-test.o
TARGET = ../bin/send-arp
DTARGET = ../bin/send-arp-test
LIBS = -lpcap

all: $(TARGET)
debug: $(DTARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(@) $(^) $(LIBS)

$(DTARGET): $(DOBJECTS)
	$(CXX) $(DEBUGFLAGS) -o $(@) $(^) $(LIBS)

main.o: ./main.cpp
send-arp.o: ./send-arp.hpp ./send-arp.cpp
arphdr.o:  ./arphdr.hpp ./arphdr.cpp
ethhdr.o: ./ethhdr.hpp ./ethhdr.cpp
ip.o: ./ip.hpp ./ip.cpp
mac.o : ./mac.hpp ./mac.cpp

main-test.o: ./main.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
send-arp-test.o: ./send-arp.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
arphdr-test.o: ./arphdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ethhdr-test.o: ./ethhdr.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
ip-test.o: ./ip.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)
mac-test.o : ./mac.cpp
	$(CXX) -DDEBUG -c -o $(@) $(^)

clean:
	rm -f $(TARGET)
	rm -f $(DTARGET)
	rm -f *.o

.PHONY: all clean