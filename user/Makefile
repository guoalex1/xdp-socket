CXX = g++
CXXFLAGS = -O3 -Wall

LIBNAME = libxdp_socket.a
SRC = xdp_socket.cpp arp.cpp xdp_loader.cpp
OBJS = $(SRC:.cpp=.o)

all: $(LIBNAME)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(LIBNAME): $(OBJS)
	ar rcs $@ $^

clean:
	rm -f $(OBJS) $(LIBNAME)

PREFIX ?= /usr/local
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include/xdp_socket
HEADER = xdp_socket.h

.PHONY: install uninstall

install: $(LIBNAME)
	install -d $(LIBDIR)
	install -d $(INCLUDEDIR)
	install -m 644 $(LIBNAME) $(LIBDIR)
	install -m 644 $(HEADER) $(INCLUDEDIR)

uninstall:
	rm -f $(LIBDIR)/$(LIBNAME)
	rm -f $(INCLUDEDIR)/$(HEADER)
