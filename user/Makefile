# Compiler and flags
CXX = g++
CXXFLAGS = -O3 -Wall

# Output
LIBNAME = libxdp_socket.a
SRC = xdp_socket.cpp arp.cpp
OBJS = $(SRC:.cpp=.o)

# Default target
all: $(LIBNAME)

# Compile source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Archive into static library
$(LIBNAME): $(OBJS)
	ar rcs $@ $^

clean:
	rm -f $(OBJS) $(LIBNAME)
