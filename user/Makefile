# Makefile

# Compiler and flags
CXX = g++
CXXFLAGS = -O3 -I/home/ubuntu1/xdp-tools/headers

# Output binary
TARGET = xdp

SRC = xdp.cc

# Library path and linked libraries
LDFLAGS = -L/home/ubuntu1/xdp-tools/lib/libxdp/ -L/home/ubuntu1/xdp-tools/lib/libbpf/
LDLIBS = -lxdp -lbpf

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
