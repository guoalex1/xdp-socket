# Makefile

# Compiler and flags
CXX = g++
CXXFLAGS = -O3 -I$(XDP_INCLUDE)

# Output binary
TARGET = xdp

SRC = xdp.cc

# Library path and linked libraries
LDFLAGS = -L$(XDP_LIB) -L$(BPF_LIB)
LDLIBS = -lxdp -lbpf

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
