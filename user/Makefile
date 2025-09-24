# Makefile

# Compiler and flags
CXX = g++
CXXFLAGS = -g -O3 -I/home/ubuntu1/xdp-tools/headers

# Output binary
TARGET = xdp

# Source and object files
SRC = xdp.cc
OBJ = xdp.o

# Library path and linked libraries
LDFLAGS = -L/home/ubuntu1/xdp-tools/lib/libxdp/
LDLIBS = -lxdp

# Default target
all: $(TARGET)

# Compile source file to object file
$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Link object file into executable
$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS) $(LDLIBS)

# Clean up
clean:
	rm -f $(TARGET) $(OBJ)
