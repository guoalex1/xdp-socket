# Compiler and flags
CXX = g++
CXXFLAGS = -O3 -Wall -c -I$(XDP_INCLUDE)

# Output
OBJ = a_xdp.o
SRC = xdp.cc

all: $(OBJ)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(OBJ)
