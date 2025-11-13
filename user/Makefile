# Compiler and flags
CXX = g++
CXXFLAGS = -O3 -Wall -c -I$(XDP_INCLUDE)

# Output
OBJ = a_xdp.o
SRC = a_xdp.cpp a_arpget.cpp

all: $(OBJ)

$(OBJ): $(SRC)
	$(CXX) $(CXXFLAGS) $^

clean:
	rm -f $(OBJ)
