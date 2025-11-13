# Compiler and flags
CXX = g++
CXXFLAGS = -O3 -Wall -c -I$(XDP_INCLUDE)

# Output
LIBNAME = liba_xdp.a
OBJS = a_xdp.o a_arpget.o
SRC = a_xdp.cpp a_arpget.cpp

# Default target
all: $(LIBNAME)

# Compile source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

# Archive into static library
$(LIBNAME): $(OBJS)
	ar rcs $@ $^

clean:
	rm -f $(OBJS) $(LIBNAME)
