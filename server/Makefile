CC = gcc
CFLAGS = -O3 -Wall

LDFLAGS = -L$(XDP_LIB) -L../user
LDLIBS = -la_xdp -lxdp -lbpf

TARGET = server
SRC = server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
