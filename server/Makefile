CC = gcc
CFLAGS = -O3 -Wall

LDFLAGS = -L../user
LDLIBS = -lxdp_socket -lxdp -lbpf

TARGET = server
SRC = server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
