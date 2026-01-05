CC = gcc
CFLAGS = -O3 -Wall

LDLIBS = -lxdp_socket -lxdp -lbpf

TARGET = server
SRC = server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET)
