CC = gcc
CFLAGS = -O3 -Wall

LDLIBS = -lxdp_socket -lxdp -lbpf

TARGET = client
SRC = client.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f $(TARGET)
