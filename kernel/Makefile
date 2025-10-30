BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf
OBJ = xdp_filter.o
SRC = xdp_filter.c

all: $(OBJ)

%.o: %.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

.PHONY: all clean
