BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf
OBJ = xdp_filter.o
SRC = xdp_filter.c

ifdef LIBXDP_OBJECT_PATH
    INSTALL_DIR = $(LIBXDP_OBJECT_PATH)
else
    INSTALL_DIR = /usr/local/lib/bpf
endif

all: $(OBJ)

%.o: %.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

install: $(OBJ)
	install -m 644 $(OBJ) $(INSTALL_DIR)

uninstall:
	rm -f $(INSTALL_DIR)/$(OBJ)

clean:
	rm -f $(OBJ)

.PHONY: all clean install
