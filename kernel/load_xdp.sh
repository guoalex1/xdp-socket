#!/bin/bash
IFACE=$1
BPF_DIR="/sys/fs/bpf/xdp/xsk_filter/$IFACE"
XDP_PROG="xdp_filter.o"

if [ -z "$IFACE" ]; then
    echo "Usage: $0 <interface>"
    exit 1
fi

sudo rm -rf "$BPF_DIR"
sudo mkdir -p "$BPF_DIR"

# -m unspecified will use native mode if available, otherwise skb mode
sudo xdp-loader load -m unspecified "$IFACE" "$XDP_PROG" --pin-path "$BPF_DIR"
