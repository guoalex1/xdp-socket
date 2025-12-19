# xdp-socket

xdp-socket is a performant socket interface that uses XDP and XSK for UDP packets

## Setup

- Setup dependencies for XDP: https://github.com/xdp-project/xdp-tutorial/blob/main/setup_dependencies.org

- Clone https://github.com/xdp-project/xdp-tools and run:
  ```sh
  sudo make install
  ```

## Kernel

To build the XDP filter, run:
```sh
make
```
inside directory `kernel`

With the `xdp-loader` from `xdp-tools`:
```sh
sudo xdp-loader load <interface_name> xdp_filter.o --pin-path /sys/fs/bpf/xdp/xsk_filter
```

Example:
```sh
sudo xdp-loader load enp0s3 xdp_filter.o --pin-path /sys/fs/bpf/xdp/xsk_filter
```

## User

Run:
```sh
make
```
inside the directory `user` and the static library `libxdp.a` will be built in the same directory

Install the library and header to the system (/usr/local/lib and /usr/local/include/xdp-socket) with:
```sh
make install
```

## Examples

The directories `server` and `client` provide a minimal request-reply example using `xdp_sockets`

### Server

Run:
```sh
make
```
inside the directory `server` to build the server

Usage:
```sh
sudo ./server -a <interface_ip> -p <port> [-q queue (default: 0)]
```

Example:
```sh
sudo ./server -a 192.168.100.6 -p 8888
```

### Client

Run:
```sh
make
```
inside the directory `client` to build the client

Usage:
```sh
sudo ./client -a <interface_ip> -d <dest_ip> -p <port> [-q queue (default: 0)]
```

Example:
```sh
sudo ./client -a 192.168.100.5 -d 192.168.100.6 -p 8888
```

## Notes

The client **MUST** call `xdp_bind` to receive replies, a port will not be assigned and binded to if a packet is sent before `xdp_bind` is called

## Neper

See https://github.com/guoalex1/neper/tree/xdp-socket for an example of xdp-socket integration

In the xdp-socket branch, run
```sh
make xdp
```
to build with xdp-sockets (this will require xdp-sockets to be installed to the system via make install)

All tests can be run with the usual commands, udp_rr and udp_stream will use xdp-sockets

Note that the ip address of the interface must be supplied in the command line for xdp-socket creation: for the server this is done with the -H (or --host) flag, and for the client with the -L (--local-hosts) flag
