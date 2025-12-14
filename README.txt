Setup:
Setup dependencies for XDP: https://github.com/xdp-project/xdp-tutorial/blob/main/setup_dependencies.org

Clone https://github.com/xdp-project/xdp-tools and run make install

Kernel:
To build the XDP filter, run make inside directory 'kernel'

With the xdp-loader from xdp-tools:
sudo xdp-loader load <interface_name> xdp_filter.o --pin-path /sys/fs/bpf/xdp/xsk_filter

User:
Run make inside the directory 'user' and the static library libxdp.a will be built in the same directory

Examples:
The directories server and client provide a minimal request-reply example using xdp_sockets

Server:
Run make inside the directory 'server' to build the server
Usage: sudo ./server -a <interface_ip> -p <port> [-q queue (default: 0)]
Example: sudo ./server -a 192.168.100.6 -p 8888

Client:
Run make inside the directory 'client' to build the client
Usage: sudo ./client -a <interface_ip> -d <dest_ip> -p <port> [-q queue (default: 0)]
Example: sudo ./client -a 192.168.100.5 -d 192.168.100.6 -p 8888

Notes:
The client MUST call xdp_bind to receive replies, a port will not be assigned and binded to if a packet is sent before xdp_bind is called
