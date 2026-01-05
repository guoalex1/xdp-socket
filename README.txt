xdp-socket is a performant socket interface that uses XDP and XSK for UDP packets

Setup:
Setup dependencies for XDP: https://github.com/xdp-project/xdp-tutorial/blob/main/setup_dependencies.org

Clone https://github.com/xdp-project/xdp-tools and run make install

Build:
Build and install the xdp and userspace programs in the root directory of this repository with 'make install'

Examples:
The directories server and client provide a minimal request-reply example using xdp-sockets

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

Neper:
See https://github.com/guoalex1/neper/tree/xdp-socket for an example of xdp-socket integration
In the xdp-socket branch, run 'make xdp' to build with xdp-sockets (this will require xdp-sockets to be installed to the system via make install)
All tests can be run with the usual commands, udp_rr and udp_stream will use xdp-sockets

Note that the ip address of the interface must be supplied in the command line for xdp-socket creation:
For the server this is done with the -H (or --host) flag, and for the client with the -L (--local-hosts) flag
