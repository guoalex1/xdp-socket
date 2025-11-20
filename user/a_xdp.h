#ifndef	A_XDP_H
#define	A_XDP_H	1

#include <sys/socket.h>
#include <cstdint>

struct a_socket_config {
    const char* ifname;
    uint32_t queue;
    uint16_t xdp_flags = 0;
    uint32_t queue_length = 16;
};

int a_socket(int socket_family, int socket_type, int protocol, const struct a_socket_config* config);

int a_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

ssize_t a_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);

ssize_t a_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);

int a_close(int fd);

int a_fcntl(int fd, int cmd, ...);

#endif
