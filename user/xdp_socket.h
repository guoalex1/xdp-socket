#ifndef	XDP_SOCKET_H
#define	XDP_SOCKET_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <stdint.h>

struct xdp_socket_config {
    const char* iface_ip;
    uint32_t queue;
    uint16_t xdp_flags;
    uint32_t queue_length;
};

// Sets default values for xdp_flags and queue_length
void xdp_init_config(struct xdp_socket_config* config);

int xdp_socket(int socket_family, int socket_type, int protocol, const struct xdp_socket_config* config);

int xdp_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

int xdp_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

ssize_t xdp_sendto(int sockfd, const void* buf, size_t size, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);

ssize_t xdp_send(int sockfd, const void* buf, size_t size, int flags);

ssize_t xdp_recvfrom(int sockfd, void* buf, size_t size, int flags, struct sockaddr* src_addr, socklen_t* addrlen);

ssize_t xdp_recv(int sockfd, void* buf, size_t size, int flags);

int xdp_close(int fd);

int xdp_fcntl(int fd, int cmd, ...);

int xdp_getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen);

int xdp_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);

#ifdef __cplusplus
}
#endif

#endif
