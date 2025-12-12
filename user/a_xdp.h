#ifndef	A_XDP_H
#define	A_XDP_H	1

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <stdint.h>

struct a_socket_config {
    const char* iface_ip;
    uint32_t queue;
    uint16_t xdp_flags;
    uint32_t queue_length;
};

// Sets default values for xdp_flags and queue_length
void a_init_config(struct a_socket_config* config);

int a_socket(int socket_family, int socket_type, int protocol, const struct a_socket_config* config);

int a_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

int a_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

ssize_t a_sendto(int sockfd, const void* buf, size_t size, int flags, const struct sockaddr* dest_addr, socklen_t addrlen);

ssize_t a_send(int sockfd, const void* buf, size_t size, int flags);

ssize_t a_recvfrom(int sockfd, void* buf, size_t size, int flags, struct sockaddr* src_addr, socklen_t* addrlen);

ssize_t a_recv(int sockfd, void* buf, size_t size, int flags);

int a_close(int fd);

int a_fcntl(int fd, int cmd, ...);

int a_getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen);

int a_setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen);

#ifdef __cplusplus
}
#endif

#endif
