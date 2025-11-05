#include <sys/socket.h>
#include <cstdint>

int a_socket(uint32_t queue, const char* ifname);

int a_bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen);

ssize_t a_sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen, const char* dmac);

ssize_t a_recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t addrlen);
