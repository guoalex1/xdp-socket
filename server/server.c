#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../user/xdp_socket.h"

int main(int argc, char** argv) {
    const char* iface_ip = NULL;
    uint32_t queue = 0;
    uint16_t port = 0;

    int opt;
    while ((opt = getopt(argc, argv, "a:q:p:h:")) != -1) {
        switch (opt) {
        case 'a':
            iface_ip = optarg;
            break;
        case 'q':
            queue = atoi(optarg);
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
        default:
            fprintf(stderr, "usage: %s -a <iface_ip> -q <queue> -p <port>\n", argv[0]);
            return -1;
        }
    }

    if (!iface_ip || port == 0) {
        fprintf(stderr, "Msissing required parameters\n");
        return -1;
    }

    struct xdp_socket_config cfg;
    cfg.iface_ip = iface_ip;
    cfg.queue = queue;
    xdp_init_config(&cfg);

    int sockfd = xdp_socket(AF_XDP, SOCK_DGRAM, 0, &cfg);

    if (sockfd < 0) {
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (xdp_bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        return -1;
    }

    char buf[2048];
    while (true) {
        struct sockaddr_in src = {0};
        socklen_t srclen = sizeof(src);
        ssize_t n = xdp_recvfrom(sockfd, buf, sizeof(buf) - 1, 0, (struct sockaddr*)&src, &srclen);

        if (n > 0) {
            buf[n] = '\0';
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src.sin_addr.s_addr, ipstr, sizeof(ipstr));
            printf("Received %zd bytes from %s:%u -> \"%s\"\n", n, ipstr, ntohs(src.sin_port), buf);

            const char* reply = "Reply from server";
            ssize_t sent = xdp_sendto(sockfd, reply, strlen(reply), 0, (struct sockaddr*)&src, srclen);

            if (sent < 0) {
                printf("Error sending reply\n");
            } else {
                printf("Sent reply to %s:%u\n", ipstr, ntohs(src.sin_port));
            }
        }
    }
}
