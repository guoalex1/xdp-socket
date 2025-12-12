#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "../user/a_xdp.h"

int main(int argc, char** argv) {
    const char* iface_ip = NULL;
    uint32_t queue = 0;
    uint16_t port = 0;
    const char* dest_ip = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "a:q:p:d:h:")) != -1) {
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
        case 'd':
            dest_ip = optarg;
            break;
        case 'h':
        default:
            fprintf(stderr, "usage: %s -a <iface_ip> -q <queue> -p <port> -d <dest_ip>\n", argv[0]);
            return -1;
        }
    }

    if (!iface_ip || !dest_ip || port == 0) {
        fprintf(stderr, "Missing required parameters\n");
        return -1;
    }

    struct a_socket_config cfg = { .iface_ip = iface_ip, .queue = queue };
    a_init_config(&cfg);

    int sockfd = a_socket(AF_XDP, SOCK_DGRAM, 0, &cfg);

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, dest_ip, &dest.sin_addr);

    a_connect(sockfd, (struct sockaddr*)&dest, sizeof(dest));

    uint32_t src_addr = INADDR_ANY;
    inet_pton(AF_INET, iface_ip, &src_addr);
    struct sockaddr_in bind_addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = src_addr };
    a_bind(sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)); // client must also bind to receive replies

    const char* msg = "Hello from client";
    char buf[2048];

    while (true) {
        ssize_t n = a_send(sockfd, msg, strlen(msg), 0);

        if (n > 0) {
            printf("Sent %zd bytes to %s:%u\n", n, dest_ip, port);

            ssize_t r = a_recv(sockfd, buf, sizeof(buf) - 1, 0);
            if (r > 0) {
                buf[r] = '\0';
                printf("Received reply: \"%s\"\n", buf);
            }
        }

        sleep(1);
    }

    return 0;
}
