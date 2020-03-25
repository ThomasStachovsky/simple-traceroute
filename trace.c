/*
Tomasz Stachowski
309675
*/

#include "trace.h"
#include "error.h"

u_int16_t compute_icmp_checksum(const void *buff, int length)
{
    u_int32_t sum;
    const u_int16_t *ptr = buff;
    assert(length % 2 == 0);
    for (sum = 0; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16) + (sum & 0xffff);
    return (u_int16_t)(~(sum + (sum >> 16)));
}

void construct_sockaddr(struct sockaddr_in *address, sa_family_t family, char *address_string)
{
    bzero(address, sizeof(*address));
    address->sin_family = family;
    Inet_pton(address->sin_family, address_string, &(address->sin_addr));
}

void construct_icmphdr(struct icmphdr *header, uint8_t type, uint8_t code, uint16_t id, uint16_t sequence)
{
    header->type = type;
    header->code = code;
    header->un.echo.id = id;
    header->un.echo.sequence = sequence;
    header->checksum = 0;
    header->checksum = compute_icmp_checksum((u_int16_t *)header, sizeof(*header));
}

void reset_replies(int n, struct reply array[n])
{
    for (int i = 0; i < n; i++)
        array[i].replied = 0;
}

void send_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr)
{
    struct icmphdr header;
    for (int i = 0; i < probes; i++, (*seq_ptr)++)
    {
        construct_icmphdr(&header, ICMP_ECHO, 0, id, *seq_ptr);
        Setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
        Sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr *)&dest, sizeof(dest));
    }
}

void set_time(struct timeval *tv, time_t sec, suseconds_t usec)
{
    tv->tv_usec = usec;
    tv->tv_sec = sec;
}

int check_for_answers(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn])
{
    int packets_left = probes_per_turn;
    int ready;
    struct timeval tv;
    set_time(&tv, 0, 1000000);
    fd_set descriptors;
    int destination_reached = 0;
    do
    {
        FD_ZERO(&descriptors);
        FD_SET(sockfd, &descriptors);
        ready = Select(sockfd + 1, &descriptors, NULL, NULL, &tv);
        if (ready > 0)
            receive_packets(sockfd, ttl, id, probes_per_turn, replies, &packets_left, tv, &destination_reached);
    } while (ready > 0 && packets_left > 0);
    return destination_reached;
}

void analize_packet(u_int8_t *buffer, uint8_t *returned_type_p, uint16_t *returned_id_p, uint16_t *returned_seq_p)
{
    struct ip *ip_header;
    ssize_t ip_header_len;
    struct icmphdr *returned_icmp_p;
    uint8_t returned_type;
    uint16_t returned_id;
    uint16_t returned_seq;

    ip_header = (struct ip *)buffer;
    ip_header_len = 4 * ((*(uint8_t *)ip_header) & 0xf); //get the lengh (in bytes) of the IP header
    returned_icmp_p = (void *)ip_header + ip_header_len;
    returned_type = returned_icmp_p->type;

    if (returned_type == ICMP_TIME_EXCEEDED)
    {
        struct icmphdr *old_icmp_p = (void *)returned_icmp_p + ip_header_len + 8; //8 is the sum of lengths of type, code and checksum in the icmp header
        returned_id = old_icmp_p->un.echo.id;
        returned_seq = old_icmp_p->un.echo.sequence;
    }
    else // returned_type == ICMP_ECHOREPLY
    {
        returned_id = returned_icmp_p->un.echo.id;
        returned_seq = returned_icmp_p->un.echo.sequence;
    }

    *returned_type_p = returned_type;
    *returned_seq_p = returned_seq;
    *returned_id_p = returned_id;
}

void receive_packets(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn], int *packets_left_ptr, struct timeval tv, int *destination_reached)
{
    ssize_t packet_len = 0;
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];

    uint8_t returned_type;
    uint16_t returned_id;
    uint16_t returned_seq;

    while (1)
    {
        packet_len = Recvfrom(sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&sender, &sender_len);
        if (packet_len == -1) // Recvfrom returned so packet_len == -1 implies errno == EWOULDBLOCK
            break;

        analize_packet(buffer, &returned_type, &returned_id, &returned_seq);

        if (returned_id == id)
        {
            if (returned_seq / probes_per_turn == ttl || returned_type == ICMP_ECHOREPLY)
            {
                if (returned_type == ICMP_ECHOREPLY)
                    *destination_reached = 1;
                replies[probes_per_turn - *packets_left_ptr].replied = 1;
                replies[probes_per_turn - *packets_left_ptr].sender = sender;
                replies[probes_per_turn - *packets_left_ptr].tv.tv_usec = 1000000 - tv.tv_usec;
                (*packets_left_ptr)--;
            }
            else
                continue;
            if (*packets_left_ptr == 0)
                break;
        }
        else
            break;
    }
}

void print_traceroute(uint16_t probes_per_turn, struct reply replies[probes_per_turn], uint16_t ttl)
{
    int packets = 0;
    struct timeval time_sum;
    set_time(&time_sum, 0, 0);
    char ip_str[20];

    printf("%d", ttl);
    printf(".");

    //a quick solution to keep columns alligned in an output with ten or more rows
    if (ttl < 10)
        printf("  ");
    else
        printf(" ");

    for (int i = 0; i < probes_per_turn; i++)
        if (replies[i].replied)
        {
            packets++;
            time_sum.tv_usec += replies[i].tv.tv_usec;
            int is_address_new = 1;
            for (int j = 0; j < i; j++)
                if (replies[j].sender.sin_addr.s_addr == replies[i].sender.sin_addr.s_addr)
                    is_address_new = 0;
            if (is_address_new)
            {
                Inet_ntop(AF_INET, &(replies[i].sender.sin_addr), ip_str, sizeof(ip_str));
                printf("%s ", ip_str);
            }
        }

    if (packets == 0)
        printf("*\n");
    else if (packets < probes_per_turn)
        printf("???\n");
    else
    {
        printf("%ld", (time_sum.tv_usec / packets) / 1000);
        printf("ms\n");
    }
}

void trace(char *destination_string, uint16_t probes_per_turn, int max_ttl)
{
    struct sockaddr_in destination;
    construct_sockaddr(&destination, AF_INET, destination_string);

    pid_t mypid = getpid();

    struct icmphdr header;
    construct_icmphdr(&header, ICMP_ECHO, 0, mypid, 0);

    int sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct reply replies[probes_per_turn];
    uint16_t seq = probes_per_turn;
    int destination_reached = 0;

    for (int ttl = 1; ttl <= max_ttl; ttl++)
    {
        reset_replies(probes_per_turn, replies);
        send_probes(sockfd, destination, ttl, probes_per_turn, mypid, &seq);
        destination_reached = check_for_answers(sockfd, ttl, mypid, probes_per_turn, replies);
        print_traceroute(probes_per_turn, replies, ttl);
        if (destination_reached)
            break;
    }

    Close(sockfd);
}