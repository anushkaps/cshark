// B/transport.c
#include "cshark.h"

void process_tcp_layer(const unsigned char *packet, int offset, int ip_header_len) {
    (void)ip_header_len; // Suppress unused parameter warning
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + offset);
    
    int src_port = ntohs(tcp_hdr->th_sport);
    int dst_port = ntohs(tcp_hdr->th_dport);
    
    printf("L4 (TCP): Src Port: %d", src_port);
    const char *src_service = get_port_service(src_port);
    if (src_service) {
        printf(" (%s)", src_service);
    }
    
    printf(" | Dst Port: %d", dst_port);
    const char *dst_service = get_port_service(dst_port);
    if (dst_service) {
        printf(" (%s)", dst_service);
    }
    
    printf(" | Seq: %u | Ack: %u\n",
           ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack));
    
    printf("          | Flags: ");
    print_tcp_flags(tcp_hdr->th_flags);
    printf("\n");
    
    unsigned int tcp_header_len = tcp_hdr->th_off * 4;
    
    printf("          Window: %u | Checksum: 0x%04X | Header Length: %u bytes\n",
           ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_sum), tcp_header_len);
    
    int payload_offset = offset + tcp_header_len;
    int total_packet_len = 0;
    
    process_payload(packet, payload_offset, total_packet_len, src_port, dst_port);
}

void process_udp_layer(const unsigned char *packet, int offset) {
    struct udphdr *udp_hdr = (struct udphdr *)(packet + offset);
    
    int src_port = ntohs(udp_hdr->uh_sport);
    int dst_port = ntohs(udp_hdr->uh_dport);
    
    printf("L4 (UDP): Src Port: %d", src_port);
    const char *src_service = get_port_service(src_port);
    if (src_service) {
        printf(" (%s)", src_service);
    }
    
    printf(" | Dst Port: %d", dst_port);
    const char *dst_service = get_port_service(dst_port);
    if (dst_service) {
        printf(" (%s)", dst_service);
    }
    
    printf(" | Length: %u | Checksum:\n          0x%04X\n",
           ntohs(udp_hdr->uh_ulen), ntohs(udp_hdr->uh_sum));
    
    int payload_offset = offset + sizeof(struct udphdr);
    int total_packet_len = 0;
    
    process_payload(packet, payload_offset, total_packet_len, src_port, dst_port);
}

void process_payload(const unsigned char *packet, int offset, int total_len, 
                     int src_port, int dst_port) {
    (void)total_len; // Suppress unused parameter warning
    const char *protocol = NULL;
    
    if (src_port == 80 || dst_port == 80) {
        protocol = "HTTP";
    } else if (src_port == 443 || dst_port == 443) {
        protocol = "HTTPS/TLS";
    } else if (src_port == 53 || dst_port == 53) {
        protocol = "DNS";
    } else {
        protocol = "Unknown";
    }
    
    int port = (dst_port == 80 || dst_port == 443 || dst_port == 53) ? dst_port : src_port;
    
    if (strcmp(protocol, "Unknown") != 0) {
        printf("L7 (Payload): Identified as %s on port %d", protocol, port);
    } else {
        printf("L7 (Payload): Unknown protocol");
    }
    
    const unsigned char *payload = packet + offset;
    int max_display = 64;
    
    printf("\nData (first %d bytes):\n", max_display);
    print_hex_dump(payload, 128, max_display);
}

void print_tcp_flags(unsigned char flags) {
    int first = 1;
    printf("[");
    
    if (flags & TH_FIN) {
        printf("FIN");
        first = 0;
    }
    if (flags & TH_SYN) {
        if (!first) printf(",");
        printf("SYN");
        first = 0;
    }
    if (flags & TH_RST) {
        if (!first) printf(",");
        printf("RST");
        first = 0;
    }
    if (flags & TH_PUSH) {
        if (!first) printf(",");
        printf("PSH");
        first = 0;
    }
    if (flags & TH_ACK) {
        if (!first) printf(",");
        printf("ACK");
        first = 0;
    }
    if (flags & TH_URG) {
        if (!first) printf(",");
        printf("URG");
        first = 0;
    }
    
    printf("]");
}
