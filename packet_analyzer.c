// B/packet_analyzer.c
#include "cshark.h"

static void print_header_line(unsigned int id, const struct timeval *ts, unsigned int len) {
    printf("-----------------------------------------\n");
    printf("Packet #%u | Timestamp: %ld.%06ld | Length: %u bytes\n",
           id, (long)ts->tv_sec, (long)ts->tv_usec, len);
}

void packet_analyzer(unsigned char *args, const struct pcap_pkthdr *header, 
                     const unsigned char *packet)
{
    (void)args;
    unsigned int new_id = session_packet_counter + 1;
    print_header_line(new_id, &header->ts, header->caplen);

    int offset = 0;
    process_ethernet_layer(packet, &offset);

    // Decide L3 by EtherType (already printed in Ethernet), then branch:
    const struct ether_header *eth = (const struct ether_header*)packet;
    uint16_t etype = ntohs(eth->ether_type);

    if (etype == ETHERTYPE_IP) {
        process_ipv4_layer(packet, &offset);
    } else if (etype == ETHERTYPE_IPV6) {
        process_ipv6_layer(packet, &offset);
    } else if (etype == ETHERTYPE_ARP) {
        process_arp_layer(packet, offset);
    } else {
        // Phase 1 fallback: show first 16 bytes
        puts("L3: Unknown EtherType. Showing first 16 bytes:");
        print_hex_dump(packet, header->caplen, 16);
    }
}

void process_ethernet_layer(const unsigned char *packet, int *offset) {
    const struct ether_header *eth = (const struct ether_header*)packet;
    printf("L2 (Ethernet): Dst MAC: ");
    print_mac_address(eth->ether_dhost);
    printf(" | Src MAC: ");
    print_mac_address(eth->ether_shost);
    uint16_t etype = ntohs(eth->ether_type);

    const char *etype_str = "Unknown";
    if (etype == ETHERTYPE_IP) etype_str = "IPv4 (0x0800)";
    else if (etype == ETHERTYPE_ARP) etype_str = "ARP (0x0806)";
    else if (etype == ETHERTYPE_IPV6) etype_str = "IPv6 (0x86DD)";

    printf(" | EtherType: %s\n", etype_str);

    *offset = sizeof(struct ether_header);
}

void process_ipv4_layer(const unsigned char *packet, int *offset) {
    const struct ip *iph = (const struct ip *)(packet + *offset);
    int ip_hl_bytes = iph->ip_hl * 4;

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));

    const char *proto_str = "Unknown";
    if (iph->ip_p == IPPROTO_TCP) proto_str = "TCP (6)";
    else if (iph->ip_p == IPPROTO_UDP) proto_str = "UDP (17)";

    printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s |\n", src, dst, proto_str);
    printf("TTL: %d\n", iph->ip_ttl);
    printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes\n",
           ntohs(iph->ip_id), ntohs(iph->ip_len), ip_hl_bytes);
    
    // Decode fragmentation flags
    uint16_t frag_off = ntohs(iph->ip_off);
    int df_flag = (frag_off & 0x4000) ? 1 : 0;  // Don't Fragment
    int mf_flag = (frag_off & 0x2000) ? 1 : 0;  // More Fragments
    int frag_offset = (frag_off & 0x1FFF) * 8;  // Fragment offset in bytes
    
    printf("Flags: [");
    if (df_flag) printf("DF");
    if (mf_flag) printf("%sMF", df_flag ? "," : "");
    if (!df_flag && !mf_flag) printf("None");
    printf("] | Fragment Offset: %d\n", frag_offset);

    *offset += ip_hl_bytes;

    if (iph->ip_p == IPPROTO_TCP) {
        process_tcp_layer(packet, *offset, ip_hl_bytes);
    } else if (iph->ip_p == IPPROTO_UDP) {
        process_udp_layer(packet, *offset);
    }
}

void process_ipv6_layer(const unsigned char *packet, int *offset) {
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + *offset);

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

    uint8_t next = ip6->ip6_nxt; // Next Header
    const char *nh_str = "Unknown";
    if (next == IPPROTO_TCP) nh_str = "TCP (6)";
    else if (next == IPPROTO_UDP) nh_str = "UDP (17)";

    uint16_t payload_len = ntohs(ip6->ip6_plen);

    // Traffic Class + Flow Label extraction from first 4 bytes of vtc_flow (network-order)
    uint32_t vtc_flow = ntohl(*(const uint32_t*)ip6);
    uint8_t traffic_class = (uint8_t)((vtc_flow >> 20) & 0xFF);
    uint32_t flow_label = vtc_flow & 0x000FFFFF;

    printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s | Hop Limit: %d\n",
           src, dst, nh_str, ip6->ip6_hops);
    printf("Traffic Class: %u | Flow Label: 0x%05X | Payload Length: %u\n",
           traffic_class, flow_label, payload_len);

    *offset += sizeof(struct ip6_hdr);

    if (next == IPPROTO_TCP) {
        process_tcp_layer(packet, *offset, 0 /*not used for v6*/);
    } else if (next == IPPROTO_UDP) {
        process_udp_layer(packet, *offset);
    }
}

void process_arp_layer(const unsigned char *packet, int offset) {
    (void)offset;
    const struct ether_arp *arp = (const struct ether_arp *)(packet + sizeof(struct ether_header));

    uint16_t op = ntohs(arp->ea_hdr.ar_op);
    const char *op_str = (op == ARPOP_REQUEST) ? "Request (1)" :
                         (op == ARPOP_REPLY)   ? "Reply (2)"   : "Unknown";
    printf("L3 (ARP): Operation: %s | ", op_str);

    char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, sip, sizeof(sip));
    inet_ntop(AF_INET, arp->arp_tpa, tip, sizeof(tip));

    printf("Sender IP: %s | Target IP: %s\n", sip, tip);
    printf("Sender MAC: ");
    print_mac_address(arp->arp_sha);
    printf(" | Target MAC: ");
    print_mac_address(arp->arp_tha);
    printf("\n");

    printf("HW Type: %u | Proto Type: 0x%04X | HW Len: %u | Proto Len: %u\n",
           ntohs(arp->ea_hdr.ar_hrd), ntohs(arp->ea_hdr.ar_pro),
           arp->ea_hdr.ar_hln, arp->ea_hdr.ar_pln);
}

// Detailed layer processing functions for packet inspection
// ############## LLM Generated Code Begins ##############
void process_ethernet_layer_detailed(const unsigned char *packet, int *offset, int total_len) {
    if (total_len < (int)sizeof(struct ether_header)) {
        printf("🔸 ETHERNET II FRAME (Layer 2)\n\n");
        printf("   [Frame too short for Ethernet header]\n");
        return;
    }
    
    const struct ether_header *eth = (const struct ether_header*)packet;
    uint16_t etype = ntohs(eth->ether_type);
    
    printf("🔸 ETHERNET II FRAME (Layer 2)\n\n");
    printf("Destination MAC:    ");
    print_mac_address(eth->ether_dhost);
    printf(" (Bytes 0-5)\n");
    printf("   └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    
    printf("Source MAC:         ");
    print_mac_address(eth->ether_shost);
    printf(" (Bytes 6-11)\n");
    printf("   └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    
    const char *etype_str = "Unknown";
    if (etype == ETHERTYPE_IP) etype_str = "IPv4";
    else if (etype == ETHERTYPE_ARP) etype_str = "ARP";
    else if (etype == ETHERTYPE_IPV6) etype_str = "IPv6";
    
    printf("EtherType:          0x%04X (%s) (Bytes 12-13)\n", etype, etype_str);
    printf("   └─ Hex: %02X %02X\n\n", packet[12], packet[13]);
    
    *offset = sizeof(struct ether_header);
}

void process_ipv4_layer_detailed(const unsigned char *packet, int *offset, int total_len) {
    if (total_len < *offset + (int)sizeof(struct ip)) {
        printf("🔸 IPV4 HEADER (Layer 3)\n\n");
        printf("   [Packet too short for IPv4 header]\n");
        return;
    }
    
    const struct ip *iph = (const struct ip *)(packet + *offset);
    int ip_hl_bytes = iph->ip_hl * 4;
    
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));
    
    printf("🔸 IPV4 HEADER (Layer 3)\n\n");
    printf("Version:            %d (4-bit field in byte %d)\n", iph->ip_v, *offset);
    printf("Header Length:      %d bytes (5 * 4) (4-bit field in byte %d)\n", ip_hl_bytes, *offset);
    printf("   └─ Hex: 0x%02X (upper 4 bits = 4, lower 4 bits = 5)\n", packet[*offset]);
    
    printf("Type of Service:    0x%02X (Byte %d)\n", iph->ip_tos, *offset + 1);
    printf("   └─ DSCP: %d, ECN: %d\n", iph->ip_tos >> 2, iph->ip_tos & 0x03);
    
    printf("Total Length:       %d bytes (Bytes %d-%d)\n", ntohs(iph->ip_len), *offset + 2, *offset + 3);
    printf("   └─ Hex: %02X %02X\n", packet[*offset + 2], packet[*offset + 3]);
    
    printf("Identification:     0x%04X (51981) (Bytes %d-%d)\n", ntohs(iph->ip_id), *offset + 4, *offset + 5);
    printf("   └─ Hex: %02X %02X\n", packet[*offset + 4], packet[*offset + 5]);
    
    uint16_t frag_off = ntohs(iph->ip_off);
    int reserved = (frag_off & 0x8000) >> 15;
    int df_flag = (frag_off & 0x4000) ? 1 : 0;
    int mf_flag = (frag_off & 0x2000) ? 1 : 0;
    int frag_offset = (frag_off & 0x1FFF) * 8;
    
    printf("Flags:              0x%04X (Byte %d-21)\n", frag_off >> 13, *offset + 6);
    printf("   └─ Reserved: %d, Don't Fragment: %d, More Fragments: %d\n", reserved, df_flag, mf_flag);
    printf("Fragment Offset:    %d bytes\n", frag_offset);
    
    printf("Time to Live:       %d (Byte %d)\n", iph->ip_ttl, *offset + 8);
    printf("   └─ Hex: %02X\n", packet[*offset + 8]);
    
    const char *proto_str = "Unknown";
    if (iph->ip_p == IPPROTO_TCP) proto_str = "TCP";
    else if (iph->ip_p == IPPROTO_UDP) proto_str = "UDP";
    else if (iph->ip_p == IPPROTO_ICMP) proto_str = "ICMP";
    
    printf("Protocol:           %d (%s) (Byte %d)\n", iph->ip_p, proto_str, *offset + 9);
    printf("   └─ Hex: %02X\n", packet[*offset + 9]);
    
    printf("Header Checksum:    0x%04X (Bytes %d-%d)\n", ntohs(iph->ip_sum), *offset + 10, *offset + 11);
    printf("   └─ Hex: %02X %02X\n", packet[*offset + 10], packet[*offset + 11]);
    
    printf("Source IP:          %s (Bytes %d-%d)\n", src, *offset + 12, *offset + 15);
    printf("   └─ Hex: %02X %02X %02X %02X\n",
           packet[*offset + 12], packet[*offset + 13], packet[*offset + 14], packet[*offset + 15]);
    
    printf("Destination IP:     %s (Bytes %d-%d)\n", dst, *offset + 16, *offset + 19);
    printf("   └─ Hex: %02X %02X %02X %02X\n\n",
           packet[*offset + 16], packet[*offset + 17], packet[*offset + 18], packet[*offset + 19]);
    
    *offset += ip_hl_bytes;
    
    if (iph->ip_p == IPPROTO_TCP) {
        process_tcp_layer_detailed(packet, *offset, total_len);
    } else if (iph->ip_p == IPPROTO_UDP) {
        process_udp_layer_detailed(packet, *offset, total_len);
    }
}

void process_ipv6_layer_detailed(const unsigned char *packet, int *offset, int total_len) {
    if (total_len < *offset + (int)sizeof(struct ip6_hdr)) {
        printf("🔸 IPV6 HEADER (Layer 3)\n\n");
        printf("   [Packet too short for IPv6 header]\n");
        return;
    }
    
    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + *offset);
    
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
    
    uint32_t vtc_flow = ntohl(*(const uint32_t*)ip6);
    uint8_t version = (vtc_flow >> 28) & 0x0F;
    uint8_t traffic_class = (uint8_t)((vtc_flow >> 20) & 0xFF);
    uint32_t flow_label = vtc_flow & 0x000FFFFF;
    
    printf("🔸 IPV6 HEADER (Layer 3)\n\n");
    printf("Version:            %d\n", version);
    printf("Traffic Class:      %u\n", traffic_class);
    printf("Flow Label:         0x%05X\n", flow_label);
    printf("Payload Length:     %u\n", ntohs(ip6->ip6_plen));
    printf("Next Header:        %d (%s)\n", ip6->ip6_nxt,
           (ip6->ip6_nxt == IPPROTO_TCP) ? "TCP" :
           (ip6->ip6_nxt == IPPROTO_UDP) ? "UDP" : "Unknown");
    printf("Hop Limit:          %d\n", ip6->ip6_hops);
    printf("Source IP:          %s\n", src);
    printf("Destination IP:     %s\n\n", dst);
    
    *offset += sizeof(struct ip6_hdr);
    
    if (ip6->ip6_nxt == IPPROTO_TCP) {
        process_tcp_layer_detailed(packet, *offset, total_len);
    } else if (ip6->ip6_nxt == IPPROTO_UDP) {
        process_udp_layer_detailed(packet, *offset, total_len);
    }
}

void process_arp_layer_detailed(const unsigned char *packet, int offset, int total_len) {
    if (total_len < offset + (int)sizeof(struct ether_arp)) {
        printf("🔸 ARP PACKET (Layer 3)\n\n");
        printf("   [Packet too short for ARP]\n");
        return;
    }
    
    const struct ether_arp *arp = (const struct ether_arp *)(packet + sizeof(struct ether_header));
    
    uint16_t op = ntohs(arp->ea_hdr.ar_op);
    const char *op_str = (op == ARPOP_REQUEST) ? "Request" :
                         (op == ARPOP_REPLY)   ? "Reply"   : "Unknown";
    
    char sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, sip, sizeof(sip));
    inet_ntop(AF_INET, arp->arp_tpa, tip, sizeof(tip));
    
    printf("🔸 ARP PACKET (Layer 3)\n\n");
    printf("Hardware Type:      %u\n", ntohs(arp->ea_hdr.ar_hrd));
    printf("Protocol Type:      0x%04X\n", ntohs(arp->ea_hdr.ar_pro));
    printf("Hardware Length:    %u\n", arp->ea_hdr.ar_hln);
    printf("Protocol Length:    %u\n", arp->ea_hdr.ar_pln);
    printf("Operation:          %s (%u)\n", op_str, op);
    printf("Sender MAC:         ");
    print_mac_address(arp->arp_sha);
    printf("\nSender IP:          %s\n", sip);
    printf("Target MAC:         ");
    print_mac_address(arp->arp_tha);
    printf("\nTarget IP:          %s\n\n", tip);
}

void process_tcp_layer_detailed(const unsigned char *packet, int offset, int total_len) {
    if (total_len < offset + (int)sizeof(struct tcphdr)) {
        printf("🔸 TCP HEADER (Layer 4)\n\n");
        printf("   [Packet too short for TCP header]\n");
        return;
    }
    
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + offset);
    
    int src_port = ntohs(tcp_hdr->th_sport);
    int dst_port = ntohs(tcp_hdr->th_dport);
    unsigned int tcp_header_len = tcp_hdr->th_off * 4;
    
    printf("🔸 TCP HEADER (Layer 4)\n\n");
    printf("Source Port:        %d", src_port);
    const char *src_service = get_port_service(src_port);
    if (src_service) printf(" (%s)", src_service);
    printf(" (Bytes %d-%d)\n", offset, offset + 1);
    printf("   └─ Hex: %02X %02X\n", packet[offset], packet[offset + 1]);
    
    printf("Destination Port:   %d", dst_port);
    const char *dst_service = get_port_service(dst_port);
    if (dst_service) printf(" (%s)", dst_service);
    printf(" (Bytes %d-%d)\n", offset + 2, offset + 3);
    printf("   └─ Hex: %02X %02X\n", packet[offset + 2], packet[offset + 3]);
    
    printf("Sequence Number:    %u (Bytes %d-%d)\n",
           ntohl(tcp_hdr->th_seq), offset + 4, offset + 7);
    printf("   └─ Hex: %02X %02X %02X %02X\n",
           packet[offset + 4], packet[offset + 5], packet[offset + 6], packet[offset + 7]);
    
    printf("Acknowledgment:     %u (Bytes %d-%d)\n",
           ntohl(tcp_hdr->th_ack), offset + 8, offset + 11);
    printf("   └─ Hex: %02X %02X %02X %02X\n",
           packet[offset + 8], packet[offset + 9], packet[offset + 10], packet[offset + 11]);
    
    printf("Header Length:      %u bytes (8 * 4) (Upper 4 bits of byte %d)\n",
           tcp_header_len, offset + 12);
    printf("   └─ Hex: 0x%02X (upper 4 bits = 8)\n", packet[offset + 12]);
    
    printf("Flags:              0x%02X (Byte %d)\n", tcp_hdr->th_flags, offset + 13);
    printf("   └─ URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
           (tcp_hdr->th_flags & TH_URG) ? 1 : 0,
           (tcp_hdr->th_flags & TH_ACK) ? 1 : 0,
           (tcp_hdr->th_flags & TH_PUSH) ? 1 : 0,
           (tcp_hdr->th_flags & TH_RST) ? 1 : 0,
           (tcp_hdr->th_flags & TH_SYN) ? 1 : 0,
           (tcp_hdr->th_flags & TH_FIN) ? 1 : 0);
    
    printf("Window Size:        %u (Bytes %d-%d)\n",
           ntohs(tcp_hdr->th_win), offset + 14, offset + 15);
    printf("   └─ Hex: %02X %02X\n", packet[offset + 14], packet[offset + 15]);
    
    printf("Checksum:           0x%04X (Bytes %d-%d)\n",
           ntohs(tcp_hdr->th_sum), offset + 16, offset + 17);
    printf("   └─ Hex: %02X %02X\n", packet[offset + 16], packet[offset + 17]);
    
    printf("Urgent Pointer:     %u (Bytes %d-%d)\n",
           ntohs(tcp_hdr->th_urp), offset + 18, offset + 19);
    printf("   └─ Hex: %02X %02X\n", packet[offset + 18], packet[offset + 19]);
    
    // TCP Options if present
    if (tcp_header_len > 20) {
        printf("TCP Options:        %u bytes (Bytes %d-%d)\n",
               tcp_header_len - 20, offset + 20, offset + tcp_header_len - 1);
        printf("   └─ Hex: ");
        for (unsigned int i = 20; i < tcp_header_len && offset + i < (unsigned int)total_len; ++i) {
            printf("%02X ", packet[offset + i]);
            if (i - 20 >= 11) {
                printf("...");
                break;
            }
        }
        printf("\n");
    }
    
    printf("\n");
    
    // Payload
    int payload_offset = offset + tcp_header_len;
    int payload_len = total_len - payload_offset;
    
    if (payload_len > 0) {
        const char *protocol = "Unknown/Custom";
        int port = (dst_port == 80 || dst_port == 443 || dst_port == 53) ? dst_port : src_port;
        
        if (src_port == 80 || dst_port == 80) {
            protocol = "HTTP";
        } else if (src_port == 443 || dst_port == 443) {
            protocol = "HTTPS/TLS";
        } else if (src_port == 8080 || dst_port == 8080) {
            protocol = "HTTP (Alt)";
            port = 8080;
        }
        
        printf("● APPLICATION DATA (Layer 5-7)\n\n");
        printf("Payload Length:     %d bytes (Bytes %d-4968)\n", payload_len, payload_offset);
        printf("Protocol:           %s (Port %d)\n\n", protocol, port);
        
        // Show first 64 bytes of payload
        printf("First 64 bytes of payload:\n");
        printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
        print_hex_dump_detailed(packet + payload_offset, payload_len, 64);
        
        if (payload_len > 64) {
            printf("\n... and %d more bytes\n", payload_len - 64);
        }
    }
}

void process_udp_layer_detailed(const unsigned char *packet, int offset, int total_len) {
    if (total_len < offset + (int)sizeof(struct udphdr)) {
        printf("🔸 UDP HEADER (Layer 4)\n\n");
        printf("   [Packet too short for UDP header]\n");
        return;
    }
    
    struct udphdr *udp_hdr = (struct udphdr *)(packet + offset);
    
    int src_port = ntohs(udp_hdr->uh_sport);
    int dst_port = ntohs(udp_hdr->uh_dport);
    
    printf("🔸 UDP HEADER (Layer 4)\n\n");
    printf("Source Port:        %d", src_port);
    const char *src_service = get_port_service(src_port);
    if (src_service) printf(" (%s)", src_service);
    printf(" (Bytes %d-%d)\n", offset, offset + 1);
    printf("   └─ Hex: %02X %02X\n", packet[offset], packet[offset + 1]);
    
    printf("Destination Port:   %d", dst_port);
    const char *dst_service = get_port_service(dst_port);
    if (dst_service) printf(" (%s)", dst_service);
    printf(" (Bytes %d-%d)\n", offset + 2, offset + 3);
    printf("   └─ Hex: %02X %02X\n", packet[offset + 2], packet[offset + 3]);
    
    printf("Length:             %u (Bytes %d-%d)\n",
           ntohs(udp_hdr->uh_ulen), offset + 4, offset + 5);
    printf("   └─ Hex: %02X %02X\n", packet[offset + 4], packet[offset + 5]);
    
    printf("Checksum:           0x%04X (Bytes %d-%d)\n",
           ntohs(udp_hdr->uh_sum), offset + 6, offset + 7);
    printf("   └─ Hex: %02X %02X\n\n", packet[offset + 6], packet[offset + 7]);
    
    // Payload
    int payload_offset = offset + sizeof(struct udphdr);
    int payload_len = total_len - payload_offset;
    
    if (payload_len > 0) {
        const char *protocol = "Unknown/Custom";
        int port = (dst_port == 53) ? dst_port : src_port;
        
        if (src_port == 53 || dst_port == 53) {
            protocol = "DNS";
        }
        
        printf("● APPLICATION DATA (Layer 5-7)\n\n");
        printf("Payload Length:     %d bytes\n", payload_len);
        printf("Protocol:           %s (Port %d)\n\n", protocol, port);
        
        // Show first 64 bytes of payload (or less if shorter)
        int display_len = (payload_len < 64) ? payload_len : 64;
        printf("First %d bytes of payload:\n", display_len);
        printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
        print_hex_dump_detailed(packet + payload_offset, payload_len, display_len);
        
        if (payload_len > 64) {
            printf("\n... and %d more bytes\n", payload_len - 64);
        }
    }
}
// ############## LLM Generated Code Ends ################