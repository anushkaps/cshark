// B/inspect.c
#include "cshark.h"

static void print_summary_one(const StoredPacket *sp) {
    // Minimal L3/L4 summary directly from raw_data
    if (sp->capture_length < sizeof(struct ether_header)) {
        printf("#%u | %ld.%06ld | %u B | <truncated>\n",
               sp->packet_id, (long)sp->timestamp.tv_sec, (long)sp->timestamp.tv_usec,
               sp->capture_length);
        return;
    }
    const struct ether_header *eth = (const struct ether_header*)sp->raw_data;
    uint16_t etype = ntohs(eth->ether_type);
    const char *l3 = "Unknown";
    char l3info[128] = {0};
    char l4info[64] = {0};

    if (etype == ETHERTYPE_IP && sp->capture_length >= sizeof(struct ether_header) + sizeof(struct ip)) {
        const struct ip *iph = (const struct ip*)(sp->raw_data + sizeof(struct ether_header));
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->ip_src, src, sizeof(src));
        inet_ntop(AF_INET, &iph->ip_dst, dst, sizeof(dst));
        snprintf(l3info, sizeof(l3info), "IPv4 %s -> %s", src, dst);
        l3 = "IPv4";
        if (iph->ip_p == IPPROTO_TCP) snprintf(l4info, sizeof(l4info), "TCP");
        else if (iph->ip_p == IPPROTO_UDP) snprintf(l4info, sizeof(l4info), "UDP");
    } else if (etype == ETHERTYPE_IPV6 && sp->capture_length >= sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr*)(sp->raw_data + sizeof(struct ether_header));
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
        inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));
        snprintf(l3info, sizeof(l3info), "IPv6 %s -> %s", src, dst);
        l3 = "IPv6";
        if (ip6->ip6_nxt == IPPROTO_TCP) snprintf(l4info, sizeof(l4info), "TCP");
        else if (ip6->ip6_nxt == IPPROTO_UDP) snprintf(l4info, sizeof(l4info), "UDP");
    } else if (etype == ETHERTYPE_ARP) {
        snprintf(l3info, sizeof(l3info), "ARP");
        l3 = "ARP";
    }

    printf("#%u | %ld.%06ld | %u B | %s %s %s\n",
           sp->packet_id, (long)sp->timestamp.tv_sec, (long)sp->timestamp.tv_usec,
           sp->capture_length, l3, l3info, l4info);
}

void display_packet_summary(void) {
    if (vault_count == 0) {
        puts("[C-Shark] No packets stored from last session.");
        return;
    }
    puts("\n[C-Shark] Last session packets (summary):");
    for (unsigned int i = 0; i < vault_count; ++i) {
        print_summary_one(&packet_vault[i]);
    }
}

void detailed_packet_inspection(int packet_id) {
    if (vault_count == 0) {
        puts("[C-Shark] No session to inspect.");
        return;
    }
    if (packet_id < 1 || (unsigned int)packet_id > vault_count) {
        puts("[C-Shark] Invalid Packet ID.");
        return;
    }
    StoredPacket *sp = &packet_vault[packet_id - 1];

    // Print fancy header box
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                    C-SHARK DETAILED PACKET ANALYSIS                        ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
    // Packet Summary Section
    printf("\n● PACKET SUMMARY\n\n");
    printf("Packet ID:      #%u\n", sp->packet_id);
    printf("Timestamp:      %ld.%06ld\n", (long)sp->timestamp.tv_sec, (long)sp->timestamp.tv_usec);
    printf("Frame Length:   %u bytes\n", sp->capture_length);
    printf("Captured:       %u bytes\n", sp->capture_length);

    // Complete Frame Hex Dump
    printf("\n● COMPLETE FRAME HEX DUMP\n\n");
    printf("     0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
    print_hex_dump_detailed(sp->raw_data, sp->capture_length, sp->capture_length);

    // Layer-by-Layer Analysis
    printf("\n● LAYER-BY-LAYER ANALYSIS\n\n");
    
    int offset = 0;
    process_ethernet_layer_detailed(sp->raw_data, &offset, sp->capture_length);

    const struct ether_header *eth = (const struct ether_header*)sp->raw_data;
    uint16_t etype = ntohs(eth->ether_type);
    if (etype == ETHERTYPE_IP) {
        process_ipv4_layer_detailed(sp->raw_data, &offset, sp->capture_length);
    } else if (etype == ETHERTYPE_IPV6) {
        process_ipv6_layer_detailed(sp->raw_data, &offset, sp->capture_length);
    } else if (etype == ETHERTYPE_ARP) {
        process_arp_layer_detailed(sp->raw_data, offset, sp->capture_length);
    } else {
        puts("Unknown EtherType in detailed view.");
    }
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                         END OF PACKET ANALYSIS                             ║\n");
    printf("╚════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\nPress Enter to continue...");
}
void inspect_last_session(void) {
    if (vault_count == 0) {
        puts("[C-Shark] No packets captured in the last session.");
        return;
    }
    display_packet_summary();
    printf("\nEnter Packet ID to inspect (or 0 to cancel): ");
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) {
        puts("\n[C-Shark] EOF received. Returning.");
        return;
    }
    int id = atoi(line);
    if (id == 0) return;
    detailed_packet_inspection(id);
}
