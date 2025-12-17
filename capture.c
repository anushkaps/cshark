// B/capture.c
#include "cshark.h"

static void run_capture_loop(pcap_t *handle, const char *what) {
    stop_capture_flag = 0;
    session_packet_counter = 0;

    puts("\n[C-Shark] Starting capture. Press Ctrl+C to stop.");
    // poll using pcap_next_ex with read timeout set in open_live
    while (!stop_capture_flag) {
        struct pcap_pkthdr *header;
        const u_char *data;
        int rc = pcap_next_ex(handle, &header, &data);
        if (rc == 1) {
            // got a packet
            packet_analyzer(NULL, header, data);
            store_packet_data(header, data);
        } else if (rc == 0) {
            // timeout; continue so we can react to Ctrl+C
            continue;
        } else if (rc == PCAP_ERROR_BREAK) {
            break;
        } else {
            fprintf(stderr, "[C-Shark] Capture error: %s\n", pcap_geterr(handle));
            break;
        }
    }
    printf("[C-Shark] Stopped %s capture. Stored %u packets.\n", what, vault_count);
}

static pcap_t* open_device_live(const char *device, int promisc, int timeout_ms) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, SNAP_LENGTH, promisc, timeout_ms, errbuf);
    if (!handle) {
        fprintf(stderr, "[C-Shark] pcap_open_live error on '%s': %s\n", device, errbuf);
        return NULL;
    }
    return handle;
}

void start_sniffing_all(const char *device) {
    cleanup_packet_vault(); // new session -> clear old memory

    pcap_t *handle = open_device_live(device, 1, 500);
    if (!handle) return;

    run_capture_loop(handle, "unfiltered");
    pcap_close(handle);
}

static const char* pick_filter_expr(void) {
    puts("\n[C-Shark] Filters");
    puts("1. HTTP");
    puts("2. HTTPS");
    puts("3. DNS");
    puts("4. ARP");
    puts("5. TCP");
    puts("6. UDP");
    printf("> ");

    char line[32];
    if (!fgets(line, sizeof(line), stdin)) {
        puts("\n[C-Shark] EOF received. Returning to menu.");
        return NULL;
    }
    int choice = atoi(line);
    switch (choice) {
        case 1: return "tcp port 80";
        case 2: return "tcp port 443";
        case 3: return "udp port 53";
        case 4: return "arp";
        case 5: return "tcp";
        case 6: return "udp";
        default: puts("[C-Shark] Invalid choice."); return NULL;
    }
}

void start_sniffing_filtered(const char *device) {
    const char *expr = pick_filter_expr();
    if (!expr) return;

    cleanup_packet_vault(); // new session

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = open_device_live(device, 1, 500);
    if (!handle) return;

    // Compile + set filter
    struct bpf_program fp;
    bpf_u_int32 net = 0, mask = 0;
    pcap_lookupnet(device, &net, &mask, errbuf); // okay if it fails

    if (pcap_compile(handle, &fp, expr, 1, mask) == -1) {
        fprintf(stderr, "[C-Shark] pcap_compile error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[C-Shark] pcap_setfilter error: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }
    pcap_freecode(&fp);

    printf("[C-Shark] Filter applied: '%s'\n", expr);
    run_capture_loop(handle, "filtered");
    pcap_close(handle);
}

void store_packet_data(const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (vault_count >= MAX_PACKETS) return;

    StoredPacket *sp = &packet_vault[vault_count];
    sp->packet_id = ++session_packet_counter;
    sp->timestamp = header->ts;
    sp->capture_length = header->caplen;
    sp->raw_data = (unsigned char*)malloc(header->caplen);
    if (!sp->raw_data) {
        fprintf(stderr, "[C-Shark] malloc failed; dropping packet from storage.\n");
        return;
    }
    memcpy(sp->raw_data, packet, header->caplen);
    vault_count++;
}

void cleanup_packet_vault(void) {
    for (unsigned int i = 0; i < vault_count; ++i) {
        free(packet_vault[i].raw_data);
        packet_vault[i].raw_data = NULL;
    }
    vault_count = 0;
    session_packet_counter = 0;
}
