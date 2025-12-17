// B/interface.c
#include "cshark.h"

int discover_interfaces(pcap_if_t **devices) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(devices, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] pcap_findalldevs error: %s\n", errbuf);
        return -1;
    }

    int count = 0;
    for (pcap_if_t *d = *devices; d; d = d->next) count++;
    if (count > 0) {
        puts("[C-Shark] Searching for available interfaces... Found!\n");
    }
    return count;
}

void show_interface_menu(pcap_if_t *devices, int count) {
    (void)count; // Suppress unused parameter warning
    int idx = 1;
    for (pcap_if_t *d = devices; d; d = d->next, idx++) {
        printf("%d. %s", idx, d->name);
        if (d->description) printf("  (%s)", d->description);
        puts("");
    }
}

int select_interface(pcap_if_t *devices, int count, char *chosen_dev) {
    printf("\nSelect an interface to sniff (1-%d): ", count);
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        if (feof(stdin)) {
            puts("\n[C-Shark] EOF received. Exiting.");
            return -1;
        }
        return -1;
    }
    int pick = atoi(line);
    if (pick < 1 || pick > count) {
        puts("[C-Shark] Invalid selection.");
        return -1;
    }
    int idx = 1;
    for (pcap_if_t *d = devices; d; d = d->next, idx++) {
        if (idx == pick) {
            strncpy(chosen_dev, d->name, 255);
            chosen_dev[255] = '\0';
            break;
        }
    }
    return 0;
}
