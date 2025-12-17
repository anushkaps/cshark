// B/main.c
#include "cshark.h"

StoredPacket packet_vault[MAX_PACKETS];
unsigned int vault_count = 0;
unsigned int session_packet_counter = 0;
volatile sig_atomic_t stop_capture_flag = 0;

static void exit_if_eof_or_ctrl_d(void) {
    if (feof(stdin)) {
        puts("\n[C-Shark] Received EOF (Ctrl+D). Exiting gracefully. Bye!");
        cleanup_packet_vault();
        exit(0);
    }
}

void display_banner(void) {
    puts("[C-Shark] The Command-Line Packet Predator");
    puts("==============================================");
}

void signal_handler(int signum) {
    if (signum == SIGINT) {       // Ctrl+C
        stop_capture_flag = 1;    // cooperative stop; capture loop polls this
    }
}

static int read_int_choice(void) {
    char line[64];
    if (!fgets(line, sizeof(line), stdin)) {
        exit_if_eof_or_ctrl_d();
        return -1; // should not reach
    }
    // Trim leading spaces
    char *p = line;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) return -1;
    return atoi(p);
}

int main(void) {
    signal(SIGINT, signal_handler);

    display_banner();

    pcap_if_t *devices = NULL;
    int count = discover_interfaces(&devices);
    if (count <= 0) {
        fprintf(stderr, "[C-Shark] No interfaces found or error.\n");
        return 1;
    }
    show_interface_menu(devices, count);

    char chosen_dev[256] = {0};
    if (select_interface(devices, count, chosen_dev) != 0) {
        pcap_freealldevs(devices);
        return 1;
    }
    pcap_freealldevs(devices);

    for (;;) {
        display_main_menu(chosen_dev);
        int choice = read_int_choice();
        if (choice == 1) {
            start_sniffing_all(chosen_dev);
        } else if (choice == 2) {
            start_sniffing_filtered(chosen_dev);
        } else if (choice == 3) {
            inspect_last_session();
        } else if (choice == 4) {
            puts("[C-Shark] Exiting. Cleaning up...");
            cleanup_packet_vault();
            break;
        } else {
            puts("[C-Shark] Invalid option. Try again.");
        }
    }
    return 0;
}

void display_main_menu(const char *iface) {
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", iface);
    puts("1. Start Sniffing (All Packets)");
    puts("2. Start Sniffing (With Filters)");
    puts("3. Inspect Last Session");
    puts("4. Exit C-Shark");
    printf("> ");
}
