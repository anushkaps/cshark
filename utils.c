// B/utils.c
#include "cshark.h"

void print_mac_address(const unsigned char *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Combined hex + ASCII dump, 16 bytes per line, up to max_bytes
void print_hex_dump(const unsigned char *data, int length, int max_bytes) {
    int to_print = (length < max_bytes) ? length : max_bytes;

    for (int i = 0; i < to_print; i += HEX_DUMP_WIDTH) {
        int line_len = (i + HEX_DUMP_WIDTH <= to_print) ? HEX_DUMP_WIDTH : (to_print - i);

        // Hex part
        for (int j = 0; j < HEX_DUMP_WIDTH; ++j) {
            if (j < line_len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        printf(" ");

        // ASCII part
        for (int j = 0; j < line_len; ++j) {
            unsigned char c = data[i + j];
            if (isprint(c)) putchar(c);
            else putchar('.');
        }
        putchar('\n');
    }
}
//############## LLM Generated Code Begins ##############
// Detailed hex dump with offset column for packet inspection
void print_hex_dump_detailed(const unsigned char *data, int length, int max_bytes) {
    int to_print = (length < max_bytes) ? length : max_bytes;

    for (int i = 0; i < to_print; i += HEX_DUMP_WIDTH) {
        // Print offset
        printf("%04X ", i);
        
        int line_len = (i + HEX_DUMP_WIDTH <= to_print) ? HEX_DUMP_WIDTH : (to_print - i);

        // Hex part
        for (int j = 0; j < HEX_DUMP_WIDTH; ++j) {
            if (j < line_len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        printf("    ");

        // ASCII part
        for (int j = 0; j < line_len; ++j) {
            unsigned char c = data[i + j];
            if (isprint(c)) putchar(c);
            else putchar('.');
        }
        putchar('\n');
    }
}
// ############## LLM Generated Code Ends ################
const char* get_port_service(int port) {
    switch (port) {
        case 20:  case 21: return "FTP";
        case 22:  return "SSH";
        case 23:  return "TELNET";
        case 25:  return "SMTP";
        case 53:  return "DNS";
        case 67:  case 68: return "DHCP";
        case 69:  return "TFTP";
        case 80:  return "HTTP";
        case 110: return "POP3";
        case 123: return "NTP";
        case 143: return "IMAP";
        case 161: case 162: return "SNMP";
        case 389: return "LDAP";
        case 443: return "HTTPS";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        default:  return NULL;
    }
}
