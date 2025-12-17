// B/cshark.h
#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

#define MAX_PACKETS 10000
#define SNAP_LENGTH 65535
#define HEX_DUMP_WIDTH 16

// Packet storage structure
typedef struct {
    unsigned int packet_id;
    struct timeval timestamp;
    unsigned int capture_length;
    unsigned char *raw_data;
} StoredPacket;

// Global variables
extern StoredPacket packet_vault[MAX_PACKETS];
extern unsigned int vault_count;
extern unsigned int session_packet_counter;
extern volatile sig_atomic_t stop_capture_flag;

// Function declarations
void display_banner(void);
int discover_interfaces(pcap_if_t **devices);
void show_interface_menu(pcap_if_t *devices, int count);
int select_interface(pcap_if_t *devices, int count, char *chosen_dev);
void display_main_menu(const char *interface);
void start_sniffing_all(const char *device);
void start_sniffing_filtered(const char *device);
void inspect_last_session(void);
void packet_analyzer(unsigned char *args, const struct pcap_pkthdr *header, 
                     const unsigned char *packet);
void signal_handler(int signum);
void cleanup_packet_vault(void);
void store_packet_data(const struct pcap_pkthdr *header, 
                       const unsigned char *packet);

// Layer processing functions
void process_ethernet_layer(const unsigned char *packet, int *offset);
void process_ipv4_layer(const unsigned char *packet, int *offset);
void process_ipv6_layer(const unsigned char *packet, int *offset);
void process_arp_layer(const unsigned char *packet, int offset);
void process_tcp_layer(const unsigned char *packet, int offset, int ip_header_len);
void process_udp_layer(const unsigned char *packet, int offset);
void process_payload(const unsigned char *packet, int offset, int total_len, 
                     int src_port, int dst_port);

// Utility functions
void print_hex_dump(const unsigned char *data, int length, int max_bytes);
void print_hex_dump_detailed(const unsigned char *data, int length, int max_bytes);
void print_mac_address(const unsigned char *mac);
const char* get_port_service(int port);
void print_tcp_flags(unsigned char flags);
void display_packet_summary(void);
void detailed_packet_inspection(int packet_id);

// Detailed layer processing functions for inspection
void process_ethernet_layer_detailed(const unsigned char *packet, int *offset, int total_len);
void process_ipv4_layer_detailed(const unsigned char *packet, int *offset, int total_len);
void process_ipv6_layer_detailed(const unsigned char *packet, int *offset, int total_len);
void process_arp_layer_detailed(const unsigned char *packet, int offset, int total_len);
void process_tcp_layer_detailed(const unsigned char *packet, int offset, int total_len);
void process_udp_layer_detailed(const unsigned char *packet, int offset, int total_len);

#endif
