#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
void forward_ip_packet_with_mac(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* outcoming_interface, unsigned char* mac_address);
void forward_arp_packet_with_mac(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* outcoming_interface, unsigned char* mac_address);

void send_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint32_t ip);
void handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void find_MAC_address_and_send(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint32_t target_ip);

struct sr_if* contains_interface_for_ip(struct sr_instance* sr, uint32_t ip);
void send_icmp_echo_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint8_t type, uint8_t code);
void send_icmp_type3_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint8_t type, uint8_t code);
struct sr_rt* longest_prefix_matching(struct sr_instance* sr, uint32_t target_ip);
bool is_ip_checksum_valid(sr_ip_hdr_t* ip_header);
bool is_ip_length_valid(unsigned int len);
bool is_icmp_length_valid(unsigned int len);



#endif /* SR_ROUTER_H */
