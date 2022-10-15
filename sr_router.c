#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 * Let's Start!!!!!!!
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Get Ethernet Header */
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;

  /* First we need to check whether the received packet is an IP packet or ARP packet */
  if (ntohs(ethernet_header->ether_type) == ethertype_arp) {
    handle_arp_packet(sr, packet, len, interface);
  } else if (ntohs(ethernet_header->ether_type) == ethertype_ip){
    handle_ip_packet(sr, packet, len, interface);
  } else {
    fprintf(stderr, "[ERROR] Unknown Packet Type.\n");
  }
}/* end sr_ForwardPacket */


/* Handle ARP Packet */
void handle_arp_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
  /* Incoming ethernet header & ARP header */
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
  sr_arp_hdr_t* arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /*    ***********  REQUEST  ************   */
  if (ntohs(arp_header->ar_op) == arp_op_request) {
    printf("[INFO] Received ARP Request.\n");
    
    /* Pre-checking */ 
    struct sr_if* outcome_interface = contains_interface_for_ip(sr, arp_header->ar_tip);
    if (outcome_interface == NULL) {
      printf("[INFO] Target IP does not exist in this router! ARP request is not for me.\n");
      return;
    }

    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t* arp_reply = (uint8_t*)malloc(reply_len);
    /* ============= Build ethernet header ============= */ 
    sr_ethernet_hdr_t* arp_reply_eh = (sr_ethernet_hdr_t*) arp_reply;
    /* Original incoming source ethernet address becomes current destination */ 
    memcpy(arp_reply_eh->ether_dhost, ethernet_header->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t));
    /* Current source address can be found from interface */ 
    memcpy(arp_reply_eh->ether_shost, outcome_interface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
    /* Type is the same as before */
    arp_reply_eh->ether_type = ethernet_header->ether_type;


    /* ============= Build ARP header ============= */ 
    sr_arp_hdr_t* arp_reply_ah = (sr_arp_hdr_t*)(arp_reply + sizeof(sr_ethernet_hdr_t));
    /**
     * ------------ Same As Before ------------
     * format of hardware address
     * format of protocol address  
     * length of hardware address   
     * length of protocol address   
    */
    arp_reply_ah->ar_hrd = arp_header->ar_hrd;
    arp_reply_ah->ar_pro = arp_header->ar_pro;
    arp_reply_ah->ar_hln = arp_header->ar_hln;
    arp_reply_ah->ar_pln = arp_header->ar_pln;
    /* Now the ARP opcode should be reply */ 
    arp_reply_ah->ar_op = htons(arp_op_reply);

    /**
     * Logic is the same as before
     * Destination should be original source
     * Source can be found through received_interface 
    */ 
    memcpy(arp_reply_ah->ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN * sizeof(uint8_t));
    memcpy(arp_reply_ah->ar_sha, outcome_interface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
    arp_reply_ah->ar_tip = arp_header->ar_sip;
    arp_reply_ah->ar_sip = outcome_interface->ip;

    /******************   DEBUG  ******************/
    printf("[INFO] Send back ARP response info.\n");
    printf("[DEBUG] Ethernet header of the reply ARP packet is:\n");
    print_hdr_eth((uint8_t *)arp_reply_eh);
    printf("[DEBUG] Source IP of the reply ARP packet is: \n");
    print_addr_ip_int(ntohl(arp_reply_ah->ar_sip));
    printf("[DEBUG] Target IP of the reply ARP packet is:  \n");
    print_addr_ip_int(ntohl(arp_reply_ah->ar_tip));
    printf("\n");
    /******************   DEBUG  ******************/

    /* ============= Send Packet ============= */ 
    sr_send_packet(sr, arp_reply, len, interface);
    free(arp_reply);
  } else if (ntohs(arp_header->ar_op) == arp_op_reply) { /* ==========  REPLY  ========== */ 
    /* Cache it and go through request queue and send outstanding packets */
    printf("[INFO] Received ARP Reply.\n");

    /* find sr_arpreq and insert IP-MAC into cache */ 
    struct sr_arpreq* req_entry = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
    /* Found request in request queue */
    if (req_entry != NULL) {
      struct sr_packet* head = req_entry->packets;
      /* Send all related packets */
      while (head != NULL) {
        forward_ip_packet_with_mac(sr, head->buf, head->len, sr_get_interface(sr, head->iface), arp_header->ar_sha);
        head = head->next;
      }
      sr_arpreq_destroy(&(sr->cache), req_entry);
      printf("[INFO] Forward all related packets successfully.\n");
    }
  } else {
    fprintf(stderr, "[ERROR] Only handle ARP request or reply.\n");
  }
}


/* Update Ethernet header with destination MAC address and send IP packet. */ 
void forward_ip_packet_with_mac(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* outcoming_interface, unsigned char* mac_address) {
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
  
  memcpy(ethernet_header->ether_dhost, mac_address, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(ethernet_header->ether_shost, outcoming_interface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
  ethernet_header->ether_type = htons(ethertype_ip);

  sr_send_packet(sr, packet, len, outcoming_interface->name);
}


/* Update Ethernet header with destination MAC address and send ARP packet. */ 
void forward_arp_packet_with_mac(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if* outcoming_interface, unsigned char* mac_address) {
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*)packet;
  
  memcpy(ethernet_header->ether_dhost, mac_address, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(ethernet_header->ether_shost, outcoming_interface->addr, ETHER_ADDR_LEN * sizeof(uint8_t));
  ethernet_header->ether_type = htons(ethertype_arp);

  sr_send_packet(sr, packet, len, outcoming_interface->name);
}


/* Handle IP Packet */ 
void handle_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* incoming_interface) {
  printf("[INFO] Received IP packet.\n");
  /* Incoming ethernet header & IP header */ 
  /* sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet; */
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /******************   DEBUG  ******************/
  printf("[DEBUG] Get IP packet from the ip address below:  \n"); 
  print_addr_ip_int(ntohl(ip_header->ip_src));
  printf("[DEBUG] Received IP packet would like to go to:  \n"); 
  print_addr_ip_int(ntohl(ip_header->ip_dst));
  printf("\n");
  /******************   DEBUG  ******************/

  /* Sanity-check */ 
  if (!is_ip_checksum_valid(ip_header)) {
    fprintf(stderr, "[ERROR] IP header Sanity-check (CheckSum) is not passed.\n");
    return;
  } 
  if (!is_ip_length_valid(len)) {
    fprintf(stderr, "[ERROR] IP header Sanity-check (Minimum length) is not passed.\n");
    return;
  }

  if (contains_interface_for_ip(sr, ip_header->ip_dst) != NULL) {
    printf("[INFO] Router is the destination for this IP packet.\n");

    printf("----------- Receive IP ------------\n");
    print_hdr_eth(packet);
    print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
    printf("------------------------------------------\n");

    /* Judge ip_protocol */ 
    switch (ntohs(ip_header->ip_p))
    {
    case ip_protocol_icmp: {
      printf("[INFO] IP protocol is ICMP Echo.\n");

      sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
      /* Sanity-check */ 
      if (!is_icmp_checksum_valid(icmp_header)) {
        fprintf(stderr, "[ERROR] ICMP header Sanity-check (CheckSum) is not passed.\n");
        return;
      }
      if (!is_icmp_length_valid(len)) {
        fprintf(stderr, "[ERROR] ICMP header Sanity-check (Minimum length) is not passed.\n");
        return;
      }
      
      /****   ONLY HANDLE THIS SITUATION   ****/ 
      if (icmp_header->icmp_type == (uint8_t)8) {
        printf("[INFO] ICMP Echo Request.\n");
        send_icmp_echo_packet(sr, packet, len, incoming_interface, (uint8_t)0, (uint8_t)0);
      }
      break;
    }
    
    case ip_protocol_tcp:
    case ip_protocol_udp: {
      printf("[INFO] IP protocol is TCP/UDP.\n");
      /* Port unreachable */ 
      send_icmp_type3_packet(sr, packet, len, incoming_interface, (uint8_t)3, (uint8_t)3); 
      break;
    }
    
    default:
      break;
    }
  } else {
    printf("[INFO] Router is not the destination for this IP packet.\n");
    send_ip_packet(sr, packet, len, incoming_interface, ip_header->ip_dst);

    /*
    ip_header->ip_ttl--;
    if (ip_header->ip_ttl == 0) {
      printf("[INFO] ICMP packet time exceeded.\n");
      send_icmp_type3_packet(sr, packet, len, incoming_interface, (uint8_t)11, (uint8_t)0);
      return;
    }

    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
    send_ip_packet(sr, packet, len, incoming_interface, ip_header->ip_dst);
    */
  }
}


/* Send IP packet when knowing the destination IP address. */ 
void send_ip_packet(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint32_t ip) {
  /* Update TTL */
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  ip_header->ip_ttl--;
  if (ip_header->ip_ttl == 0) {
    printf("[INFO] ICMP packet time exceeded.\n");
    send_icmp_type3_packet(sr, packet, len, interface, (uint8_t)11, (uint8_t)0); 
    return;
  }

  /* Recompute the packet checksum over the modified header */ 
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Check routing table and perform LPM */
  struct sr_rt* node = longest_prefix_matching(sr, ip);
  if (node == NULL) {
    printf("[INFO] Destination IP address not matched. ICMP net unreachable.\n");
    send_icmp_type3_packet(sr, packet, len, interface, (uint8_t)3, (uint8_t)0); 
  }
  printf("[INFO] Destination IP address matched.\n");


  /******************   DEBUG  ******************/
  printf("[DEBUG] (send_ip_packet) - outcoming interface is: %s\n", node->interface);
  printf("[DEBUG] (send_ip_packet) target ip address is:  \n");
  print_addr_ip_int(ntohl(node->gw.s_addr));
  printf("\n");
  /******************   DEBUG  ******************/

  /* Find gateway / next-hop 's corresponding MAC address. */ 
  find_MAC_address_and_send(sr, packet, len, node->interface, node->gw.s_addr);
}


/* Check ARP Cache */
void find_MAC_address_and_send(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint32_t target_ip) {
  struct sr_if* outcoming_interface = sr_get_interface(sr, interface);

  /* Find target_ip's corresponding MAC address. */ 
  struct sr_arpentry* cached_entry = sr_arpcache_lookup(&(sr->cache), target_ip);
  if (cached_entry != NULL) {
    printf("[INFO] Find IP-MAC pair in cache.\n");
    /******************   DEBUG  ******************/
    printf("[DEBUG] (find_MAC_address_and_send) target ip address is: \n");
    print_addr_ip_int(ntohl(target_ip));
    printf("[DEBUG] (find_MAC_address_and_send) target MAC address is: \n");
    print_addr_eth(cached_entry->mac);
    /******************   DEBUG  ******************/

    forward_ip_packet_with_mac(sr, packet, len, outcoming_interface, cached_entry->mac);
    free(cached_entry);
  } else {
    printf("[INFO] Start ARP Cache request since corresponding entry is not found.\n");
    struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), target_ip, packet, len, outcoming_interface->name);
    handle_arpreq(sr, req);
  }
}

/* Check whether router contains the corresponding interface (ip) */ 
struct sr_if* contains_interface_for_ip(struct sr_instance* sr, uint32_t ip) {
  struct sr_if* head = sr->if_list;

  while (head != NULL) {
    if (head->ip == ip) {
      return head;
    }
    head = head->next;
  }
  return NULL;
}


/* Send back Echo reply */ 
void send_icmp_echo_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint8_t type, uint8_t code) {
  sr_ethernet_hdr_t* ethernet_header = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Build ICMP header */
  icmp_header->icmp_code = code;
  icmp_header->icmp_type = type;
  icmp_header->icmp_sum = (uint16_t)0;
  icmp_header->icmp_sum = cksum(icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  /* Build IP header */
  ip_header->ip_ttl = INIT_TTL;
  uint32_t temp = ip_header->ip_src;
  ip_header->ip_src = ip_header->ip_dst;
  ip_header->ip_dst = temp;

  ip_header->ip_sum = (uint16_t)0;
  ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

  /* Build Ethernet header */
  ethernet_header->ether_type = htons(ethertype_ip);

  /* Send IP packet */
  find_MAC_address_and_send(sr, packet, len, interface, ip_header->ip_dst);
}


void send_icmp_type3_packet(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface, uint8_t type, uint8_t code) {
  printf("[INFO] (send_icmp_type3_packet) - Send_icmp_type3_packet type is %d, code is %d\n", type, code);
  printf("[INFO] (send_icmp_type3_packet) - Receive the ICMP packet from %s.\n", interface);
  unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t* new_packet = malloc(new_len * sizeof(uint8_t));

  assert(new_packet);

  printf("----------- Receive ICMP ------------\n");
  print_hdr_eth(packet);
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
  print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  printf("------------------------------------------\n");

  /* Previous */
  sr_ethernet_hdr_t* prev_ethernet_header = (sr_ethernet_hdr_t*) packet;
  sr_ip_hdr_t* prev_ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* prev_icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)); 

  /* Current */
  sr_ethernet_hdr_t* new_ethernet_header = (sr_ethernet_hdr_t*) new_packet;
  sr_ip_hdr_t* new_ip_header = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* new_icmp_t3_header = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Build ICMP header */
  new_icmp_t3_header->icmp_code = code;
  new_icmp_t3_header->icmp_type = type;
  new_icmp_t3_header->unused = (uint16_t)0;
  new_icmp_t3_header->next_mtu = (uint16_t)1500;
  memcpy(new_icmp_t3_header->data, prev_ip_header, ICMP_DATA_SIZE);
  memcpy(new_icmp_t3_header->data + sizeof(sr_ip_hdr_t), prev_icmp_header,8);
  new_icmp_t3_header->icmp_sum = (uint16_t)0;
  new_icmp_t3_header->icmp_sum = cksum(new_icmp_t3_header, sizeof(sr_icmp_t3_hdr_t));

  /* Build IP header */
  new_ip_header->ip_v = prev_ip_header->ip_v;
  new_ip_header->ip_hl = prev_ip_header->ip_hl;
  new_ip_header->ip_tos = prev_ip_header->ip_tos;
  new_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip_header->ip_id = htons(0);
  new_ip_header->ip_off = prev_ip_header->ip_off;
  new_ip_header->ip_p = ip_protocol_icmp;
  new_ip_header->ip_ttl = INIT_TTL;

  if (type == 3 && code == 3) {
    new_ip_header->ip_src = prev_ip_header->ip_dst;
  } else {
    new_ip_header->ip_src = sr_get_interface(sr, interface)->ip;
  }
  new_ip_header->ip_dst = prev_ip_header->ip_src;
  new_ip_header->ip_sum = (uint16_t)0;
  new_ip_header->ip_sum = cksum(new_ip_header, sizeof(sr_ip_hdr_t));


  /* Build Ethernet header */
  new_ethernet_header->ether_type = htons(ethertype_ip);
  memcpy(new_ethernet_header->ether_dhost, prev_ethernet_header->ether_shost, ETHER_ADDR_LEN * sizeof(uint8_t));
  memcpy(new_ethernet_header->ether_shost, sr_get_interface(sr, interface)->addr, ETHER_ADDR_LEN * sizeof(uint8_t));

  printf("----------- Send ICMP ------------\n");
  print_hdr_eth(new_packet);
  print_hdr_ip(new_packet + sizeof(sr_ethernet_hdr_t));
  print_hdr_icmp(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  printf("------------------------------------------\n");

  /* Send IP packet */
  send_ip_packet(sr, new_packet, len, interface, new_ip_header->ip_dst);
  free(new_packet);
}


/* Find the longest prefix match of a destination IP address in the routing table */
struct sr_rt* longest_prefix_matching(struct sr_instance* sr, uint32_t target_ip) {
  if (sr->routing_table == NULL) {
    fprintf(stderr, "[ERROR] Router cache is empty.\n");
    return NULL;
  }

  struct sr_rt* entry = sr->routing_table;
  struct sr_rt* longest_prefix = NULL;
  int len = 0;

  while (entry != NULL) {
    if ((entry->dest.s_addr & entry->mask.s_addr) == (target_ip & entry->mask.s_addr)) {
      if ((entry->mask.s_addr & target_ip) > len) {
        longest_prefix = entry;
        len = entry->mask.s_addr & target_ip;
      }
    }
    entry = entry->next;
  }

  if (longest_prefix == NULL) {
    printf("[WARNING] Longest prefix matching failed.\n");
  }
  return longest_prefix;
}


/* Check whether ICMP's checksum is valid or not  */
bool is_icmp_checksum_valid(sr_icmp_hdr_t* icmp_header) {
  uint16_t original_checksum = icmp_header->icmp_sum;
  icmp_header->icmp_sum = (uint16_t)0;
  uint16_t computed_checksum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));

  icmp_header->icmp_sum = original_checksum;
  if (original_checksum == computed_checksum) {
    return true;
  }
  return false;
}


/* check whether IP's checksum is valid or not */
bool is_ip_checksum_valid(sr_ip_hdr_t* ip_header) {
  uint16_t original_checksum = ip_header->ip_sum;

  /* Calculate new one, don't forget to reset ip_sum to 0 first. */
  ip_header->ip_sum = (u_int16_t)0;
  uint16_t computed_checksum = cksum(ip_header, sizeof(sr_ip_hdr_t));
  ip_header->ip_sum = original_checksum;

  if (original_checksum == computed_checksum) {
    return true;
  }
  return false;
}


/* Check whether IP struct meets minimum length */
bool is_ip_length_valid(unsigned int len) {
  if (len < (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t))) {
    return false;
  }
  return true;
}


/* Check whether ICMP struct meets the minimim length*/
bool is_icmp_length_valid(unsigned int len) {
  if (len < (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t))) {
    return false;
  }
  return true;
}