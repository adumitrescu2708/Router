#include "skel.h"
#include "queue.h"

#define REQUEST htons(0x001)
#define REPLY htons(0x002)
#define ARP htons(0x806)

/**
 * @brief Header for ARP functions and packet queue manager
 * 
 * @author Dumitrescu Alexandra
 * @since See more: <arp.c>
 */

void send_request_arp(packet m, struct route_table_entry *route);  

void send_reply_arp(packet m);

void receive_reply_arp(packet m, struct arp_entry **__cache_table, int *len);

void update_queue(queue *packet_queue,
                struct arp_entry *__cache_table, int len,
                struct route_table_entry *__routing_table,
                int __routing_table_len);

void add_packet_to_queue(packet m, queue __queue);