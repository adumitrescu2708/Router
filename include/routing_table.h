#include "queue.h"
#include "skel.h"

#define MAX_SIZE 1000000
#define IPv4 htons(0x800) 

/**
 * @brief Header for routing table functions
 * 
 * @author Dumitrescu Alexandra
 * @since See more: <routing_table.c>
 */

int binary_search(struct route_table_entry *__routing_table,
                                        struct in_addr dest_ip_address,
                                        int left_idx, int right_idx, int result);

struct route_table_entry *get_best_route(struct route_table_entry *__routing_table, struct in_addr dest_ip_address, int __routing_table_len);

int compare(const void *a, const void *b);