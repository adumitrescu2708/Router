#include "skel.h"

/**
 * @brief Header for Cache Table functions
 * 
 * @author Dumitrescu Alexandra
 * @since See more: <cache.c>
 */

struct arp_entry *search_mac_address(struct arp_entry *__cache_table,
                                    uint32_t dest_address, int __cache_table_len);

int search_new_entry(struct arp_entry *__cache_table, int len,
                    uint32_t ip_adr, uint8_t *mac_adr);

