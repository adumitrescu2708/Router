#include "cache.h"

/**
 * @brief Functions for Cache Table used in forwarding and ARP protocol
 * 
 * @author Dumitrescu Alexandra
 * @since April 2022
 */


/**
 * @brief function returns mac adress of a specified IP adress or null if
 * there is no correspondence in the cache table
 * 
 * @param __cache_table - cache table
 * @param dest_address - searched address
 * @param __cache_table_len - size of cache table
 * @return struct arp_entry* - corresponding line in cache table
 */
struct arp_entry *search_mac_address(struct arp_entry *__cache_table, uint32_t dest_address, int __cache_table_len) {
    for(int i = 0; i < __cache_table_len; i++) {
        if(__cache_table[i].ip == dest_address)
            return &__cache_table[i];
    }
    return NULL;
}

/**
 * @brief function returns true/false if an entry is in the cache table
 * 
 * @param __cache_table - cache table
 * @param len - size of cache table
 * @param ip_adr - searched ip adress
 * @param mac_adr - searched mac adress
 * @return int 1(True) or 0(False)
 */
int search_new_entry(struct arp_entry *__cache_table, int len, uint32_t ip_adr, uint8_t *mac_adr) {
    for(int i = 0; i < len; i++) {
        if(ip_adr == __cache_table[i].ip) {
            return 0;
        }
    }
    return 1;
}

