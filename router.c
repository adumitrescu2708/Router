#include "queue.h"
#include "skel.h"
#include "routing_table.h"
#include "cache.h"
#include "icmpp.h"
#include "arp.h"
#include "checksum.h"

/**
 * @brief Main Entry in the Router
 *  
 * @author Dumitrescu Alexandra
 * @since April 2022
 */

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Prepare Routing table and Cache table */
    struct route_table_entry *__routing_table = malloc(MAX_SIZE * sizeof(struct route_table_entry));
    struct arp_entry *__cache_table = malloc(1 * sizeof(struct arp_entry));
    int __routing_table_len = 0, __cache_table_len = 0;

    /* Structures used in forwarding process */
    struct route_table_entry *__best_route;
    struct arp_entry *__best_route_mac;

    /* Possible Headers in packet's payload */
    struct ether_header *__ether_header;
    struct arp_header *__arp_header;
    struct iphdr *__ipv4_header;

    struct in_addr destination_adress;    
    packet m;
    int rc;

    /* Prepare queue for ARP protocol */
    queue packet_queue = queue_create();

    /* Parse Routing table and sort it in ascending order after prefix and then after mask */
    __routing_table_len = read_rtable(argv[1], __routing_table);
    qsort(__routing_table, __routing_table_len, sizeof(struct route_table_entry), compare);
    
    init(argc -2, argv + 2);
    
    while(1) {
        
        rc = get_packet(&m);
        DIE(rc < 0, "get_packet");
       
        __ether_header = (struct ether_header *) m.payload;

        if(__ether_header->ether_type == ARP) {
            /* Obtain Ether Header */
            __arp_header = ((void *) __ether_header) + sizeof(struct ether_header);

            if(__arp_header->op == REQUEST) {
                uint32_t router_ip_adr;
                uint32_t target_ip_adr = __arp_header->tpa;
                inet_pton(AF_INET, get_interface_ip(m.interface), &router_ip_adr);

                /* Check if ARP Request is for the current router */
                if(target_ip_adr == router_ip_adr) {
                    send_reply_arp(m);
                }
            }
            if(__arp_header->op == REPLY) {
                uint32_t new_ip_adr = __arp_header->spa;
                uint8_t *new_mac_adr = __arp_header->sha;

                /* Check if the new entry received from reply is already in the routing table */
                if(search_new_entry(__cache_table, __cache_table_len, new_ip_adr, new_mac_adr) != 0) {
                    /* Resize and store new data in the cache table */
                    receive_reply_arp(m, &__cache_table, &__cache_table_len);

                    /* Send packets with the information received */
                    update_queue(&packet_queue, __cache_table, __cache_table_len, __routing_table, __routing_table_len);
                }
            }
        }
        if(__ether_header->ether_type == IPv4) {
            /* Obtain IPv4 header*/
            __ipv4_header = ((void *) __ether_header) + sizeof(struct ether_header);

            /* 1. Check if there is an ICMP request adressed to the current router */
            if(check_icmp_request(m) == 1)
                continue;    

            /* 2. Check header's checksum */
            if(ip_checksum((void *) __ipv4_header, sizeof(struct iphdr)) != 0) {
                continue;
            }

            /* 3. Check time to leave */
            if(__ipv4_header->ttl <= 1) {
                send_time_limit_excedeed(m);
                continue;
            }

            /* 4. Compute next hop */
            destination_adress.s_addr = __ipv4_header->daddr;
            int idx = binary_search(__routing_table, destination_adress, 0, __routing_table_len - 1, -1);
               
            if(idx == -1) {
                send_destination_unreachable(m);
                continue;
            } else {
                __best_route = &__routing_table[idx];
                __best_route_mac = search_mac_address(__cache_table, __best_route->next_hop, __cache_table_len);

                if(__best_route_mac == NULL) {
                    add_packet_to_queue(m, packet_queue);
                    send_request_arp(m, __best_route);
                    continue;
                } else {
                    /* Compute new TTL using RFC1624 */
                    __ipv4_header->ttl --;
                    __ipv4_header->check = RFC1624_checksum(__ipv4_header);

                    /* 5. Rewrite Level2 header data*/
                    memcpy(__ether_header->ether_dhost, &__best_route_mac->mac, 6);
                    get_interface_mac(__best_route->interface, __ether_header->ether_shost);

                    /* 6. Select the corresponding interface */
                    m.interface = __best_route->interface;
                    send_packet(&m);
                    continue;
                }
            }
        }
    }
    free(__routing_table);
    free(__cache_table);
    return 0;

}