#include "arp.h"
#include "cache.h"
#include "queue.h"
#include "routing_table.h"
#include "checksum.h"

/**
 *                  ARP PROTOCOL
 * 
 * There are 3 steps involved in ARP protocol.
 *              A) Sending a request
 *              B) Sending a reply
 *              C) Receiving a reply
 * 
 * Implement: When computing the cache table, we used a resizable array, therefor
 *            whenever a new entry is received, the cache's memory is resized.
 * 
 * Case:        A) In forwarding, whenever a mac address of the next route
 *                 is not found in the cache table, the router sends an ARP request
 *                 with the destination address set to broadcast and the target to the
 *                 searched route.
 *                      | a) We used a queue of packets for storing temporarly
 *                      |    the packets and wait for the replies with the 
 *                      |    corresponding mac address.
 * 
 *              B) When is delivered a packet with ARP header and is having the 
 *                 broadcast address, using the ARP protocol we must check whether
 *                 the packet is for us and send a reply request
 * 
 *              C) When a reply is received, a router must extract the information
 *                 and update the cache table with new data.
 *                      | c) When a new entry in the cache table is generated, the router
 *                      |    searches for the packet waiting in the queue.
 * 
 *      
 * @author Dumitrescu Alexandra
 * @since April 2022
 */

uint8_t *broadcast_addr() {
    uint8_t *addr = malloc(6 * sizeof(uint8_t));
    addr[0] = 0xFF;
    addr[1] = 0xFF;
    addr[2] = 0xFF;
    addr[3] = 0xFF;
    addr[4] = 0xFF;
    addr[5] = 0xFF;

    return addr;    
}


/**
 * @brief Construct a send request 
 * 
 *  
 *  Steps:  - Compute new package:
 *          |  - payoad 
 *          |       |
 *          |       | - Compute Ether Header
 *          |       |       | - d_host:   broadcast (FF:FF:FF:FF:FF:FF)
 *          |       |       | - s_host:   mac address of Next-Hop
 *          |       |       | - type:     ARP type
 *          |       |
 *          |       | - Compute ARP Header
 *          |       |       | - op:       REQUEST
 *          |       |       | - tha:      broadcast (FF:FF:FF:FF:FF:FF)
 *          |       |       | - sha:      mac address of Next-Hop
 *          |       |       | - tpa:      IP of next hop  
 *          |       |
 *          |   - len 
 *          |       |  - Compute sum of sizes of all headers included
 *          |       |       | - size(Ether Header) + size(ARP Header)
 *          |   - interface
 *          |       |   - Interface of next-route
 * 
 * 
 * @param m - initial packet
 * @param route  - route for forwarding
 */

void send_request_arp(packet m, struct route_table_entry *route) {
    /* Prepare new packet */
    packet request;

    /* Compute new len */
    request.len = sizeof(struct ether_header) + sizeof(struct arp_header);

    /* Send packet on the route's interface */
    request.interface = route->interface;
    
    /* Obtain Next-Hop's Mac and Ip adresses */
    uint8_t *__next_hop_mac_addr = malloc(6 * sizeof(uint8_t));
    get_interface_mac(route->interface, __next_hop_mac_addr);
    uint32_t __next_hop_ip_addr;
    inet_pton(AF_INET, get_interface_ip(route->interface), &__next_hop_ip_addr);


    /* Compute new Ether Header */
    struct ether_header *__new_ether_header = malloc(1 * sizeof(struct ether_header));
    uint8_t *broadcast = broadcast_addr();
    memcpy(__new_ether_header->ether_dhost, broadcast, 6 * sizeof(uint8_t));
    memcpy(__new_ether_header->ether_shost, __next_hop_mac_addr, 6 * sizeof(uint8_t));
    __new_ether_header->ether_type = ARP;
    /* Copy Ether Header in new packet's payload */
    memcpy(request.payload, __new_ether_header, sizeof(struct ether_header));


    /* Compute new ARP Header */
    struct arp_header *__new_arp_header = malloc(1 * sizeof(struct arp_header));
    __new_arp_header->ptype = htons(2048);
    __new_arp_header->htype = htons(1);
    __new_arp_header->plen = 4;
    __new_arp_header->hlen = 6;
    __new_arp_header->op = REQUEST;
    memcpy(__new_arp_header->sha, __next_hop_mac_addr, 6 * sizeof(uint8_t));
    memcpy(__new_arp_header->tha, broadcast , 6 * sizeof(uint8_t));
    memcpy(&__new_arp_header->spa, &__next_hop_ip_addr, sizeof(uint32_t));
    memcpy(&__new_arp_header->tpa, &route->next_hop, sizeof(uint32_t));
    /* Copy ARP Header in new packet's payload */
    memcpy(request.payload + sizeof(struct ether_header), __new_arp_header, sizeof(struct arp_header));

    send_packet(&request);
}

/**
 * @brief Construct a send reply 
 * 
 *  
 *  Steps:  - Compute new package:
 *          |  - payoad 
 *          |       |
 *          |       | - Compute Ether Header
 *          |       |       | - d_host:   souce_host from initial package (sending back the packet)
 *          |       |       | - s_host:   mac address of current router
 *          |       |       | - type:     ARP type
 *          |       |
 *          |       | - Compute ARP Header
 *          |       |       | - op:       REPLY
 *          |       |       | - tha:      souce_host from initial package (sending back the packet)
 *          |       |       | - sha:      mac address of current router
 *          |       |       | - tpa:      souce_host from initial package (sending back the packet)
 *          |       |       | - spa:      ip adress of current router
 *          |       |
 *          |   - len 
 *          |       |  - Compute sum of sizes of all headers included
 *          |       |       | - size(Ether Header) + size(ARP Header)
 *          |   - interface
 *          |       |   - Interface of next-route
 * 
 * 
 * @param m - initial packet
 */

void send_reply_arp(packet m) {
    /* Prepare new packet */
    packet reply;

    /* Compute new len */
    reply.len = sizeof(struct ether_header) + sizeof(struct arp_header);

    /* Send packet on the route's interface */
    reply.interface = m.interface;

    /* Obtain ARP Header from initial packet */
    struct arp_header *__arp_header = ((void *)(struct ether_header *) m.payload) + sizeof(struct ether_header);
    
    /* Obtain Router's mac and Ip address */
    uint32_t __router_ip_addr;
    inet_pton(AF_INET, get_interface_ip(m.interface), &__router_ip_addr);
    uint8_t *__router_mac_addr = malloc(6 * sizeof(uint8_t));
    get_interface_mac(m.interface, __router_mac_addr); 


    /* Compute new Ether Header */
    struct ether_header *__new_ether_header = malloc(1 * sizeof(struct ether_header));
    memcpy(__new_ether_header->ether_shost, __router_mac_addr, 6 * sizeof(uint8_t));
    memcpy(__new_ether_header->ether_dhost, __arp_header->sha, 6 * sizeof(uint8_t));
    __new_ether_header->ether_type = ARP;
    /* Copy Ether Header in new packet's payload */
    memcpy(reply.payload, __new_ether_header, sizeof(struct ether_header));

    
    /* Compute new ARP Header */
    struct arp_header *__new_arp_header = malloc(1 * sizeof(struct arp_header));
    __new_arp_header->ptype = htons(2048);
    __new_arp_header->htype = htons(1);
    __new_arp_header->plen = 4;
    __new_arp_header->hlen = 6;
    __new_arp_header->op = REPLY;    
    memcpy(__new_arp_header->sha, __router_mac_addr, 6 * sizeof(uint8_t));
    memcpy(__new_arp_header->tha, __arp_header->sha, 6 * sizeof(uint8_t));
    memcpy(&__new_arp_header->spa, &__router_ip_addr, sizeof(uint32_t));
    memcpy(&__new_arp_header->tpa, &__arp_header->spa, sizeof(uint32_t));
    /* Copy ARP Header in new packet's payload */
    memcpy(reply.payload + sizeof(struct ether_header), __new_arp_header, sizeof(struct arp_header));

    send_packet(&reply);
}



/**
 * @brief Functiun that realocs cache table's size
 * 
 * @param __cache_table pointer to cache table
 * @param len  size of cache table
 */
void realoc_cache(struct arp_entry **__cache_table, int *len) {
    struct arp_entry *aux = malloc((*len + 1) * sizeof(struct arp_entry));

    for(int i = 0; i < *len; i++) {
        aux[i].ip = (*__cache_table)[i].ip;
        memcpy(aux[i].mac, (*__cache_table)[i].mac, 6);
    }

    free(*__cache_table);
    (*__cache_table) = malloc((*len + 1) * sizeof(struct arp_entry));
    (*len) = (*len) + 1;
    for(int i = 0; i < *len - 1; i++) {
        (*__cache_table)[i].ip = aux[i].ip;
        memcpy((*__cache_table)[i].mac, aux[i].mac, 6);
    }
    free(aux);
}

/**
 * @brief Receive a reply packet
 * 
 * When receiving a reply packet, the router must check if the received IP address has
 * been already updated in the cache table. If it wasn't, it updates the cache table
 * and realocs its memory, adding the last line with the corresponding (id, mac). 
 * 
 * @param m - initial packet
 * @param __cache_table - pointer to cache table
 * @param len - len of cache table
 */


void receive_reply_arp(packet m, struct arp_entry **__cache_table, int *len) {
    /* Obtain ARP Header from initial packet */
    struct arp_header *__arp_header = ((void *)(struct ether_header *) m.payload) + sizeof(struct ether_header);

    /* Extract new IP and Mac adress from ARP Header */
    uint32_t __new_ip_address = __arp_header->spa;
    uint8_t *__new_mac_adress = __arp_header->sha;

    /* Search if the received data is already stored in the cache table */
    if(search_new_entry(*__cache_table, *len,  __new_ip_address, __new_mac_adress) != 0) {
        /* Realoc cache memory and increment its size */
        realoc_cache(__cache_table, len);

        /* Store a copy of the received data*/
        (*__cache_table)[*len - 1].ip = __new_ip_address;
        memcpy((*__cache_table)[*len - 1].mac, __new_mac_adress, 6 * sizeof(uint8_t));
    }
}




/**
 * @brief Updates queque of packets when an ARP reply is received with new data
 * 
 * Steps:
 *          A) Iterate through the queue and search for packets undelivered 
 *             having the new data received from ARP reply
 *          B) Use an auxiliar queue for storing the undelivered packets
 *          C) Put the packets from auxiliar queue back to the initial queue
 * 
 * @param packet_queue - queue of packets
 * @param __cache_table - cache table
 * @param len - size of cache table
 * @param __routing_table - routing table
 * @param __routing_table_len - size of routing table
 */

void update_queue(queue *packet_queue,
                struct arp_entry *__cache_table, int len,
                struct route_table_entry *__routing_table,
                int __routing_table_len) {

    /* Initiate a new auxliar queue */
    queue aux = queue_create();
    struct ether_header *__ether_header;
    struct iphdr *__ipv4_header;
    struct route_table_entry *__best_route;
    struct arp_entry *__best_route_mac;
    struct in_addr addr;


    while(queue_empty(*packet_queue) == 0) {
        /* Extract first element in the queue */
        packet *front = (packet *) queue_deq(* packet_queue);

        /* Obtain its Ether Header and IPv4 Header */
        __ether_header = (struct ether_header *) front->payload;
        __ipv4_header = ((void *) __ether_header) + sizeof(struct ether_header);

        /* Compute next hop */
        addr.s_addr = __ipv4_header->daddr;
        __best_route = get_best_route(__routing_table, addr,__routing_table_len);

        /* Check the existance of next hop */
        if(__best_route != NULL) {
            /* Search for the corresponding mac adress */
            if(search_mac_address(__cache_table, __best_route->next_hop, len) == NULL) {

                /* If we still hadn't find the mac adress, store in temporaly auxiliar queue */
                queue_enq(aux, (void *) front);
            } else {
                
                /* Obtain mac adress of next hop */
                __best_route_mac = search_mac_address(__cache_table, __best_route->next_hop, len);

                /* Update packet's fields */
                __ipv4_header->ttl --;
                __ipv4_header->check = RFC1624_checksum(__ipv4_header);

                /* Compute new Ether header */
                memcpy(__ether_header->ether_dhost, &__best_route_mac->mac, 6);
                get_interface_mac(__best_route->interface, __ether_header->ether_shost);

                /* Send packet on the route's interface */
                front->interface = __best_route->interface;

                send_packet(front);                  
            }
        }
    }

    /* Restore the remaining packets from the auxiliar queue */
    while(!queue_empty(aux)) {
        queue_enq(*packet_queue, (packet *) queue_deq(aux));
    }
}

/**
 * @brief Functian that makes deep copy of a specified packet in
 * order to store it in the queue
 * 
 * @param m - initial packet
 * @param __queue - packets queue
 */

void add_packet_to_queue(packet m, queue __queue) {
    /* Create new packet */
    packet *aux = malloc(sizeof (packet));
    
    /* Deep copy given packet */
    aux->interface = m.interface;
    aux->len = m.len;
    memcpy(aux->payload, &m.payload, sizeof(m.payload));

    /* Add packet to queue */
    queue_enq(__queue, aux);
}