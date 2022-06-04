
#include "icmpp.h"
#include "routing_table.h"
#include <netinet/ip_icmp.h>

#define DESTINATION_UNREACHABLE_TYPE 3
#define TIME_EXCEDEED_TYPE 11
#define REPLY_TYPE 0
#define REQUEST_TYPE 8

/**
 *               ICMP PROTOCOL
 * 
 * Treating 3 main ussages for ICMP protocol:
 *            A) Time Out
 *            B) Destination Unreachable
 *            C) Echo reply
 * 
 * In order to send an ICMP packet, we first check the applicability of
 * the ICMP protocol and then compute the corresponding IPv4 header
 * and Ether header from the initial packet.
 * 
 * Case:     A) Whenever a packet is received with the time limit
 *              expired (checking the ttl field in IPv4 header), we send
 *              an ICMP error package with Error_Type and Error_Code (11, 0)
 * 
 *           B) Whenever a packet is received with an unknown
 *              destination IP, (checking the correspondent IP in the routing
 *              table of the router), we send an ICMP error packet
 *              with Error_Type and Error_Code (3, 0)
 * 
 *           C) A router can receive an Echo Request from a Host, in which
 *              case we send an Echo Reply packet with Error_Type and Error_Code (0, 0)
 * 
 * Implement: Common utility function for all 3 cases, differences in Error_Type
 *            and Error_Code
 * 
 * 
 * @author Dumitrescu Alexandra
 * @since April 2022 
 */



/**
 * @brief Construct a new icmp error packet object
 * 
 *  Steps:  - Compute new package:
 *          |  - payoad 
 *          |       |
 *          |       | - Compute Ether Header
 *          |       |       | - d_host:   souce_host from initial package (sending back the packet)
 *          |       |       | - s_host:   mac address of current router
 *          |       |       | - type:     Ipv4 type
 *          |       |
 *          |       | - Compute Ipv4 Header
 *          |       |       | - protocol: ICMP type
 *          |       |       | - daddr:    source_address from initial package (sending back the packet)
 *          |       |       | - saddr:    IP address of current router
 *          |       |       | - check:    Recompute checksum
 *          |       |
 *          |       | - Compute ICMP Header
 *          |       |       | - type:       @type param (could be 0, 3 or 11 in our problem)
 *          |       |       | - code:       @code param (could be 0)
 *          |       |       | - check:      Recompute checksum
 *          |   - len 
 *          |       |  - Compute sum of sizes of all headers included
 *          |       |       | - size(Ether Header) + size(IPv4 Header) + size(ICMP header)
 *          |   - interface
 *          |       |   - Interface of initial packet (sending back the packet on same interface)
 *              
 * 
 * @param m - initial package
 * @param code - code required for ICMP header
 * @param type - type required for ICMP header
 */

void send_icmp_error_packet(packet m, uint8_t code, uint8_t type) {
    /* Prepare new packet */
    packet new;

    /* Compute new len */
    new.len = sizeof(struct ether_header) + sizeof(struct icmphdr) + sizeof(struct iphdr);

    /* Send packet back on same interface */
    new.interface = m.interface;

    /* Obtain Ether Header and Ipv4 Header from initial packet */
    struct ether_header *__ether_header = (struct ether_header *) m.payload;
    struct iphdr *__ipv4_header = (void *)__ether_header + sizeof(struct ether_header);

    /* Obtain Router's mac and Ip address */
    uint32_t router_ip_adr;
    inet_pton(AF_INET, get_interface_ip(m.interface), &router_ip_adr);
    uint8_t *router_mac_adr = malloc(6 * sizeof(uint8_t));
    get_interface_mac(m.interface, router_mac_adr);

    /* Compute new Ether Header */
    struct ether_header *new_eth_header = malloc(sizeof(struct ether_header));
    memcpy(new_eth_header->ether_dhost, __ether_header->ether_shost, 6);
    memcpy(new_eth_header->ether_shost, router_mac_adr, 6);
    new_eth_header->ether_type = IPv4;
    /* Copy Ether Header in new packet's payload */
    memcpy(new.payload, new_eth_header, sizeof(struct ether_header));


    /* Compute new IPv4 Header */
    struct iphdr *new_ipv_header = malloc(sizeof(struct iphdr));
	new_ipv_header->protocol = 1;
	new_ipv_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	new_ipv_header->id = htons(1);
	new_ipv_header->check = 0;
    memcpy(&new_ipv_header->daddr, &__ipv4_header->saddr, sizeof(uint32_t));
    memcpy(&new_ipv_header->saddr, &router_ip_adr, sizeof(uint32_t)); 
    new_ipv_header->check = 0;
    new_ipv_header->check = ip_checksum((void *) new_ipv_header, sizeof(struct iphdr));
    /* Copy IPv4 Header in new packet's payload */
    memcpy(new.payload + sizeof(struct ether_header), new_ipv_header, sizeof(struct iphdr));


    /* Compute new ICMP Header*/
    struct icmphdr __icmp_header;
    __icmp_header.type = type;
    __icmp_header.code = code;
    __icmp_header.checksum = 0;
    __icmp_header.checksum = icmp_checksum((uint16_t *)&__icmp_header, sizeof(struct icmphdr));
    /* Copy ICMP Header in new packet's payload */
    memcpy(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr), &__icmp_header, sizeof(struct icmphdr));
    
    send_packet(&new);      
}


/**
 * @brief Map corresponding (code, type) to specific operations
 * 
 * @param m - initial package
 */
void send_destination_unreachable(packet m) {
   send_icmp_error_packet(m, 0, DESTINATION_UNREACHABLE_TYPE);
}
void send_time_limit_excedeed(packet m) {
    send_icmp_error_packet(m, 0, TIME_EXCEDEED_TYPE);
}
void send_reply(packet m) {
    send_icmp_error_packet(m, 0, REPLY_TYPE);
}

/**
 * @brief Check existance of an ICMP Echo Request
 * 
 * When a packet is received, we first check whether an IPv4 Header is present and
 * its operation is set to 1, meaning there is an ICMP Header. Then, we check the
 * type of operation set in the ICMP header (should be of REQUEST_TYPE) and
 * whether the destination adress is current router's adress.
 * 
 * If there is an ICMP request for the router we send a reply and return a TRUE
 * value, and FALSE value otherwise
 * 
 * @param m - initial package
 * @return int - True/False
 */
int check_icmp_request(packet m) {
    /* Obtain IPv4 Header from received packet */
    struct iphdr *__ipv4_header = (void *) m.payload + sizeof(struct ether_header);

    /* Obtain current router's IP address*/
    uint32_t router_ip_adr;
    inet_pton(AF_INET, get_interface_ip(m.interface), &router_ip_adr);

    /* Check if the protocol in IP Header is set to 1 (ICMP) */
    if(__ipv4_header->protocol == 1) {

        /* Obtain ICMP Header from received packet */
        struct icmphdr *__icmp_header = (void *)__ipv4_header + sizeof(struct iphdr);

        /* Check if there is an Echo Request */
        if(__icmp_header->type == REQUEST_TYPE && __icmp_header->code == 0) {
            
            /* Check if the request is for the current router */
            if(__ipv4_header->daddr == router_ip_adr) {
                send_reply(m);
                return 1;
            }
        }
    }
    return 0;
}