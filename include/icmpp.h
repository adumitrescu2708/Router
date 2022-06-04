#include "skel.h"
#include <netinet/ip_icmp.h>

/**
 * @brief Header for ICMP functions
 * 
 * @author Dumitrescu Alexandra
 * @since See more: <icmp.c>
 */

void send_icmp_error_packet(packet m, uint8_t code, uint8_t type);

void send_destination_unreachable(packet m);

void send_time_limit_excedeed(packet m);

int check_icmp_request(packet m);