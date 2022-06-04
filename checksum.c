#include "checksum.h"

uint16_t RFC1624_checksum(struct iphdr *ip_hdr)
{
	uint16_t old_ttl = 0 + ((ip_hdr->ttl + (uint8_t) 1));
	uint16_t new_ttl = 0 + ip_hdr->ttl;

	return ~(~ip_hdr->check + ~old_ttl + new_ttl) - 1;
}