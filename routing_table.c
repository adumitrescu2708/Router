#include "skel.h"
#include "routing_table.h"

/**
 * @brief Functions for Routing Table
 *  
 * @author Dumitrescu Alexandra
 * @since April 2022
 */


/**
 * @brief Get the best route object
 * Searches for the corresponding next hop given the destination as
 * parameter
 * 
 * @param __routing_table - routing table
 * @param dest_ip_address - searched ip adress
 * @param __routing_table_len - size of routing table
 * @return struct route_table_entry* - line in the routing table or NULL
 */

struct route_table_entry *get_best_route(struct route_table_entry *__routing_table,
                                struct in_addr dest_ip_address,
                                int __routing_table_len)
{
    int best_route = -1;

    for(int i = 0; i < __routing_table_len; i++) {
        if((dest_ip_address.s_addr & __routing_table[i].mask) == __routing_table[i].prefix) {
            if(best_route == -1) {
                best_route = i;
            } else {
                if(ntohl(__routing_table[i].mask) > ntohl(__routing_table[best_route].mask)) {
                    best_route = i;
                }
            }
        }
    }
    if(best_route != -1)
        return &(__routing_table[best_route]);
    return NULL;
} 

/**
 * @brief Binary search for next hop IP adress in the routing table
 * 
 * Computing the binary search handels an issue. There coult be multiple matches in 
 * the binary search for a single destination IP. Therefor, whenever finding a correct
 * next-hop we continue searching for another correct adress to the left, as we are
 * looking for the match with the greatest mask.
 * 
 * @param __routing_table routing table 
 * @param dest_ip_address destination IP
 * @param left_idx left index in the binary search
 * @param right_idx right inde in the binary search
 * @param result result line in the routing table
 * @return int -1 if there is no math or the line of the match
 */
int binary_search(struct route_table_entry *__routing_table,
                                        struct in_addr dest_ip_address,
                                        int left_idx, int right_idx, int result) {                   
    
    if(right_idx > left_idx) {
        int i;
        /* Compute middle index */
        if((left_idx + right_idx) % 2 == 1)
            i = (left_idx + right_idx) / 2 + 1;
        else
            i = (left_idx + right_idx) / 2;

        /* If there is a match, continue searching to the left */
        if((dest_ip_address.s_addr & __routing_table[i].mask) == (__routing_table[i].prefix)) {
            return binary_search(__routing_table, dest_ip_address, i + 1, right_idx, i);
        }

        /* Continue searching to the right */
        if(((dest_ip_address.s_addr & __routing_table[i].mask) < (__routing_table[i].prefix))) {
            return binary_search(__routing_table, dest_ip_address, left_idx, i - 1, result);
        }      
        
        /* Continue searching to the left */
        return binary_search(__routing_table, dest_ip_address, i + 1, right_idx, result);
    } else {
        /* Check the single-item last interval */
        if(right_idx == left_idx) {
            if((dest_ip_address.s_addr & __routing_table[right_idx].mask) == (__routing_table[right_idx].prefix)) {
                result = right_idx;
            }             
        }

        /* Compute the final result */
        if(result == -1)
            return -1;
        else
            return result;
    }

}

/**
 * @brief Compare function for routing table
 * Sorting ascending from prefix and then ascending for mask
 */
int compare(const void *a, const void *b) {
    if((*((struct route_table_entry *) a)).prefix > (*((struct route_table_entry *) b)).prefix)
        return 1;
    if((*((struct route_table_entry *) a)).prefix == (*((struct route_table_entry *) b)).prefix
        && (*((struct route_table_entry *) a)).mask > (*((struct route_table_entry *) b)).mask)
            return 1;
    return 0;
}
