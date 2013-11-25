#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "lkm.h"

MODULE_LICENSE("GPL");

struct nf_hook_ops nf_incoming_hook;
struct nf_hook_ops nf_outgoing_hook;
char *filter;
struct rule* rules_in = NULL;
struct rule* rules_out = NULL;
//
// Most important - this is what binds the configuration string to
// the parameter 'filter'
//
module_param(filter, charp, 0);

int are_mac_addresses_equal(
    const BYTE *addr1, 
    const BYTE *addr2)
{
    int i = 0 ; 
    while ( i < eth_num_bytes){
        if( addr1[i] != addr2[i])
            return 0;
        i++;
    }
    return 1;
}

int are_ip_addresses_equal( 
    const BYTE *addr1, 
    const uint32_t addr2)
{
    int i = 0 ; 
    BYTE *addr2_byte =  (BYTE *)&addr2;
    
    // printk( KERN_INFO ": %x %x %x %x, %x %x %x %x\n", 
    //     addr1[0], addr1[1], addr1[2], addr1[3],
    //     addr2_byte[0], addr2_byte[1], addr2_byte[2], addr2_byte[3]);
    
    while ( i < ip_num_bytes){
        if( addr1[i] != addr2_byte[i]){
            return 0;
        }
        i++;
    }
    return 1;
}


int are_trans_addresses_equal( 
    const int addr1, 
    const uint16_t addr2)
{
    if( addr1 != addr2){
        return 0;
    }
    return 1;
}


// This method will return NF_DROP only if the rule applies to this packet and the action is DROP.
// Otherwise, return NF_ACCEPT

unsigned int apply_single_rule_to_packet(
    const struct rule* rule , 
    const struct packet* packet)
{
    unsigned int decision = NF_ACCEPT;

    if (rule->eth.type & fld_SRC) {
        //
        // No need to bother if the address doesn't match, the rest of the rule doesn't matter now
        //
        if (!are_mac_addresses_equal(rule->eth.src, packet->src_mac_address)) {
            goto finished;
        }
    }

    if (rule->eth.type & fld_DEST) {
        //
        // No need to bother if the address doesn't match, the rest of the rule doesn't matter now
        //
        if (!are_mac_addresses_equal(rule->eth.dest, packet->dest_mac_address)) {
            goto finished;
        }
    }

    if (rule->ip.type & fld_SRC) {
        //
        // No need to bother if the address doesn't match, the rest of the rule doesn't matter now
        //
        if (!are_ip_addresses_equal(rule->ip.src, packet->src_ip_address)) {
            goto finished;
        }        
    }

    if (rule->ip.type & fld_DEST) {
        //
        // No need to bother if the address doesn't match, the rest of the rule doesn't matter now
        //
        if (!are_ip_addresses_equal(rule->ip.dest, packet->dest_ip_address)) {
            goto finished;
        }        
    }

    if (packet->ip_next_proto == rule->trans.src_protocol) {
        //
        // No need to bother if the address doesn't match, the rest of the rule doesn't matter now
        //
        if (!are_trans_addresses_equal(rule->trans.src, packet->tcp.src_port)) {
            goto finished;
        }   
    }
    else if (rule->trans.src_protocol != 0) {
        //
        // Rule is mentioned but protocol doesn't match
        //
        goto finished;
    }

    if (packet->ip_next_proto == rule->trans.dest_protocol) {
        //
        // No need to bother if the address doesn't match, the rest of the rule doesn't matter now
        //
        if (!are_trans_addresses_equal(rule->trans.dest, packet->tcp.dest_port)) {
            goto finished;
        }   
    }
    else if (rule->trans.dest_protocol != 0) {
        //
        // Rule is mentioned but protocol doesn't match
        //
        goto finished;
    }

    decision = (rule->action == act_DROP) ? NF_DROP : NF_ACCEPT;

finished:
    return decision;
}

unsigned int apply_filters_to_packet(
    const struct rule* list,
    const struct packet* packet)
{
    int decision = NF_ACCEPT; 
    //
    // If there are two conflicting rules, NF_DROP will take
    // precedence. 
    //
    while( list != NULL){
        decision = apply_single_rule_to_packet(list,packet);
        if( decision == NF_DROP){
            goto finished;
        }
        list = list->next;
    }

finished:
    return decision;
}    


int skbuff_to_packet(
    BYTE direction,
    const struct net_device* device,
    struct sk_buff* skb,
    struct packet* packet) 
{
    struct ethhdr* eth_header = NULL; 
    struct iphdr* ip_header = NULL;
    struct udphdr* udp_header = NULL;
    struct tcphdr* tcp_header = NULL;
    //
    // Check if this is an ethernet device that sent the packet
    //
    if (device->type != ARPHRD_ETHER) {
        goto error;
    }

    if (direction == dir_IN)
        eth_header = eth_hdr(skb);
    
    if (skb->protocol == htons(ETH_P_IP)) {
        //
        // Extract the IP Header
        // Note, we cannot use the Ethernet header->next protocol field
        // as the Ethernet header would not be available in the OUT path
        //
        ip_header = ip_hdr(skb);
        if (ip_header->protocol == IPPROTO_UDP) {
            //
            // Extract the UDP header and the fields required for UDP filtering
            //
            udp_header = udp_hdr(skb);
            packet->ip_next_proto = IPPROTO_UDP;
            packet->udp.src_port = udp_header->source;
            packet->udp.dest_port = udp_header->dest;
        }
        else if (ip_header->protocol == IPPROTO_TCP) {
            //
            // Extract the TCP header and the fields required for TCP filtering
            //
            tcp_header = tcp_hdr(skb);
            packet->ip_next_proto = IPPROTO_TCP;
            packet->tcp.src_port = tcp_header->source;
            packet->tcp.dest_port = tcp_header->dest;
        }
        else {
            //
            // This type of packet is not served by our module
            //
            goto error;
        }

        if (direction == dir_IN) {
            memcpy(packet->src_mac_address, eth_header->h_dest, eth_num_bytes);
            memcpy(packet->dest_mac_address, eth_header->h_source, eth_num_bytes);
        }

    	packet->src_ip_address = ip_header->saddr;
        packet->dest_ip_address = ip_header->daddr;
    }
    else {
        //
        // This type of packet is not served by our module
        //
        goto error;
    }

    printk(KERN_INFO "%p %p %d %d %d %d\n", (void *)skb, (void *)skb->head, skb->end, skb->mac_header, skb->network_header, skb->transport_header);
    
    return 0;

error:
    return -1;  
}

unsigned int hook_func_outgoing(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    unsigned int decision = NF_ACCEPT;
    struct packet* packet = NULL;

    //
    // Fastpath: if there are no outgoing rules, nothing to do; act as pass through
    //
    if (rules_out == NULL) {
        goto end;
    }

    packet = (struct packet*)kmalloc(sizeof(struct packet), GFP_KERNEL);
    if (packet == NULL) {
        printk(KERN_INFO "Error in memory allocation\n");
        goto end;
    }
    //
    // Parse the sk_buff structure and retrieve all fields that we need to take a look at
    //
    if (skbuff_to_packet(dir_OUT, out, skb, packet) == -1) {
        //
        // A return value of -1 indicates that it is not one of the packets we parse
        //
        decision = NF_ACCEPT;
        goto end;
    }

   decision = apply_filters_to_packet(rules_out, packet);
   printk("Outgoing: Decision for %p: %u", (void *)skb, decision);

end:

    // if (out->type == ARPHRD_ETHER)
    //     printk(KERN_INFO "outgoing: %p %p %d %d %d %d\n", (void *)skb, (void *)skb->head, skb->end, skb->mac_header, skb->network_header, skb->transport_header);
    
    if (packet != NULL) {
        kfree(packet);
    }
    return decision;
}

unsigned int hook_func_incoming(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    unsigned int decision = NF_ACCEPT;
    struct packet* packet = NULL;

    //
    // Fastpath: if there are no incoming rules, nothing to do; act as pass through
    //
    if (rules_in == NULL) {
        decision = NF_ACCEPT;
        goto end;
    }

    packet = (struct packet*)kmalloc(sizeof(struct packet), GFP_KERNEL);
    //
    // Parse the sk_buff structure and retrieve all fields that we need to take a look at
    //
    if (skbuff_to_packet(dir_IN, in, skb, packet) == -1) {
        //
        // A return value of -1 indicates that it is not one of the packets we parse
        //
        decision = NF_ACCEPT;
        goto end;
    }

   decision = apply_filters_to_packet(rules_in, packet);
   printk("incoming: Decision for %p: %u", (void *)skb, decision);

end:

    // if (in->type == ARPHRD_ETHER)
    //     printk(KERN_INFO "incoming: %p %p %d %d %d %d\n", (void *)skb, (void *)skb->head, skb->end, skb->mac_header, skb->network_header, skb->transport_header);
    
    if (packet != NULL) {
        kfree(packet);
    }
    return decision;
}

BYTE get_dec_from_hex(const BYTE c) 
{
    if (c >= 48 && c <= 58) {
        return c - 48;
    }
    else if (c >= 65 && c <= 70) {
        return c - 55;
    }
    else if (c >= 97 && c <= 102) {
        return c - 87;
    }
    else 
        return -1;
}

//
// Reads the port number associated with a tcp or udp rule
// Returns the number of characters read or -1 in case of an error
//
int get_port(
    BYTE field,
    const char* rule_str,
    const int rule_len,
    struct rule* rule) 
{
    int index = 0, port = 0, expt = 1, ret;
    const char rule_delimiter = '|', delimiter = ',';

    while (rule_str[index] != '\0' && rule_str[index] != rule_delimiter
        && rule_str[index] != ' '  && rule_str[index] != delimiter) {
        if (rule_str[index] < 48 || rule_str[index] > 57) {
            goto error;
        }
        index++;
    }

    ret = index;

    if (index == 0) {
        goto error;
    }

    while (index > 0) {
        index--;
        port += (rule_str[index] - 48) * expt;
        expt *= 10;
    }

    if (field == fld_SRC) {
        rule->trans.src = port;
    }
    else {
        rule->trans.dest = port;
    }

return ret;

error:
    return -1;    
}

//
// Reads a mac address associated with a mac rule
// Returns the number of characters read or -1 in case of an error
//
int get_mac_address(
    BYTE field,
    const char* rule_str, 
    const int rule_len,
    struct rule* rule) 
{
    int byte_index = 0, index = 0, num_dec_1, num_dec_2;
    const char delimiter = ':';
    unsigned char mac_address[eth_num_bytes];
    //
    // Check that the size of the string left is larger than the MAC address
    // in AA:BB:CC:DD:EE:FF notation
    //
    if (rule_len < (eth_num_bytes * 3 - 1)) {
        goto error;
    }

    while(byte_index < eth_num_bytes) {
        //
        // In case of later bytes, the first character should be a ':'
        //
        if (byte_index > 0 && rule_str[index++] != delimiter) {
            goto error;
        } 

        if ((num_dec_1 = get_dec_from_hex(rule_str[index++])) == -1)  {
            goto error;
        }

        if ((num_dec_2 = get_dec_from_hex(rule_str[index++])) == -1) {
            goto error;
        }

        mac_address[byte_index++] = num_dec_1 * 16 + num_dec_2;
    }

    if (field == fld_SRC) {
        memcpy(rule->eth.src, mac_address, eth_num_bytes);
    }
    else {
        memcpy(rule->eth.dest, mac_address, eth_num_bytes);
    }
    
    return index;

error:
    return -1;    
}

//
// Reads an ip address in the form of aaa.bbb.ccc.ddd 
// Returns the number of characters read or -1 in case of error
//
int get_ip_address(
    BYTE field,
    const char* rule_str,
    const int rule_len,
    struct rule* rule) 
{
    int byte_index = 0, index = 0, num_dec_1, num_dec_2, num_dec_3;
    const char delimiter = '.';
    unsigned char ip_address[4];
    //
    // Check if the total length of the string is larger than an IP
    // address 
    //
    if (rule_len < (ip_num_bytes * 4 - 1)) {
        goto error;
    }

    while (byte_index < ip_num_bytes) {
        //
        // In case of later bytes, the first character should be a '.'
        //
        if (byte_index > 0 && rule_str[index++] != delimiter) {
            goto error;
        }

        num_dec_1 = rule_str[index++] - 48;
        num_dec_2 = rule_str[index++] - 48;
        num_dec_3 = rule_str[index++] - 48;
        
        if (num_dec_1 < 0 || num_dec_1 > 9 || 
            num_dec_2 < 0 || num_dec_2 > 9 ||
            num_dec_3 < 0 || num_dec_3 > 9) {
            goto error;
        }

        ip_address[byte_index++] = num_dec_1 * 100 + num_dec_2 * 10 + num_dec_3;
    }

    if (field == fld_SRC) {
        memcpy(rule->ip.src, ip_address, ip_num_bytes);
    }
    else {
        memcpy(rule->ip.dest, ip_address, ip_num_bytes);
    }

    return index;

error:
    return -1;
}

//#ifdef DBG
void print_rule(struct rule* rule) 
{
    printk(KERN_INFO "Action: %x\n", rule->action & 0xFF);
    printk(KERN_INFO "Direction: %x\n", rule->dir & 0xFF);
    printk(KERN_INFO "Eth flag: %d\n", rule->eth.type);
    printk(KERN_INFO "Eth src: %x %x %x %x %x %x\n", rule->eth.src[0], rule->eth.src[1], rule->eth.src[2], rule->eth.src[3], rule->eth.src[4], rule->eth.src[5]);
    printk(KERN_INFO "Eth dest: %x %x %x %x %x %x\n", rule->eth.dest[0], rule->eth.dest[1], rule->eth.dest[2], rule->eth.dest[3], rule->eth.dest[4], rule->eth.dest[5]);
    printk(KERN_INFO "IP flag: %d\n", rule->ip.type);
    printk(KERN_INFO "IP src: %x %x %x %x\n", rule->ip.src[0], rule->ip.src[1], rule->ip.src[2], rule->ip.src[3]);
    printk(KERN_INFO "IP dest: %x %x %x %x\n", rule->ip.dest[0], rule->ip.dest[1], rule->ip.dest[2], rule->ip.dest[3]);
    printk(KERN_INFO "Trans src proto: %d\n", rule->trans.src_protocol);
    printk(KERN_INFO "Trans dest proto: %d\n", rule->trans.dest_protocol);
    printk(KERN_INFO "Trans src: %d \n", rule->trans.src);
    printk(KERN_INFO "Trans dest: %d\n\n", rule->trans.dest);
}//#endif

void add_rule_to_list(
    struct rule** list,
    struct rule* rule) 
{
    if (*list == NULL) {
        //
        // This is the first rule in this linked list
        //
        *list = rule;
    }
    else {
        //
        // Just add it on as the first rule in the list
        //
        rule->next = *list;
    }
}

void add_rule_to_lists(
    struct rule* rule) 
{
    struct rule **list, **other_list = NULL;

    if (rule->dir == dir_IN) {
        //
        // This rule applies to incoming packets only
        //
        list = &rules_in;
    }
    else if (rule->dir == dir_OUT) {
        //
        // This rule applies to outgoing packets only
        //
        list = &rules_out;
    }
    else {
        //
        // This is an inout rule, applies to both pathways
        //
        list = &rules_in;
        other_list = &rules_out;
    }
    //
    // Add to the primary list
    //
    add_rule_to_list(list, rule);
    if (other_list != NULL) {
        //
        // If it is needed to add to the other list
        // To avoid double free and make things simpler, copying to another structure
        //
        struct rule* new_rule = (struct rule*)kmalloc(sizeof(struct rule), GFP_KERNEL);
        memcpy(new_rule, rule, sizeof(struct rule));
        add_rule_to_list(other_list, new_rule);
    }
}


int create_rule(
    const char* rule_str,
    const int rule_size) 
{
    const char* temp_rule_str = rule_str, comma = ',';
    int temp_rule_len = rule_size, nbytes, type;

    struct rule* new_rule = (struct rule*)kmalloc(sizeof(struct rule), GFP_KERNEL);
    if (new_rule == NULL) {
        printk(KERN_INFO "Failed to allocate memory for rule.");
        goto error;
    }
    memset(new_rule, 0, sizeof(struct rule));
    
    if (temp_rule_len > lstr_DROP && strncasecmp(temp_rule_str, str_DROP, lstr_DROP) == 0) {
        //
        // Packet to be dropped
        //
        printk(KERN_INFO "Matched Drop.");
        new_rule->action = act_DROP; temp_rule_str += lstr_DROP; temp_rule_len -= lstr_DROP;
    }
    else if (temp_rule_len > lstr_ALLOW && strncasecmp(temp_rule_str, str_ALLOW, lstr_ALLOW) == 0) {
        //
        // Packet to be allowed
        //
        printk(KERN_INFO "Matched Allow.");
        new_rule->action = act_ALLOW; temp_rule_str += lstr_ALLOW; temp_rule_len -= lstr_ALLOW;
    }
    else {
        goto error;
    }

    if (temp_rule_len > lstr_IN && strncasecmp(temp_rule_str, str_IN, lstr_IN) == 0) {
        //
        // Rule to be applied on incoming packets
        //
        printk(KERN_INFO "Matched In.");
        new_rule->dir = dir_IN; temp_rule_str += lstr_IN; temp_rule_len -= lstr_IN;
    }
    else if (temp_rule_len > lstr_OUT && strncasecmp(temp_rule_str, str_OUT, lstr_OUT) == 0) {
        //
        // Rule to be applied on outgoing packets
        //
        printk(KERN_INFO "Matched Out.");
        new_rule->dir = dir_OUT; temp_rule_str += lstr_OUT; temp_rule_len -= lstr_OUT;
    }
    else if (temp_rule_len > lstr_INOUT && strncasecmp(temp_rule_str, str_INOUT, lstr_INOUT) == 0) {
        //
        // Rule to be applied on both incoming and outgoing packets
        //
        printk(KERN_INFO "Matched Inout.");
        new_rule->dir = dir_INOUT; temp_rule_str += lstr_INOUT; temp_rule_len -= lstr_OUT;
    }
    else {
        goto error;
    }

    //
    // In case of composite rules, the code will keep looping
    // to this label as long as there are more sections to the rule
    //
add_to_rule:
    if (strncasecmp(temp_rule_str, str_SRC, lstr_SRC) == 0) {
        //
        // Rule value should be matched with the source address
        //
        printk(KERN_INFO "Matched Src.");
        type = fld_SRC; temp_rule_str += lstr_SRC; temp_rule_len -= lstr_SRC;
    }
    else if (strncasecmp(temp_rule_str, str_DEST, lstr_DEST) == 0) {
        //
        // Rule value should be matched with the destination address
        //
        printk(KERN_INFO "Matched Dest.");
        type = fld_DEST; temp_rule_str += lstr_DEST; temp_rule_len -= lstr_DEST;
    }
    else {
        goto error;
    }

    if (temp_rule_len > lstr_MAC && strncasecmp(temp_rule_str, str_MAC, lstr_MAC) == 0
        && (new_rule->eth.type & type) == 0) {
        //
        // This rule applies to the Ethernet address, what follows should be a 
        // valid MAC address of the form AA:BB:CC:DD:EE:FF in hexadecimal notation
        //
        printk(KERN_INFO "Matched Mac.");
        //
        // Ethernet header cannot be accessed in the outgoing path
        // So, we don't allow ethernet header rules for outgoing packets
        //
        if (new_rule->dir != dir_IN) {
            printk(KERN_INFO "Mac addresses cannot be matched for outgoing packets.");
            goto error;
        }

        new_rule->eth.type |= type; temp_rule_str += lstr_MAC; temp_rule_len -= lstr_MAC;
        if ((nbytes = get_mac_address(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            printk(KERN_INFO "Failed mac address extraction.");
            goto error; 
        }
    }
    else if (temp_rule_len > lstr_IP && strncasecmp(temp_rule_str, str_IP, lstr_IP) == 0
        && (new_rule->ip.type & type) == 0) {
        //
        // This rule applies to the IP address, what follows should be a 
        // valid IPv4 address of the form AAA:BBB:CCC:DDD in decimal notation
        // TODO: Currently all 3 digits need to be specified, should remove this requirement
        //
        printk(KERN_INFO "Matched Ip.");
        new_rule->ip.type |= type; temp_rule_str += lstr_IP; temp_rule_len -= lstr_IP;
        if ((nbytes = get_ip_address(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            printk(KERN_INFO "Failed ip address extraction.");
            goto error;
        }
    }
    else if (temp_rule_len > lstr_TCP && strncasecmp(temp_rule_str, str_TCP, lstr_TCP) == 0) {
        //
        // This rule applies to the TCP ports, what follows should be a 
        // valid port number in decimal notation
        //
        printk(KERN_INFO "Matched Tcp.");
        //
        // This rule should not overwrite a previously set rule
        //
        if ((type == fld_SRC && new_rule->trans.src_protocol != 0) ||
            (type == fld_DEST && new_rule->trans.dest_protocol != 0)) {
            goto error;
        }
        //
        // The rule should not mention TCP port for one field and UDP port for the other
        //
        if (type == fld_SRC) {
            if (new_rule->trans.dest_protocol == 0 || new_rule->trans.dest_protocol == IPPROTO_TCP) 
                new_rule->trans.src_protocol = IPPROTO_TCP;
            else 
                goto error;
        }
        else {
            if (new_rule->trans.src_protocol == 0 || new_rule->trans.src_protocol == IPPROTO_TCP) 
                new_rule->trans.dest_protocol = IPPROTO_TCP;
            else
                goto error;
        }

        temp_rule_str += lstr_TCP; temp_rule_len -= lstr_TCP;
        if ((nbytes = get_port(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            printk(KERN_INFO "Failed port extraction.");
            goto error;
        }
    }
    else if (temp_rule_len > lstr_UDP && strncasecmp(temp_rule_str, str_UDP, lstr_UDP) == 0) {
        //
        // This rule applies to the UDP ports, what follows should be a 
        // valid port number in decimal notation
        //
        printk(KERN_INFO "Matched Udp.");
        //
        // This rule should not overwrite a previously set rule
        //
        if ((type == fld_SRC && new_rule->trans.src_protocol != 0) ||
            (type == fld_DEST && new_rule->trans.dest_protocol != 0)) {
            goto error;
        }
        //
        // The rule should not mention TCP port for one field and UDP port for the other
        //
        if (type == fld_SRC) {
            if (new_rule->trans.dest_protocol == 0 || new_rule->trans.dest_protocol == IPPROTO_UDP) 
                new_rule->trans.src_protocol = IPPROTO_UDP;
            else 
                goto error;
        }
        else {
            if (new_rule->trans.src_protocol == 0 || new_rule->trans.src_protocol == IPPROTO_UDP) 
                new_rule->trans.dest_protocol = IPPROTO_UDP;
            else
                goto error;
        }

        temp_rule_str += lstr_UDP; temp_rule_len -= lstr_UDP;
        if ((nbytes = get_port(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            printk(KERN_INFO "Failed port extraction.");
            goto error;
        }
    }
    else {
        printk(KERN_INFO "Match failed.");
        goto error;
    }

    temp_rule_len -= nbytes;
    temp_rule_str += nbytes;
    type = 0;
    //
    // Check if there is anything left of the rule string, if there 
    // is then go ahead and parse it again for more fields
    //
    if (temp_rule_len != 0) {
        if (temp_rule_str[0] == comma) {
            temp_rule_str++;
            temp_rule_len--;
            goto add_to_rule;
        }
        else 
            goto error;
    }

//#ifdef DBG
    //
    // Dump out the rule just in case
    //
    print_rule(new_rule);
//#endif 
    //
    // Add the rule to whichever list it needs to be added to
    //
    add_rule_to_lists(new_rule);
    return 0;

error:
    printk("Rule: %s %d\n", temp_rule_str, temp_rule_len);
    print_rule(new_rule);
    if (new_rule != NULL) {
        kfree(new_rule);
    }

    return -1;
}

int parse_filter_rules(void) 
{
    const char *current_rule;
    int current_size = 0, size, index = 0;
    const char delimiter = '|';
    //
    // Trim starting spaces
    //
    while (filter[index] == ' ') {
        index++;
    }

    printk(KERN_INFO "Filter string is: %s\n.", filter);
    size = strlen(filter);
    current_rule = filter;

    while (index <= size) {
        if (filter[index] == delimiter || filter[index] == '\0') {
            //
            // Encountered a delimiter or end of string
            // All characters from current_rule to here are part of a rule
            //
            current_size = &filter[index] - current_rule;
            if (0 != create_rule(current_rule, current_size)) {
                printk(KERN_INFO "Failed to create rule at: %s %d\n.", current_rule, current_size);
                return -1;
            }

            index++;
            while (filter[index] == ' ' && index < size) {
                index++;
            }       
            current_rule = &filter[index];
        }
        else {
            //
            // Just increment and move on to the next character
            //
            index++;
        }
    }
    return 0;
}

void cleanup_rule_list(struct rule* list) 
{
    struct rule* first, *temp;
    first = list;

    while (first != NULL) {
        temp = first->next;
        kfree(first);
        first = temp;
    }
}

int init_module(void) 
{
    //
    // Read and parse the rules specified in the rules file
    //
    if (0 != parse_filter_rules()) {
        printk(KERN_INFO "Failed to parse rules.");
       return -1;
    }
    printk(KERN_INFO "Completed parsing rules.");
    //
    // Register the hook for outgoing packets
    //
    nf_outgoing_hook.hook = hook_func_outgoing;
    nf_outgoing_hook.hooknum = NF_INET_POST_ROUTING;
    nf_outgoing_hook.pf = PF_INET;
    nf_outgoing_hook.priority = NF_IP_PRI_LAST;
    nf_register_hook(&nf_outgoing_hook);
    //
    // Register the hook for incoming packets
    //
    nf_incoming_hook.hook = hook_func_incoming;
    nf_incoming_hook.hooknum = NF_INET_PRE_ROUTING;
    nf_incoming_hook.pf = PF_INET;
    nf_incoming_hook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nf_incoming_hook);
    
    printk(KERN_INFO "Simple firewall loaded.");
    printk(KERN_INFO "%s\n", filter);
    return 0;
}

void cleanup_module(void) 
{
    // UN-register the hook with netfilter
    nf_unregister_hook(&nf_incoming_hook);
    nf_unregister_hook(&nf_outgoing_hook);
    //
    // Delete the allocated memory
    //
    cleanup_rule_list(rules_in);
    cleanup_rule_list(rules_out);
    printk(KERN_INFO "Simple firewall unloaded\n");
}
