#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include "lkm.h"

MODULE_LICENSE("GPL");

struct nf_hook_ops nf_incoming_hook;
struct nf_hook_ops nf_outgoing_hook;
char *filter;
struct rule* rules_in = NULL;
struct rule* rules_out = NULL;

module_param(filter, charp, 0);

unsigned int hook_func_outgoing(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
//    unsigned char* mac_header = skb_mac_header(skb);
//    unsigned char* net_header = skb_network_header(skb);
//    unsigned char* transport_header = skb_transport_header(skb);
    printk(KERN_INFO "%d\n", out->type);
    return NF_ACCEPT;        
}

unsigned int hook_func_incoming(
    unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{
    // printk(KERN_INFO "%d\n", in->type);
    return NF_ACCEPT;
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


int get_port(
    const char* rule_str,
    const int rule_len,
    struct rule* rule) 
{
    int index = 0, port = 0, expt = 1;
    const char delimiter = '|';

    while (rule_str[index] != '\0' && rule_str[index] != delimiter) {
        if (rule_str[index] < 48 || rule_str[index] > 57) {
            goto error;
        }
        index++;
    }

    if (index == 0) {
        goto error;
    }

    while (index > 0) {
        index--;
        port += rule_str[index] * expt;
        expt *= 10;
    }

    if (rule->fld == fld_SRC) {
        rule->net.src = port;
    }
    else {
        rule->net.dest = port;
    }

return 0;

error:
    return -1;    
}


int get_mac_address(
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

    if (rule->fld == fld_SRC) {
        memcpy(rule->eth.src, mac_address, eth_num_bytes);
    }
    else {
        memcpy(rule->eth.dest, mac_address, eth_num_bytes);
    }
    
    return 0;

error:
    return -1;    
}

int get_ip_address(
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

    if (rule->fld == fld_SRC) {
        memcpy(rule->ip.src, ip_address, ip_num_bytes);
    }
    else {
        memcpy(rule->ip.dest, ip_address, ip_num_bytes);
    }

    return 0;

error:
    return -1;
}

//#ifdef DBG
void print_rule(struct rule* rule) 
{
    printk(KERN_INFO "Type: %x\n", rule->type & 0xFF);
    printk(KERN_INFO "Action: %x\n", rule->action & 0xFF);
    printk(KERN_INFO "Field: %x\n", rule->fld & 0xFF);
    printk(KERN_INFO "Direction: %x\n", rule->dir & 0xFF);
    printk(KERN_INFO "Bytes 00-03: %x %x %x %x\n", rule->eth.src[0], rule->eth.src[1], rule->eth.src[2], rule->eth.src[3]);
    printk(KERN_INFO "Bytes 04-07: %x %x %x %x\n", rule->eth.src[4], rule->eth.src[5], rule->eth.dest[0], rule->eth.dest[1]);
    printk(KERN_INFO "Bytes 08-11: %x %x %x %x\n", rule->eth.dest[2], rule->eth.dest[3], rule->eth.dest[4], rule->eth.dest[5]);
}
//#endif

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
    const char* temp_rule_str = rule_str;
    int temp_rule_len = rule_size;

    struct rule* new_rule = (struct rule*)kmalloc(sizeof(struct rule), GFP_KERNEL);
    if (new_rule == NULL) {
        printk(KERN_INFO "Failed to allocate memory for rule.");
        goto error;
    }
    
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

    if (strncasecmp(temp_rule_str, str_SRC, lstr_SRC) == 0) {
        //
        // Rule value should be matched with the source address
        //
        printk(KERN_INFO "Matched Src.");
        new_rule->fld = fld_SRC; temp_rule_str += lstr_SRC; temp_rule_len -= lstr_SRC;
    }
    else if (strncasecmp(temp_rule_str, str_DEST, lstr_DEST) == 0) {
        //
        // Rule value should be matched with the destination address
        //
        printk(KERN_INFO "Matched Dest.");
        new_rule->fld = fld_DEST; temp_rule_str += lstr_DEST; temp_rule_len -= lstr_DEST;
    }
    else {
        goto error;
    }

    if (temp_rule_len > lstr_MAC && strncasecmp(temp_rule_str, str_MAC, lstr_MAC) == 0) {
        //
        // This rule applies to the Ethernet address, what follows should be a 
        // valid MAC address of the form AA:BB:CC:DD:EE:FF in hexadecimal notation
        //
        printk(KERN_INFO "Matched Mac.");
        new_rule->type = type_MAC; temp_rule_str += lstr_MAC; temp_rule_len -= lstr_MAC;
        if (get_mac_address(temp_rule_str, temp_rule_len, new_rule) != 0) {
            printk(KERN_INFO "Failed mac address extraction.");
            goto error; 
        }
    }
    else if (temp_rule_len > lstr_IP && strncasecmp(temp_rule_str, str_IP, lstr_IP) == 0) {
        //
        // This rule applies to the IP address, what follows should be a 
        // valid IPv4 address of the form AAA:BBB:CCC:DDD in decimal notation
        // TODO: Currently all 3 digits need to be specified, should remove this requirement
        //
        printk(KERN_INFO "Matched Ip.");
        new_rule->type = type_IP; temp_rule_str += lstr_IP; temp_rule_len -= lstr_IP;
        if (get_ip_address(temp_rule_str, temp_rule_len, new_rule) != 0) {
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
        new_rule->type = type_TCP; temp_rule_str += lstr_TCP; temp_rule_len -= lstr_TCP;
        if (get_port(temp_rule_str, temp_rule_len, new_rule) != 0) {
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
        new_rule->type = type_UDP; temp_rule_str += lstr_UDP; temp_rule_len -= lstr_UDP;
        if (get_port(temp_rule_str, temp_rule_len, new_rule) != 0) {
            printk(KERN_INFO "Failed port extraction.");
            goto error;
        }
    }
    else {
        printk(KERN_INFO "Match failed.");
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
    nf_outgoing_hook.priority = NF_IP_PRI_FIRST;
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