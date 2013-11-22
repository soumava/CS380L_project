#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include "lkm.h"

MODULE_LICENSE("GPL");

struct nf_hook_ops nf_incoming_hook;
struct nf_hook_ops nf_outgoing_hook;
char *filter;
struct _rule* rules_in;
struct _rule* rules_out;

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
    printk(KERN_INFO "%d\n", in->type);
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

int get_mac_address(
    const char* rule_str, 
    const int rule_len,
    struct _rule* rule) 
{
    int byte_index = 0, index = 0, num_dec_1, num_dec_2;
    const int num_bytes = 6;
    const char delimiter = ':';
    unsigned char mac_address[num_bytes];
    //
    // Check that the size of the string left is larger than the MAC address
    // in AA:BB:CC:DD:EE:FF notation
    //
    if (rule_len < (num_bytes * 3 - 1)) {
        goto error;
    }
    
    while(byte_index < num_bytes) {
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
        memcpy(rule->eth.src, mac_address, num_bytes);
    }
    else {
        memcpy(rule->eth.dst, mac_address, num_bytes);
    }

    return 0;

error:
    return -1;    
}

int get_ip_address(
    const char* rule_str,
    const int rule_len,
    struct _rule* rule) 
{
    int byte_index = 0, index = 0, num_dec_1, num_dec_2, num_dec_3;
    const int num_bytes = 4;
    const char delimiter = '.';
    unsigned char ip_address[4];
    //
    // Check if the total length of the string is larger than an IP
    // address 
    //
    if (rule_len < (num_bytes * 4 - 1)) {
        goto error;
    }

    while (byte_index < num_bytes) {
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
        memcpy(rule->ip.src, ip_address, num_bytes);
    }
    else {
        memcpy(rule->ip.dst, ip_address, num_bytes);
    }

    return 0;

error:
    return -1;
}


int create_rule(
    const char* rule_str,
    const int rule_size) 
{
    char* temp_rule_str = rule_str;
    int temp_rule_len = rule_size;
    const char comma = ',', colon = ':';
    struct _rule* new_rule = (struct _rule*)malloc(sizeof(struct _rule));
    if (new_rule == NULL) {
        goto error;
    }
    //
    // parse the action DROP/ALLOW
    //
    if (strncmpi(temp_rule_str, str_DROP, lstr_DROP) == 0) {
        new_rule->action = act_DROP; temp_rule_str += lstr_DROP; temp_rule_len -= lstr_DROP;
    }
    else if (strncmpi(temp_rule_str, str_ALLOW, lstr_ALLOW) == 0) {
        new_rule->action = act_ALLOW; temp_rule_str += lstr_ALLOW; temp_rule_len -= lstr_ALLOW;
    }
    else {
        goto error;
    }
    //
    // Check for the delimiter = ','
    //
    if (temp_rule_len <= 0 || temp_rule_str[0] != comma) {
        goto error;
    }
    else {
        temp_rule_str++; temp_rule_len--;
    }
    //
    // parse the layer MAC/IP/TCP
    //
    if (temp_rule_len > lstr_MAC && strncmpi(temp_rule_str, str_MAC, lstr_MAC) == 0) {
        new_rule->type = type_MAC; temp_rule_str += lstr_MAC; temp_rule_len -= lstr_MAC;
        if (temp_rule_str[0] != colon || get_mac_address(++temp_rule_str, --temp_rule_len, new_rule) != 0)
            goto error; 
    }
    else if (temp_rule_len > lstr_IP && strncmpi(temp_rule_str, str_IP, lstr_IP) == 0) {
        new_rule->type = type_IP; temp_rule_str += lstr_IP; temp_rule_len -= lstr_IP;
        if (temp_rule_str[0] != colon || get_ip_address(++temp_rule_str, --temp_rule_len, new_rule) != 0) {
            goto error;
        }
    }
    else if (temp_rule_len > lstr_TCP && strncmpi(temp_rule_str, str_TCP, lstr_TCP) == 0) {
        new_rule->type = type_TCP; temp_rule_str += lstr_TCP; temp_rule_len -= lstr_TCP;
        if (temp_rule_str[0] != colon || get_port(++temp_rule_str, --temp_rule_len, new_rule) != 0) {
            goto error;
        }
    }
    else if (temp_rule_len > lstr_UDP && strncmpi(temp_rule_str, str_UDP, lstr_UDP) == 0) {
        new_rule->type = type_UDP; temp_rule_str += lstr_UDP; temp_rule_len -= lstr_UDP;
        if (temp_rule_str[0] != colon || get_port(++temp_rule_str, --temp_rule_len, new_rule) != 0) {
            goto error;
        }
    }
    else {
        goto error;
    }

    return 0;
error:
    return -1;
}

int parse_filter_rules() 
{
    char *current_rule;
    int current_size = 0, size, index = 0;
    const char delimiter = '|';

    size = strlen(filter);
    current_rule = filter;

    while (index <= size) {
        if (filter[index] == delimiter || filter[index] == '\0') {
            current_size = &filter[index] - current_rule;
            if (0 != create_rule(current_rule, current_size)) {
                return -1;
            }

            if (index != size) {
                current_rule = &filter[index + 1];
            }
        }
        index++;
    }
    return 0;
}


int init_module(void) 
{
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
    //
    // Read the rules specified in the rules file
    //
    if (0 != parse_filter_rules()) {
       return -1;
    }

    printk(KERN_INFO "Simple firewall loaded.");
    printk(KERN_INFO "%s\n", filter);
    return 0;
}

void cleanup_module(void) 
{
    // UN-register the hook with netfilter
    nf_unregister_hook(&nf_incoming_hook);
    nf_unregister_hook(&nf_outgoing_hook);

    printk(KERN_INFO "Simple firewall unloaded\n");
}