#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <linux/in.h>
#include "lkm.h"

struct rule* rules_in = NULL;
struct rule* rules_out = NULL;

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
        rule->net.src = port;
    }
    else {
        rule->net.dest = port;
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
        struct rule* new_rule = (struct rule*)malloc(sizeof(struct rule));
        memcpy(new_rule, rule, sizeof(struct rule));
        add_rule_to_list(other_list, new_rule);
    }
}


int create_rule(
    const char* rule_str,
    const int rule_size,
    struct rule* new_rule) 
{
    const char* temp_rule_str = rule_str;
    int temp_rule_len = rule_size, nbytes, type;
    const char comma = ',', colon = ':';
    
    if (new_rule == NULL) {
        goto error;
    }
    //
    // parse the action DROP/ALLOW
    //
    if (temp_rule_len > lstr_DROP && strncasecmp(temp_rule_str, str_DROP, lstr_DROP) == 0) {
        new_rule->action = act_DROP; temp_rule_str += lstr_DROP; temp_rule_len -= lstr_DROP;
    }
    else if (temp_rule_len > lstr_ALLOW && strncasecmp(temp_rule_str, str_ALLOW, lstr_ALLOW) == 0) {
        new_rule->action = act_ALLOW; temp_rule_str += lstr_ALLOW; temp_rule_len -= lstr_ALLOW;
    }
    else {
        goto error;
    }
    //
    // parse the direction IN/OUT
    //
    if (temp_rule_len > lstr_IN && strncasecmp(temp_rule_str, str_IN, lstr_IN) == 0) {
        new_rule->dir = dir_IN; temp_rule_str += lstr_IN; temp_rule_len -= lstr_IN;
    }
    else if (temp_rule_len > lstr_OUT && strncasecmp(temp_rule_str, str_OUT, lstr_OUT) == 0) {
        new_rule->dir = dir_OUT; temp_rule_str += lstr_OUT; temp_rule_len -= lstr_OUT;
    }
    else if (temp_rule_len > lstr_INOUT && strncasecmp(temp_rule_str, str_INOUT, lstr_INOUT) == 0) {
        new_rule->dir = dir_INOUT; temp_rule_str += lstr_INOUT; temp_rule_len -= lstr_OUT;
    }
    else {
        goto error;
    }

add_to_rule:    
    //
    // parse the field SRC/DEST
    //
    if (strncasecmp(temp_rule_str, str_SRC, lstr_SRC) == 0) {
        type = fld_SRC; temp_rule_str += lstr_SRC; temp_rule_len -= lstr_SRC;
    }
    else if (strncasecmp(temp_rule_str, str_DEST, lstr_DEST) == 0) {
        type = fld_DEST; temp_rule_str += lstr_DEST; temp_rule_len -= lstr_DEST;
    }
    else {
        goto error;
    }

    //
    // parse the layer MAC/IP/TCP
    //
    if (temp_rule_len > lstr_MAC && strncasecmp(temp_rule_str, str_MAC, lstr_MAC) == 0 
        && (new_rule->eth.type & type) == 0) {
        
        new_rule->eth.type |= type; temp_rule_str += lstr_MAC; temp_rule_len -= lstr_MAC;
        if ((nbytes = get_mac_address(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            goto error; 
        }
    }
    else if (temp_rule_len > lstr_IP && strncasecmp(temp_rule_str, str_IP, lstr_IP) == 0 
        && (new_rule->ip.type & type) == 0) {
        
        new_rule->ip.type |= type; temp_rule_str += lstr_IP; temp_rule_len -= lstr_IP;
        if ((nbytes = get_ip_address(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            goto error;
        }
    }
    else if (temp_rule_len > lstr_TCP && strncasecmp(temp_rule_str, str_TCP, lstr_TCP) == 0) {
        //
        // The rule should not overwrite a previously set rule
        //
        if ((type == fld_SRC && new_rule->net.src_protocol != 0) ||
            (type == fld_DEST && new_rule->net.dest_protocol != 0)) {
            goto error;
        }
        //
        // The rule should not mention TCP port for one field and UDP port for the other
        //
        if (type == fld_SRC) {
            if (new_rule->net.dest_protocol == 0 || new_rule->net.dest_protocol == IPPROTO_TCP) 
                new_rule->net.src_protocol = IPPROTO_TCP;
            else
                goto error;    
        }
        else {
            if (new_rule->net.src_protocol == 0 || new_rule->net.src_protocol == IPPROTO_TCP)
                new_rule->net.dest_protocol = IPPROTO_TCP;
            else 
                goto error;
        } 
            
        temp_rule_str += lstr_TCP; temp_rule_len -= lstr_TCP;
        if ((nbytes = get_port(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            goto error;
        }
    }
    else if (temp_rule_len > lstr_UDP && strncasecmp(temp_rule_str, str_UDP, lstr_UDP) == 0) {
        //
        // The rule should not overwrite a previously set rule
        //
        if ((type == fld_SRC && new_rule->net.src_protocol != 0) ||
            (type == fld_DEST && new_rule->net.dest_protocol != 0)) {
            goto error;
        }

        //
        // The rule should not mention TCP port for one field and UDP port for the other
        //
        if (type == fld_SRC) {
            if (new_rule->net.dest_protocol == 0 || new_rule->net.dest_protocol == IPPROTO_UDP) 
                new_rule->net.src_protocol = IPPROTO_UDP;
            else
                goto error;    
        }
        else {
            if (new_rule->net.src_protocol == 0 || new_rule->net.src_protocol == IPPROTO_UDP)
                new_rule->net.dest_protocol = IPPROTO_UDP;
            else 
                goto error;
        } 
        
        temp_rule_str += lstr_UDP; temp_rule_len -= lstr_UDP;
        if ((nbytes = get_port(type, temp_rule_str, temp_rule_len, new_rule)) == -1) {
            goto error;
        }
    }
    else {
        goto error;
    }

    temp_rule_len -= nbytes; 
    temp_rule_str += nbytes;
    type = 0;

    if (temp_rule_len != 0) {
        if (temp_rule_str[0] == comma) {
            temp_rule_str++;
            temp_rule_len--;
            goto add_to_rule;
        }
        else {
            goto error;
        }
    }

    add_rule_to_lists(new_rule);
    return 0;
error:
    return -1;
}

void print_rule(struct rule* rule) 
{
    printf("Action: %x\n", rule->action & 0xFF);
    printf("Direction: %x\n", rule->dir & 0xFF);
    printf("Eth flag: %d\n", rule->eth.type);
    printf("Eth src: %x %x %x %x %x %x\n", rule->eth.src[0], rule->eth.src[1], rule->eth.src[2], rule->eth.src[3], rule->eth.src[4], rule->eth.src[5]);
    printf("Eth dest: %x %x %x %x %x %x\n", rule->eth.dest[0], rule->eth.dest[1], rule->eth.dest[2], rule->eth.dest[3], rule->eth.dest[4], rule->eth.dest[5]);
    printf("IP flag: %d\n", rule->ip.type);
    printf("IP src: %x %x %x %x\n", rule->ip.src[0], rule->ip.src[1], rule->ip.src[2], rule->ip.src[3]);
    printf("IP dest: %x %x %x %x\n", rule->ip.dest[0], rule->ip.dest[1], rule->ip.dest[2], rule->ip.dest[3]);
    printf("Net src proto: %d\n", rule->net.src_protocol);
    printf("Net dest proto: %d\n", rule->net.dest_protocol);
    printf("Net src: %d \n", rule->net.src);
    printf("Net dest: %d\n\n", rule->net.dest);
}

int parse_filter_rules(const char* filter) 
{
    const char *current_rule;
    int current_size = 0, size, index = 0;
    const char delimiter = '|';
    struct rule* rule;
    //
    // Trim starting spaces
    //
    while (filter[index] == ' ') {
        index++;
    }

    size = strlen(filter);
    current_rule = &filter[index];

    while (index <= size) {
        
        if (filter[index] == delimiter || filter[index] == '\0') {
            //
            // Encountered a delimiter or end of string
            // All characters from current_rule to here are part of a rule
            //
            rule = (struct rule*)malloc(sizeof(struct rule));
            memset(rule, 0, sizeof(struct rule));
            current_size = &filter[index] - current_rule;
            if (0 != create_rule(current_rule, current_size, rule)) {
                print_rule(rule);
                return -1;
            }

            print_rule(rule);

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
        free(first);
        first = temp;
    }
}

void main(int argc, char** argv) 
{
    int ret;
    if (argc != 2) {
        exit(0);
    }

    ret = parse_filter_rules(argv[1]);
    printf("%d\n", ret);
    cleanup_rule_list(rules_in);
    cleanup_rule_list(rules_out);
}