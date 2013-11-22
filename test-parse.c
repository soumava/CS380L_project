#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lkm.h"

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
    struct _rule* rule) 
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


int create_rule(
    const char* rule_str,
    const int rule_size) 
{
    const char* temp_rule_str = rule_str;
    int temp_rule_len = rule_size;
    const char comma = ',', colon = ':';
    struct _rule* new_rule = (struct _rule*)malloc(sizeof(struct _rule));

    if (new_rule == NULL) {
        goto error;
    }
    //
    // parse the action DROP/ALLOW
    //
    if (temp_rule_len > lstr_DROP && strncmp(temp_rule_str, str_DROP, lstr_DROP) == 0) {
        new_rule->action = act_DROP; temp_rule_str += lstr_DROP; temp_rule_len -= lstr_DROP;
    }
    else if (temp_rule_len > lstr_ALLOW && strncmp(temp_rule_str, str_ALLOW, lstr_ALLOW) == 0) {
        new_rule->action = act_ALLOW; temp_rule_str += lstr_ALLOW; temp_rule_len -= lstr_ALLOW;
    }
    else {
        goto error;
    }
    //
    // parse the direction IN/OUT
    //
    if (temp_rule_len > lstr_IN && strncmp(temp_rule_str, str_IN, lstr_IN) == 0) {
        new_rule->dir = dir_IN; temp_rule_str += lstr_IN; temp_rule_len -= lstr_IN;
    }
    else if (temp_rule_len > lstr_OUT && strncmp(temp_rule_str, str_OUT, lstr_OUT) == 0) {
        new_rule->dir = dir_OUT; temp_rule_str += lstr_OUT; temp_rule_len -= lstr_OUT;
    }
    else if (temp_rule_len > lstr_INOUT && strncmp(temp_rule_str, str_INOUT, lstr_INOUT) == 0) {
        new_rule->dir = dir_INOUT; temp_rule_str += lstr_INOUT; temp_rule_len -= lstr_OUT;
    }
    else {
        goto error;
    }
    //
    // parse the field SRC/DEST
    //
    if (strncmp(temp_rule_str, str_SRC, lstr_SRC) == 0) {
        new_rule->fld; temp_rule_str += lstr_SRC; temp_rule_len -= lstr_SRC;
    }
    else if (strncmp(temp_rule_str, str_DEST, lstr_DEST) == 0) {
        new_rule->fld = fld_SRC; temp_rule_str += lstr_SRC; temp_rule_len -= lstr_SRC;
    }
    else {
        goto error;
    }
    //
    // parse the layer MAC/IP/TCP
    //
    if (temp_rule_len > lstr_MAC && strncmp(temp_rule_str, str_MAC, lstr_MAC) == 0) {
        new_rule->type = type_MAC; temp_rule_str += lstr_MAC; temp_rule_len -= lstr_MAC;
        if (get_mac_address(temp_rule_str, temp_rule_len, new_rule) != 0)
            goto error; 
    }
    else if (temp_rule_len > lstr_IP && strncmp(temp_rule_str, str_IP, lstr_IP) == 0) {
        new_rule->type = type_IP; temp_rule_str += lstr_IP; temp_rule_len -= lstr_IP;
        if (get_ip_address(temp_rule_str, temp_rule_len, new_rule) != 0) {
            goto error;
        }
    }
    else if (temp_rule_len > lstr_TCP && strncmp(temp_rule_str, str_TCP, lstr_TCP) == 0) {
        new_rule->type = type_TCP; temp_rule_str += lstr_TCP; temp_rule_len -= lstr_TCP;
        if (get_port(temp_rule_str, temp_rule_len, new_rule) != 0) {
            goto error;
        }
    }
    else if (temp_rule_len > lstr_UDP && strncmp(temp_rule_str, str_UDP, lstr_UDP) == 0) {
        new_rule->type = type_UDP; temp_rule_str += lstr_UDP; temp_rule_len -= lstr_UDP;
        if (get_port(temp_rule_str, temp_rule_len, new_rule) != 0) {
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

int parse_filter_rules(const char* filter) 
{
    const char *current_rule;
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

void main(int argc, char** argv) 
{
    int ret;
    if (argc != 2) {
        exit(0);
    }

    ret = parse_filter_rules(argv[1]);
    printf("%d\n", ret);
}