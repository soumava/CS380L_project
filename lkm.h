#ifndef _LKM_H_
#define _LKM_H_

#define fld_SRC             0x1
#define fld_DEST            0x2

#define shift_MAC           0x0
#define shift_IP            0x1
#define shift_TCP           0x2
#define shift_UDP           0x3

#define act_DROP       0x1
#define act_ALLOW      0x2

#define dir_IN         0x1
#define dir_OUT        0x2
#define dir_INOUT      0x3

#define str_DROP       "drop,"
#define str_ALLOW      "allow,"
#define str_MAC        "mac:"
#define str_IP         "ip:"
#define str_TCP        "tcp:"
#define str_UDP        "udp:"
#define str_SRC        "src,"
#define str_DEST       "dest,"
#define str_IN         "in,"
#define str_OUT        "out,"
#define str_INOUT      "inout,"

//
// Size of a literal includes the terminating NULL
//
#define lstr_DROP      (sizeof(str_DROP) - 1)
#define lstr_ALLOW     (sizeof(str_ALLOW) - 1)
#define lstr_MAC       (sizeof(str_MAC) - 1)
#define lstr_IP        (sizeof(str_IP) - 1)
#define lstr_TCP       (sizeof(str_TCP) - 1)
#define lstr_UDP       (sizeof(str_UDP) - 1)
#define lstr_SRC       (sizeof(str_SRC) - 1)
#define lstr_DEST      (sizeof(str_DEST) - 1)
#define lstr_IN        (sizeof(str_IN) - 1)
#define lstr_OUT       (sizeof(str_OUT) - 1)
#define lstr_INOUT     (sizeof(str_INOUT) - 1)
 
#define eth_num_bytes  ETH_ALEN
#define ip_num_bytes   4

typedef unsigned char BYTE;

struct rule {
    BYTE action;
    BYTE dir;
 
	struct {
        BYTE type;
		BYTE src[eth_num_bytes];
		BYTE dest[eth_num_bytes];
	} eth;

	struct {
        BYTE type;
        BYTE src[ip_num_bytes];
		BYTE dest[ip_num_bytes];
	} ip;

	struct {
        BYTE src_protocol;
        BYTE dest_protocol;
    	int src;
		int dest;
	} trans;

    struct rule* next;
};

struct packet {
    BYTE ip_next_proto;
    BYTE src_mac_address[eth_num_bytes];
    BYTE dest_mac_address[eth_num_bytes];
    
    uint32_t src_ip_address;
    uint32_t dest_ip_address;

    union {
        struct {
            uint16_t src_port;
            uint16_t dest_port;
        } tcp;

        struct {
            uint16_t src_port;
            uint16_t dest_port;
        } udp;
    };
};

#endif