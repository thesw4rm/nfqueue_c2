//
// Created by ytpillai on 4/13/19.
//

#ifndef USERLAND_NFQUEUE_C_CLIENT_TCP_PACKET_STRUCT_H
#define USERLAND_NFQUEUE_C_CLIENT_TCP_PACKET_STRUCT_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
// Structs to read a manipulate a raw TCP packet
typedef uint32_t addr_t;
typedef uint16_t port_t;

#define METADATA_SIZE 12
#pragma pack(push, 1)
typedef struct {
    uint32_t padding; // All zeroes
    uint8_t  exp_opt; // Should be experimental option assigned by IANA
    uint8_t  exp_opt_len;
	uint16_t exp_opt_id;
//uint16_t exp_opt_exid; // ExID for experimental option
    uint32_t ip_addr;
} pkt_meta;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    struct iphdr ipv4_header;
    struct tcphdr tcp_header;
} full_tcp_pkt_t;
#pragma pack(pop)


#endif //USERLAND_NFQUEUE_C_CLIENT_TCP_PACKET_STRUCT_H
