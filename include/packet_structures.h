#pragma once

#include <winsock2.h>

#pragma pack(push,1)

struct EthernetHeader
{
    unsigned char dest[6];
    unsigned char src[6];
    unsigned short type;
};

struct IPHeader
{
    unsigned char ver_ihl;
    unsigned char tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int src_ip;
    unsigned int dest_ip;
};

struct TCPHeader
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

struct UDPHeader
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
};

#pragma pack(pop)