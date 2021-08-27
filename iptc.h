#pragma once

#include <stdio.h>
#include <string.h>
#include <string>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>

#include "structs.h"

#define NFC_IP_SRC_PT	0x0200
#define NFC_IP_DST_PT	0x0400
#define NFC_UNKNOWN 	0x4000

#define IP_NAT_RANGE_MAP_IPS 			1
#define IP_NAT_RANGE_PROTO_SPECIFIED 	2

union ip_conntrack_manip_proto
{
	u_int16_t all;

	struct
	{
		u_int16_t port;
	} tcp;
	struct
	{
		u_int16_t port;
	} udp;
	struct
	{
		u_int16_t id;
	} icmp;
};

struct ip_nat_range
{
	unsigned int flags;
	u_int32_t min_ip, max_ip;
	union ip_conntrack_manip_proto min, max;
};

struct ip_nat_multi_range
{
	unsigned int rangesize;
	struct ip_nat_range range[1];
};

struct ipt_natinfo {
    struct ipt_entry_target t;
    struct ip_nat_multi_range mr;
};

class IpTc
{
public:
	IpTc();
	~IpTc();

	int add_rule(struct rule conditions, std::string table, std::string chain, unsigned int index);
	int del_rule(struct rule entry);
private:
	struct ipt_entry_match* get_osi4_match(protocol proto, struct range sport, struct range dport, struct ipt_entry* chain_entry);
	struct ipt_entry_target* get_nat_target(std::string action, std::string action_params);
	struct ip_nat_range parse_range(std::string input);
};