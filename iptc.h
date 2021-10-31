#pragma once

#include <stdio.h>
#include <string.h>
#include <string>
#include <arpa/inet.h>
#include <libiptc/libiptc.h>
#include <linux/netfilter/xt_conntrack.h>
#include <stdexcept>
#include <map>
#include <tuple>

#include "structs.h"
#include "logger.h"

#define NFC_IP_SRC_PT	0x0200
#define NFC_IP_DST_PT	0x0400
#define NFC_UNKNOWN 	0x4000

#define IP_NAT_RANGE_MAP_IPS 		1
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
    IpTc(Logger *log);
    ~IpTc();
    IpTc(const IpTc&) = delete;
    void operator=(const IpTc&) = delete;
    
    int add_chain(std::string table, std::string chain);
    int flush_chain(std::string table, std::string chain);
    int add_rule(struct rule conditions, std::string table, std::string chain, unsigned int index);
    int del_rule_by_index(std::string table, std::string chain, unsigned int index);
    int change_policy(std::string table, std::string chain, uint8_t policy);
    std::pair<std::map<unsigned int, struct rule>, uint8_t> print_rules(std::string table, std::string chain);
private:
    Logger* log = NULL;
    
    struct ipt_entry_match* get_osi4_match(protocol proto, struct range sport, struct range dport, struct ipt_entry* chain_entry, uint16_t inv_flags);
    struct ipt_entry_target* get_nat_target(std::string action, std::string action_params);
    struct ip_nat_range parse_range(std::string input);
    std::string parse_range_reverse(struct ip_nat_range& range);
};
