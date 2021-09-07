#pragma once

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <vector>
#include <map>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

struct range
{
    uint16_t min;
    uint16_t max;
};

enum class protocol: uint8_t
{
    none = 0,
    icmp = 1,
    tcp = 6,
    udp = 17
};

struct rule
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t src_mask;
    uint32_t dst_mask;
    std::string in_if;
    std::string out_if;
    protocol proto;
    struct range sport;
    struct range dport;
    uint8_t state;
    uint8_t action;
    std::string action_params;
    uint16_t inv_flags;
};

/* function declarations */
void init_firewallFilterForwardTable(void);
void initialize_table_firewallFilterForwardTable(void);
Netsnmp_Node_Handler firewallFilterForwardTable_handler;


/* column number definitions for table firewallFilterForwardTable */
       #define COLUMN_FCFFINDEX			1
       #define COLUMN_FCFFSRCADDR		2
       #define COLUMN_FCFFSRCMASK		3
       #define COLUMN_FCFFDSTADDR		4
       #define COLUMN_FCFFDSTMASK		5
       #define COLUMN_FCFFINIFACE		6
       #define COLUMN_FCFFOUTIFACE		7
       #define COLUMN_FCFFPROTO			8
       #define COLUMN_FCFFSRCPORTMIN		9
       #define COLUMN_FCFFSRCPORTMAX		10
       #define COLUMN_FCFFDSTPORTMIN		11
       #define COLUMN_FCFFDSTPORTMAX		12
       #define COLUMN_FCFFSTATE			13
       #define COLUMN_FCFFACTION		14
       #define COLUMN_FCFFACTIONPARAMS		15
       #define COLUMN_FCFFINVERSEFLAGS		16
       #define COLUMN_FCFFCOMMAND		17

/*possible values*/
const std::vector<int> FCFFPROTO_values = {0, 1, 6, 17};
const std::vector<int> FCFFSTATE_values = {0, 1, 2, 3, 4};
const std::vector<int> FCFFACTION_values = {1, 2, 3, 4, 5, 6};
const std::vector<int> FCFFCOMMAND_values = {0, 1};
