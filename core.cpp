#include "core.h"

using namespace std;

Core* Core::instance_pointer = NULL;
map<unsigned int, struct rule> Core::rules = {};
map<unsigned int, struct rule>::iterator Core::rules_it = Core::rules.begin();
uint8_t Core::policy = 1;

Core::Core(uint8_t refresh_timeout, oid* table_oid, unsigned int oid_size) : iptc{}, snmp{table_oid, oid_size, "graduationProjectTable", &rules, &rules_it, add_rule, del_rule, change_policy, &policy},
                                                                             iptc_timer{}, refresh_timeout{refresh_timeout}
{
    instance_pointer = this;
    rules_it = rules.begin();
    
    struct rule conditions = {};
    iptc.add_chain("nat", "fcDNAT");
    conditions.action = string("fcDNAT");
    iptc.del_rule(conditions, "nat", "PREROUTING");
    iptc.add_rule(conditions, "nat", "PREROUTING", 0);
    
    iptc.add_chain("mangle", "fcFILTERING");
    conditions.action = string("fcFILTERING");
    iptc.del_rule(conditions, "mangle", "PREROUTING");
    iptc.add_rule(conditions, "mangle", "PREROUTING", 0);
    
    iptc.add_chain("nat", "fcSNAT");
    conditions.action = string("fcSNAT");
    iptc.del_rule(conditions, "nat", "POSTROUTING");
    iptc.add_rule(conditions, "nat", "POSTROUTING", 0);
}

Core::~Core()
{
    
}

int Core::add_rule(unsigned int index)
{
    if(index % 2 == 0)
    {
        rules.erase(index);
        rules_it = rules.begin();
        return SNMP_ERR_INCONSISTENTVALUE;
    }
    
    int result = 0;
    if(index < 250)
        result = instance_pointer->iptc.add_rule(rules[index], "nat", "fcDNAT", (index == 1) ? 0x00 : (index - 1) % 2 + 1);
    else if(index > 250 && index < 750)
        result = instance_pointer->iptc.add_rule(rules[index], "mangle", "fcFILTERING", (index == 251) ? 0x00 : (index - 1 - 250) % 2 + 1);
    else if(index > 750)
        result = instance_pointer->iptc.add_rule(rules[index], "nat", "fcSNAT", (index == 751) ? 0x00 : (index - 1 - 750) % 2 + 17);
    else
        return SNMP_ERR_INCONSISTENTVALUE;
    
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    return result;
}

int Core::del_rule(unsigned int index)
{
    if(index % 2 != 0)
    {
        rules.erase(index);
        rules_it = rules.begin();
        return 0;
    }
    
    int result = 0;
    if(index < 250)
        result = instance_pointer->iptc.del_rule_by_index("nat", "fcDNAT", index / 2 - 1);
    else if(index > 250 && index < 750)
        result = instance_pointer->iptc.del_rule_by_index("mangle", "fcFILTERING", (index - 250) / 2 - 1);
    else if(index > 750)
        result = instance_pointer->iptc.del_rule_by_index("nat", "fcSNAT", (index - 750) / 2 - 1);
    else
        return SNMP_ERR_INCONSISTENTVALUE;
    
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    return result;
}

int Core::change_policy(uint8_t policy)
{
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    return instance_pointer->iptc.change_policy("mangle", "PREROUTING", policy);
}

void Core::cycle()
{
    while(1)
    {
        if(chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - iptc_timer).count() > refresh_timeout)
        {
            rules.clear();
            
            auto from_kernel = iptc.print_rules("nat", "fcDNAT");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size && i < 250; i += 2)
                rules[i] = from_kernel.first[i / 2];
            
            from_kernel = iptc.print_rules("mangle", "fcFILTERING");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size && i < 500; i += 2)
                rules[250 + i] = from_kernel.first[i / 2];
            
            from_kernel = iptc.print_rules("nat", "fcSNAT");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size && i < 1000; i += 2)
                rules[750 + i] = from_kernel.first[i / 2];
            
            from_kernel = iptc.print_rules("mangle", "PREROUTING");
            policy = from_kernel.second;
            
            rules_it = rules.end();
            iptc_timer = chrono::steady_clock::now();
        }
        
        while(agent_check_and_process(0));
        usleep(500);
    }
}
