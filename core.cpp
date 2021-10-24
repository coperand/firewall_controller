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
    
    iptc.add_chain("nat", "fcDNAT");
    iptc.add_chain("mangle", "fcFILTERING");
    iptc.add_chain("nat", "fcSNAT");
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
        result = instance_pointer->iptc.add_rule(rules[index], "nat", "PREROUTING", (index == 1) ? 0x00 : (index - 1) % 2 + 1);
    else if(index > 250 && index < 750)
        result = instance_pointer->iptc.add_rule(rules[index], "filter", "FORWARD", (index == 251) ? 0x00 : (index - 1 - 250) % 2 + 1);
    else if(index > 750)
        result = instance_pointer->iptc.add_rule(rules[index], "nat", "POSTROUTRING", (index == 751) ? 0x00 : (index - 1 - 750) % 2 + 17);
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
        result = instance_pointer->iptc.del_rule(rules[index], "nat", "PREROUTING");
    else if(index > 250 && index < 750)
        result = instance_pointer->iptc.del_rule(rules[index], "filter", "FORWARD");
    else if(index > 750)
        result = instance_pointer->iptc.del_rule(rules[index], "nat", "POSTROUTRING");
    else
        return SNMP_ERR_INCONSISTENTVALUE;
    
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    return result;
}

int Core::change_policy(uint8_t policy)
{
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    return instance_pointer->iptc.change_policy("filter", "FORWARD", policy);
}

void Core::cycle()
{
    while(1)
    {
        if(chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - iptc_timer).count() > refresh_timeout)
        {
            rules.clear();
            
            //TODO: Поменять на свои цепочки и добавить их создание
            
            auto from_kernel = iptc.print_rules("nat", "PREROUTING");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size && i < 250; i += 2)
                rules[i] = from_kernel.first[i / 2];
            
            from_kernel = iptc.print_rules("filter", "FORWARD");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size && i < 500; i += 2)
                rules[250 + i] = from_kernel.first[i / 2];
            policy = from_kernel.second;
            
            from_kernel = iptc.print_rules("nat", "POSTROUTING");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size && i < 1000; i += 2)
                rules[750 + i] = from_kernel.first[i / 2];
            
            rules_it = rules.end();
            iptc_timer = chrono::steady_clock::now();
        }
        
        while(agent_check_and_process(0));
        usleep(500);
    }
}
