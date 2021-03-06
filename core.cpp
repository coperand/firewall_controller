#include "core.h"

using namespace std;

Core* Core::instance_pointer = NULL;
map<unsigned int, struct rule> Core::rules = {};
map<unsigned int, struct rule>::iterator Core::rules_it = Core::rules.begin();
uint8_t Core::policy = 1;
map<unsigned int, struct event> Core::events = {};
map<unsigned int, struct event>::iterator Core::events_it = Core::events.begin();
uint8_t Core::audit_lvl = 0;
Logger* Core::log_ptr = NULL;

Core::Core(uint8_t refresh_timeout, const char* db_path, uint8_t db_timeout, unsigned int audit_threshold) : log{&events, &events_it, &audit_lvl, audit_threshold}, iptc{&log},
                                                                                                             snmp{&rules, &rules_it, add_rule, del_rule, change_policy, &policy, &events, &events_it, &audit_lvl},
                                                                                                             db{db_path}, iptc_timer{}, refresh_timeout{refresh_timeout}, db_timer{}, db_timeout{db_timeout}
{
    instance_pointer = this;
    rules_it = rules.begin();
    events = db.read_from_journal();
    log_ptr = &log;
    
    struct rule conditions = {};
    iptc.add_chain("nat", "fcDNAT");
    conditions.action = string("fcDNAT");
    iptc.flush_chain("nat", "PREROUTING");
    iptc.add_rule(conditions, "nat", "PREROUTING", 0);
    
    iptc.add_chain("mangle", "fcFILTERING");
    conditions.action = string("fcFILTERING");
    iptc.flush_chain("mangle", "PREROUTING");
    iptc.add_rule(conditions, "mangle", "PREROUTING", 0);
    
    iptc.add_chain("nat", "fcSNAT");
    conditions.action = string("fcSNAT");
    iptc.flush_chain("nat", "POSTROUTING");
    iptc.add_rule(conditions, "nat", "POSTROUTING", 0);
}

Core::~Core()
{
    
}

string Core::serialize_rule_to_str(unsigned int index)
{
    string result;
    
    struct in_addr ip = {};
    if(rules[index].src_ip != 0)
    {
        ip.s_addr = rules[index].src_ip;
        result += string("|Src ip|: ") + string(inet_ntoa(ip)) + string(" ");
    }
    if(rules[index].src_mask != 0)
    {
        ip.s_addr = rules[index].src_mask;
        result += string("|Src mask|: ") + string(inet_ntoa(ip)) + string(" ");
    }
    
    if(rules[index].dst_ip != 0)
    {
        ip.s_addr = rules[index].dst_ip;
        result += string("|Dst ip|: ") + string(inet_ntoa(ip)) + string(" ");
    }
    if(rules[index].dst_mask != 0)
    {
        ip.s_addr = rules[index].dst_mask;
        result += string("|Dst mask|: ") + string(inet_ntoa(ip)) + string(" ");
    }
    
    if(rules[index].in_if.size() != 0)
        result += string("|In if|: ") + rules[index].in_if + string(" ");
    if(rules[index].in_if.size() != 0)
        result += string("|Out if|: ") + rules[index].out_if + string(" ");
    
    switch(rules[index].proto)
    {
        case protocol::icmp:
            result += string("|Proto|: icmp") + string(" ");
            break;
        case protocol::tcp:
            result += string("|Proto|: tcp") + string(" ");
            break;
        case protocol::udp:
            result += string("|Proto|: udp") + string(" ");
            break;
        default:
            break;
    }

    if(rules[index].sport.min != 0 || rules[index].sport.max != 0)
        result += string("|Src port|: ") + to_string(rules[index].sport.min) + string(" - ") + to_string(rules[index].sport.max) + string(" ");
    if(rules[index].dport.min != 0 || rules[index].dport.max != 0)
        result += string("|Dst port|: ") + to_string(rules[index].dport.min) + string(" - ") + to_string(rules[index].dport.max) + string(" ");

    if(rules[index].state != 0)
    {
        result += string("|State(s)|: ");
        if((rules[index].state & 0x01) != 0)
            result += string("Invalid") + string(" ");
        if(((rules[index].state >> 1) & 0x01) != 0)
            result += string("Established") + string(" ");
        if(((rules[index].state >> 2) & 0x01) != 0)
            result += string("Related") + string(" ");
        if(((rules[index].state >> 3) & 0x01) != 0)
            result += string("New") + string(" ");
    }

    result += string("|Action|: ") + rules[index].action;
    return result;
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
    
    log_ptr->print(audit::info, string("Adding rule: ") + serialize_rule_to_str(index));
    
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
    
    log_ptr->print(audit::info, string("Deleting rule: ") + serialize_rule_to_str(index));
    
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    return result;
}

int Core::change_policy(uint8_t policy)
{
    instance_pointer->iptc_timer -= chrono::seconds(instance_pointer->refresh_timeout + 1);
    
    log_ptr->print(audit::info, string("Changing policy to ") + to_string(policy));
    
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
        
        if(chrono::duration_cast<chrono::seconds>(chrono::steady_clock::now() - db_timer).count() > db_timeout)
        {
            db.write_to_journal(events);
            db_timer = chrono::steady_clock::now();
        }
        
        while(agent_check_and_process(0));
        usleep(500);
    }
}
