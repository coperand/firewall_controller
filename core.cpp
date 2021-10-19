#include "core.h"

using namespace std;

IpTc* Core::iptc_pointer = NULL;
map<unsigned int, struct rule> Core::rules = {};
map<unsigned int, struct rule>::iterator Core::rules_it = Core::rules.begin();
uint8_t Core::policy = 1;

Core::Core(uint8_t refresh_timeout, oid* table_oid, unsigned int oid_size) : iptc{}, snmp{table_oid, oid_size, "graduationProjectTable", &rules, &rules_it, add_rule, del_rule, &policy}, iptc_timer{}, refresh_timeout{refresh_timeout}
{
    iptc_pointer = &iptc;
    rules_it = rules.begin();
    
    //TODO: Не забыть про политику
}

Core::~Core()
{
    
}

int Core::add_rule(unsigned int index)
{
    return 0;
}

int Core::del_rule(unsigned int index)
{
    return 0;
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
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size; i += 2)
                rules[i] = from_kernel.first[i / 2];
            
            from_kernel = iptc.print_rules("filter", "FORWARD");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size; i += 2)
                rules[250 + i] = from_kernel.first[i / 2];
            policy = from_kernel.second;
            
            from_kernel = iptc.print_rules("nat", "POSTROUTING");
            for(unsigned int i = 2, size = 2 * from_kernel.first.size(); i <= size; i += 2)
                rules[750 + i] = from_kernel.first[i / 2];
            
            rules_it = rules.end();
            iptc_timer = chrono::steady_clock::now();
        }
        
        while(agent_check_and_process(0));
        usleep(500);
    }
}