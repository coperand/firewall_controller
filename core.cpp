#include "core.h"

using namespace std;

IpTc* Core::iptc_pointer = NULL;
map<unsigned int, struct rule> Core::rules = {{1, {inet_addr("192.168.2.12"), inet_addr("131.121.2.3"), inet_addr("255.255.255.252"), inet_addr("255.255.255.0"), "eth0", "eth1", protocol::tcp, {1, 15}, {134, 32412}, 1, "accept", "test", 0x01}},
                                                {2, {inet_addr("192.163.21.1"), inet_addr("114.21.21.2"), inet_addr("255.255.0.0"), inet_addr("255.255.252.0"), "ens5f5", "exr131", protocol::udp, {3, 21}, {321, 13142}, 2, "DROP", "qwer", 0x80}}};
map<unsigned int, struct rule>::iterator Core::rules_it = Core::rules.begin();

Core::Core(uint8_t refresh_timeout, oid* table_oid, unsigned int oid_size) : iptc{}, snmp{table_oid, oid_size, "graduationProjectTable", &rules, &rules_it, add_rule, del_rule}, iptc_timer{}, refresh_timeout{refresh_timeout}
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
            //TODO: Опрос таблиц
            
            iptc_timer = chrono::steady_clock::now();
        }
        
        while(agent_check_and_process(0));
        usleep(500);
    }
}