#include <stdio.h>
#include <stdint.h>
#include <chrono>

#include "iptc.h"
#include "snmp_handler.h"

class Core
{
public:
    Core(uint8_t refresh_timeout, oid* table_oid, unsigned int oid_size);
    ~Core();
    
    static int add_rule(unsigned int index);
    static int del_rule(unsigned int index);
    
    void cycle();
private:
    IpTc iptc;
    static IpTc* iptc_pointer;
    
    SnmpHandler snmp;
    
    std::chrono::time_point<std::chrono::steady_clock> iptc_timer;
    uint8_t refresh_timeout;
    
    static std::map<unsigned int, struct rule> rules;
    static std::map<unsigned int, struct rule>::iterator rules_it;
    static uint8_t policy;
};