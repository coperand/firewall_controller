#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <chrono>

#include "iptc.h"
#include "snmp_handler.h"
#include "db_handler.h"
#include "logger.h"

class Core
{
public:
    Core(uint8_t refresh_timeout, const char* db_path, uint8_t db_timeout, unsigned int audit_threshold);
    ~Core();
    
    static int add_rule(unsigned int index);
    static int del_rule(unsigned int index);
    static int change_policy(uint8_t policy);
    
    void cycle();
private:
    Logger log;
    IpTc iptc;
    SnmpHandler snmp;
    DbHandler db;
    
    std::chrono::time_point<std::chrono::steady_clock> iptc_timer;
    uint8_t refresh_timeout;
    std::chrono::time_point<std::chrono::steady_clock> db_timer;
    uint8_t db_timeout;
    
    static Core* instance_pointer;
    static std::map<unsigned int, struct rule> rules;
    static std::map<unsigned int, struct rule>::iterator rules_it;
    static uint8_t policy;
    static std::map<unsigned int, struct event> events;
    static std::map<unsigned int, struct event>::iterator events_it;
    static uint8_t audit_lvl;
    static Logger* log_ptr;
    
    static std::string serialize_rule_to_str(unsigned int index);
};
