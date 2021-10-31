#pragma once

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdexcept>
#include <string>
#include <map>

#include "structs.h"

class Logger
{
public:
    Logger(std::map<unsigned int, struct event>* events, std::map<unsigned int, struct event>::iterator* events_it, uint8_t* audit_lvl, unsigned int threshold);
    ~Logger();
    Logger(const Logger&) = delete;
    void operator=(const Logger&) = delete;
    
    void print(uint8_t level, std::string message);
private:
    std::map<unsigned int, struct event>* events = NULL;
    std::map<unsigned int, struct event>::iterator* events_it = NULL;
    uint8_t* audit_lvl = NULL;
    unsigned int threshold = 200;
};