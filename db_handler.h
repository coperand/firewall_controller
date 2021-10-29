#pragma once

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <string>
#include <map>
#include <stdexcept>

struct dateAndTime
{
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint8_t second_part;
};

struct event
{
    uint8_t level;
    std::string message;
    dateAndTime time;
};

class DbHandler
{
public:
    DbHandler(const char* path);
    ~DbHandler();
    
    int write_to_journal(std::map<unsigned int, struct event>& events);
    std::map<unsigned int, struct event> read_from_journal();
private:
    sqlite3 *db = NULL;
    
    static int read_journal_callback(void *data, int argc, char **argv, char **colName);
};