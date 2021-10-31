#pragma once

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sqlite3.h>
#include <string>
#include <map>
#include <stdexcept>

#include "structs.h"

class DbHandler
{
public:
    DbHandler(const char* path);
    ~DbHandler();
    DbHandler(const DbHandler&) = delete;
    void operator=(const DbHandler&) = delete;
    
    int write_to_journal(std::map<unsigned int, struct event>& events);
    std::map<unsigned int, struct event> read_from_journal();
private:
    sqlite3 *db = NULL;
    
    static int read_journal_callback(void *data, int argc, char **argv, char **colName);
};