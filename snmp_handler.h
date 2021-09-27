#pragma once

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <vector>
#include <map>
#include <algorithm>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "structs.h"

class SnmpHandler
{
public:
    SnmpHandler() = delete;
    SnmpHandler(oid* table_oid, unsigned int oid_len, std::string table_name);
    ~SnmpHandler();
private:
    static std::map<unsigned int, struct rule> container;
    static std::map<unsigned int, struct rule>::iterator it;
    
    //Функции, связанные с контекстом
    static netsnmp_variable_list* get_first_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata);
    static netsnmp_variable_list* get_next_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata);
    static void* create_data_context(netsnmp_variable_list *index_data, int column);
    //Функция инициализации таблицы
    static void init_table(oid* table_oid, unsigned int oid_len, std::string table_name);
    //Функция обработки запросов
    static int request_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);
    
    //Вспомогательные функции, используемые при обработке запросов
    template <typename T>
    static void get_integer(T* data, int type, netsnmp_request_info *request);
    static void get_ip(in_addr_t* data, int type, netsnmp_request_info *request);
    static void get_char(std::string *data, netsnmp_request_info *request);
    static int check_val(int type, int waiting_type, void *val, std::vector<int> possible_values);
};

/* column number definitions for table firewallFilterForwardTable */
       #define COLUMN_INDEX		1
       #define COLUMN_SRCADDR		2
       #define COLUMN_SRCMASK		3
       #define COLUMN_DSTADDR		4
       #define COLUMN_DSTMASK		5
       #define COLUMN_INIFACE		6
       #define COLUMN_OUTIFACE		7
       #define COLUMN_PROTO		8
       #define COLUMN_SRCPORTMIN	9
       #define COLUMN_SRCPORTMAX	10
       #define COLUMN_DSTPORTMIN	11
       #define COLUMN_DSTPORTMAX	12
       #define COLUMN_STATE		13
       #define COLUMN_ACTION		14
       #define COLUMN_ACTIONPARAMS	15
       #define COLUMN_INVERSEFLAGS	16
       #define COLUMN_COMMAND		17

/*possible values*/
const std::vector<int> PROTO_values = {0, 1, 6, 17};
const std::vector<int> STATE_values = {0, 1, 2, 3, 4};
const std::vector<int> ACTION_values = {1, 2, 3, 4, 5, 6};
const std::vector<int> COMMAND_values = {0, 1};
