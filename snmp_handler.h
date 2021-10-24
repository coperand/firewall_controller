#pragma once

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <vector>
#include <map>
#include <algorithm>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "structs.h"

//Перечисление столбцов таблицы
enum class columns
{
    src_addr = 2,
    src_mask = 3,
    dst_addr = 4,
    dst_mask = 5,
    in_iface = 6,
    out_iface = 7,
    proto = 8,
    src_port_min = 9,
    src_port_max = 10,
    dst_port_min = 11,
    dst_port_max = 12,
    state = 13,
    action = 14,
    action_params = 15,
    inverse_flags = 16,
    command = 17
};

//Корректные значения для установки в заданные столбцы
const std::vector<int> proto_possible_values = {0, 1, 6, 17};
const std::vector<int> state_possible_values = {0, 1, 2, 3, 4};
const std::vector<int> action_possible_values = {1, 2, 3, 4, 5, 6};
const std::vector<int> command_possible_values = {0, 1};

class SnmpHandler
{
public:
    SnmpHandler() = delete;
    SnmpHandler(oid* table_oid, unsigned int oid_len, std::string table_name, std::map<unsigned int, struct rule>* container, std::map<unsigned int, struct rule>::iterator* it,
                                    int (*add_callback)(unsigned int), int (*del_callback)(unsigned int), int (*policy_callback)(uint8_t), uint8_t* policy);
    ~SnmpHandler();
private:
    //Переменные для работы с контейнером
    static std::map<unsigned int, struct rule>* container;
    static std::map<unsigned int, struct rule>::iterator* it;
    static uint8_t* policy;
    
    //Callback`и для выполнения set-запросов
    static int (*add_callback)(unsigned int index);
    static int (*del_callback)(unsigned int index);
    static int (*policy_callback)(uint8_t policy);
    
    //Функции, связанные с контекстом
    static netsnmp_variable_list* get_first_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata);
    static netsnmp_variable_list* get_next_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata);
    static void* create_data_context(netsnmp_variable_list *index_data, int column);
    
    //Функции инициализации обработчиков запросов
    static void init_table(oid* table_oid, unsigned int oid_len, std::string table_name);
    static void init_policy(oid* table_oid, unsigned int oid_len, std::string table_name);
    
    //Функции обработки запросов
    static int request_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);
    static int policy_request_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests);
    
    //Вспомогательные функции, используемые при обработке запросов
    template <typename T>
    static void get_integer(T* data, int type, netsnmp_request_info *request, netsnmp_agent_request_info *reqinfo);
    static void get_char(std::string *data, netsnmp_request_info *request, netsnmp_agent_request_info *reqinfo);
    static int check_val(int type, int waiting_type, void *val, std::vector<int> possible_values);
    static bool check_mask(unsigned int mask);
};


