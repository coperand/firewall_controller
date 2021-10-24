#include "snmp_handler.h"

using namespace std;

//Инициализируем статические переменные
map<unsigned int, struct rule>* SnmpHandler::container = NULL;
map<unsigned int, struct rule>::iterator* SnmpHandler::it = NULL;
int (*SnmpHandler::add_callback)(unsigned int index) = NULL;
int (*SnmpHandler::del_callback)(unsigned int index) = NULL;
int (*SnmpHandler::policy_callback)(uint8_t policy) = NULL;
uint8_t* SnmpHandler::policy = NULL;

SnmpHandler::SnmpHandler(oid* table_oid, unsigned int oid_len, string table_name, map<unsigned int, struct rule>* container, map<unsigned int, struct rule>::iterator* it,
                                int (*add_callback)(unsigned int), int (*del_callback)(unsigned int), int (*policy_callback)(uint8_t), uint8_t* policy)
{
    //Задаем рабочие значения статическим переменным
    this->container = container;
    this->it = it;
    this->add_callback = add_callback;
    this->del_callback = del_callback;
    this->policy_callback = policy_callback;
    this->policy = policy;
    
    //Устанавливаем роль программы как суб-агента
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
    SOCK_STARTUP;
    
    //Инициализируем части библиотеки, предназначенные для работы с SNMP и AgentX
    init_agent("Graduation_agent");
    init_snmp("Graduation_snmp");
    
    //Регистрируем обработчики для значений, за которые мы отвечаем
    init_table(table_oid, oid_len, table_name);
    init_policy(table_oid, oid_len, table_name);
}

SnmpHandler::~SnmpHandler()
{
    //Завершаем работу с SNMP
    snmp_shutdown("Graduation_snmp");
    shutdown_agent();
    SOCK_CLEANUP;
}

//Функция получения начальной точки в контейнере
netsnmp_variable_list* SnmpHandler::get_first_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
    if(!container->size())
        return NULL;
    
    *it = container->begin();
    
    *my_loop_context = it;
    *my_data_context = &(*it)->second;

    netsnmp_variable_list *vptr = put_index_data;
    
    snmp_set_var_value(vptr, &(*it)->first, sizeof((*it)->first));
    vptr = vptr->next_variable;

    return put_index_data;
}

//Функция получения следующей точки в контейнере
netsnmp_variable_list* SnmpHandler::get_next_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
    if(++(*it) == container->end())
        return NULL;
    
    *my_loop_context = it;
    *my_data_context = &(*it)->second;

    netsnmp_variable_list *vptr = put_index_data;
    
    snmp_set_var_value(vptr, &(*it)->first, sizeof((*it)->first));
    vptr = vptr->next_variable;

    return put_index_data;
}

//Функция создания нового элемента в контейнере
void* SnmpHandler::create_data_context(netsnmp_variable_list *index_data, int column)
{
    if( (*index_data->val.integer) % 2 == 0 )
        return NULL;
    
    return &(*container)[(*index_data->val.integer)];
}

//Функция регистрации обработчика для таблица
void SnmpHandler::init_table(oid* table_oid, unsigned int oid_len, string table_name)
{
    netsnmp_table_registration_info *table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    netsnmp_handler_registration *my_handler = netsnmp_create_handler_registration(table_name.data(),
                                                request_handler,
                                                table_oid,
                                                oid_len / sizeof(oid),
                                                HANDLER_CAN_RWRITE);
    netsnmp_iterator_info *iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    
    if (!my_handler || !table_info || !iinfo)
        return;

    netsnmp_table_helper_add_indexes(table_info,
                                  ASN_UNSIGNED,
                             0);
    
    table_info->min_column = 2;
    table_info->max_column = 17;
    
    iinfo->get_first_data_point = get_first_data_point;
    iinfo->get_next_data_point = get_next_data_point;
    iinfo->table_reginfo = table_info;
    
    netsnmp_register_table_iterator(my_handler, iinfo);
}

//Функция регистрации обработчика для поля fcPolicy
void SnmpHandler::init_policy(oid* table_oid, unsigned int oid_len, string table_name)
{
    table_oid[oid_len / sizeof(oid) - 1] += 1;
    netsnmp_register_scalar( netsnmp_create_handler_registration((table_name + string("Policy")).data(), policy_request_handler, table_oid, oid_len / sizeof(oid), HANDLER_CAN_RWRITE) );
}

//Обработчик запросов к таблице
int SnmpHandler::request_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
    for(netsnmp_request_info *request = requests; request; request = request->next)
    {
        if (request->processed != 0)
            continue;
        
        void *data_context = NULL;
        
        netsnmp_table_request_info *table_info = netsnmp_extract_table_info(request);
        if (table_info == NULL)
            continue;
        
        switch (reqinfo->mode) {
        case MODE_GET:
            data_context = netsnmp_extract_iterator_context(request);
            if (data_context == NULL)
            {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                continue;
            }
            break;

        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
            data_context = netsnmp_extract_iterator_context(request);
            if (!data_context)
            {
                data_context = create_data_context(table_info->indexes, table_info->colnum);
                if(data_context == NULL)
                {
                    netsnmp_set_request_error(reqinfo, request,
                                          SNMP_ERR_NOCREATION);
                    continue;
                }
            }
            break;
        }
        
        switch(reqinfo->mode)
        {
            case MODE_GET:
            {
                switch(static_cast<columns>(table_info->colnum))
                {
                    case columns::src_addr:
                        get_integer<in_addr_t>(&reinterpret_cast<struct rule*>(data_context)->src_ip, ASN_IPADDRESS, request, reqinfo);
                        break;
                    
                    case columns::src_mask:
                        get_integer<in_addr_t>(&reinterpret_cast<struct rule*>(data_context)->src_mask, ASN_IPADDRESS, request, reqinfo);
                        break;
                    
                    case columns::dst_addr:
                        get_integer<in_addr_t>(&reinterpret_cast<struct rule*>(data_context)->dst_ip, ASN_IPADDRESS, request, reqinfo);
                        break;
                    
                    case columns::dst_mask:
                        get_integer<in_addr_t>(&reinterpret_cast<struct rule*>(data_context)->dst_mask, ASN_IPADDRESS, request, reqinfo);
                        break;
                    
                    case columns::in_iface:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->in_if, request, reqinfo);
                        break;
                    
                    case columns::out_iface:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->out_if, request, reqinfo);
                        break;
                    
                    case columns::proto:
                        get_integer<uint8_t>(reinterpret_cast<uint8_t*>(&reinterpret_cast<struct rule*>(data_context)->proto), ASN_INTEGER, request, reqinfo);
                        break;
                    
                    case columns::src_port_min:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->sport.min), ASN_UNSIGNED, request, reqinfo);
                        break;
                    
                    case columns::src_port_max:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->sport.max), ASN_UNSIGNED, request, reqinfo);
                        break;
                    
                    case columns::dst_port_min:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->dport.min), ASN_UNSIGNED, request, reqinfo);
                        break;
                    
                    case columns::dst_port_max:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->dport.max), ASN_UNSIGNED, request, reqinfo);
                        break;
                    
                    case columns::state:
                        get_integer<uint8_t>(reinterpret_cast<uint8_t*>(&reinterpret_cast<struct rule*>(data_context)->state), ASN_INTEGER, request, reqinfo);
                        break;
                    
                    case columns::action:
                    {
                        if(reinterpret_cast<struct rule*>(data_context)->action.size() == 0)
                            break;
                        
                        //Пишем строку, приведенную к нижнему регистру, во временную переменную
                        string temp;
                        temp.resize(reinterpret_cast<struct rule*>(data_context)->action.size());
                        transform(reinterpret_cast<struct rule*>(data_context)->action.begin(), reinterpret_cast<struct rule*>(data_context)->action.end(), temp.begin(), ::tolower);
                        
                        uint16_t number = 0;
                        if(temp == "accept")
                            number = 1;
                        else if(temp == "drop")
                            number = 2;
                        else if(temp == "reject")
                            number = 3;
                        else if(temp == "snat")
                            number = 4;
                        else if(temp == "dnat")
                            number = 5;
                        else if(temp == "redirect")
                            number = 6;
                        
                        snmp_set_var_typed_value(request->requestvb, ASN_INTEGER, &number, sizeof(uint16_t));
                        break;
                    }
                    case columns::action_params:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->action_params, request, reqinfo);
                        break;
                    
                    case columns::inverse_flags:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->inv_flags), ASN_OCTET_STR, request, reqinfo);
                        break;
                    
                    default:
                        netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                }
                break;
            }
            
            case MODE_SET_RESERVE2:
            {
                int ret = -1;
                switch(static_cast<columns>(table_info->colnum))
                {
                    case columns::src_addr:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::src_mask:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if(!ret && !check_mask(*request->requestvb->val.integer))
                            ret = SNMP_ERR_INCONSISTENTVALUE;
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::dst_addr:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::dst_mask:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if(!ret && !check_mask(*request->requestvb->val.integer))
                            ret = SNMP_ERR_INCONSISTENTVALUE;
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::in_iface:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if(!ret && !if_nametoindex((const char*)request->requestvb->val.string))
                            ret = SNMP_ERR_INCONSISTENTVALUE;
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::out_iface:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if(!ret && !if_nametoindex((const char*)request->requestvb->val.string))
                            ret = SNMP_ERR_INCONSISTENTVALUE;
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::proto:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), proto_possible_values);
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::src_port_min:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::src_port_max:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::dst_port_min:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::dst_port_max:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::state:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), state_possible_values);
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::action:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), action_possible_values);
                        if( !ret && ((*(table_info->indexes->val.integer) < 250 && *request->requestvb->val.integer != 5) ||
                                    (*(table_info->indexes->val.integer) >= 250 && *(table_info->indexes->val.integer) < 750 && (*request->requestvb->val.integer == 4 || *request->requestvb->val.integer == 5)) ||
                                    (*(table_info->indexes->val.integer) >= 750 && *request->requestvb->val.integer != 4)) )
                            ret = SNMP_ERR_INCONSISTENTVALUE;
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::action_params:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::inverse_flags:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case columns::command:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), command_possible_values);
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    default:
                       netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
                }
                break;
            }
            
            case MODE_SET_ACTION:
            {
                switch(static_cast<columns>(table_info->colnum))
                {
                    case columns::src_addr:
                    {
                        reinterpret_cast<struct rule*>(data_context)->src_ip = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->src_ip += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::src_mask:
                    {
                        reinterpret_cast<struct rule*>(data_context)->src_mask = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->src_mask += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::dst_addr:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dst_ip = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dst_ip += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::dst_mask:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dst_mask = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dst_mask += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::in_iface:
                    {
                        reinterpret_cast<struct rule*>(data_context)->in_if.clear();
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->in_if.push_back(request->requestvb->val.string[j]);
                        
                        break;
                    }
                    case columns::out_iface:
                    {
                        reinterpret_cast<struct rule*>(data_context)->out_if.clear();
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->out_if.push_back(request->requestvb->val.string[j]);
                        
                        break;
                    }
                    case columns::proto:
                    {
                        unsigned int temp = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            temp += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        reinterpret_cast<struct rule*>(data_context)->proto = static_cast<protocol>(temp);
                        
                        break;
                    }
                    case columns::src_port_min:
                    {
                        reinterpret_cast<struct rule*>(data_context)->sport.min = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->sport.min += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::src_port_max:
                    {
                        reinterpret_cast<struct rule*>(data_context)->sport.max = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->sport.max += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::dst_port_min:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dport.min = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dport.min += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::dst_port_max:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dport.max = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dport.max += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::state:
                    {
                        reinterpret_cast<struct rule*>(data_context)->state = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->state += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::action:
                    {
                        unsigned int action = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            action += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        if(action == 0)
                            reinterpret_cast<struct rule*>(data_context)->action = "UNKNOWN";
                        if(action == 1)
                            reinterpret_cast<struct rule*>(data_context)->action = "ACCEPT";
                        if(action == 2)
                            reinterpret_cast<struct rule*>(data_context)->action = "DROP";
                        if(action == 3)
                            reinterpret_cast<struct rule*>(data_context)->action = "REJECT";
                        if(action == 4)
                            reinterpret_cast<struct rule*>(data_context)->action = "SNAT";
                        if(action == 5)
                            reinterpret_cast<struct rule*>(data_context)->action = "DNAT";
                        if(action == 6)
                            reinterpret_cast<struct rule*>(data_context)->action = "REJECT";
                        
                        break;
                    }
                    case columns::action_params:
                    {
                        reinterpret_cast<struct rule*>(data_context)->action_params.clear();
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->action_params.push_back(request->requestvb->val.string[j]);
                        
                        break;
                    }
                    case columns::inverse_flags:
                    {
                        reinterpret_cast<struct rule*>(data_context)->inv_flags = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->inv_flags += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case columns::command:
                    {
                        int result = SNMP_ERR_INCONSISTENTVALUE;
                        if(request->requestvb->val.string[0] == 0x00)
                        {
                            //Проводим дополнительную валидацию перед добавлением нового элемента
                            if((reinterpret_cast<struct rule*>(data_context)->src_ip == 0 && reinterpret_cast<struct rule*>(data_context)->src_mask != 0) ||
                                (reinterpret_cast<struct rule*>(data_context)->dst_ip == 0 && reinterpret_cast<struct rule*>(data_context)->dst_mask != 0))
                            {
                                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                                break;
                            }
                            if(reinterpret_cast<struct rule*>(data_context)->src_ip != 0 && reinterpret_cast<struct rule*>(data_context)->src_mask == 0)
                                reinterpret_cast<struct rule*>(data_context)->src_mask = inet_addr("255.255.255.255");
                            if(reinterpret_cast<struct rule*>(data_context)->dst_ip != 0 && reinterpret_cast<struct rule*>(data_context)->dst_mask == 0)
                                reinterpret_cast<struct rule*>(data_context)->dst_mask = inet_addr("255.255.255.255");
                            
                            if((reinterpret_cast<struct rule*>(data_context)->sport.min > reinterpret_cast<struct rule*>(data_context)->sport.max) ||
                                (reinterpret_cast<struct rule*>(data_context)->dport.min > reinterpret_cast<struct rule*>(data_context)->dport.max))
                            {
                                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                                break;
                            }
                            
                            if(reinterpret_cast<struct rule*>(data_context)->proto != protocol::udp && reinterpret_cast<struct rule*>(data_context)->proto != protocol::tcp &&
                                (reinterpret_cast<struct rule*>(data_context)->sport.min != 0 || reinterpret_cast<struct rule*>(data_context)->sport.max != 0 ||
                                 reinterpret_cast<struct rule*>(data_context)->dport.min != 0 || reinterpret_cast<struct rule*>(data_context)->dport.max != 0))
                            {
                                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                                break;
                            }
                            
                            if(reinterpret_cast<struct rule*>(data_context)->action_params.size() > 0 &&
                                    reinterpret_cast<struct rule*>(data_context)->action != "SNAT" && reinterpret_cast<struct rule*>(data_context)->action != "DNAT")
                            {
                                netsnmp_set_request_error(reqinfo, request, SNMP_ERR_INCONSISTENTVALUE);
                                break;
                            }
                            
                            result = add_callback(*(table_info->indexes->val.integer));
                        }
                        else if(request->requestvb->val.string[0] == 0x01)
                            result = del_callback(*(table_info->indexes->val.integer));
                        
                        if(result)
                            netsnmp_set_request_error(reqinfo, request, result);
                        break;
                    }
                    
                    break;
                }
            }
        }
    }
    
    return SNMP_ERR_NOERROR;
}

//Обработчик запросов к полю fcPolicy
int SnmpHandler::policy_request_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
    switch(reqinfo->mode)
    {
        case MODE_GET:
        {
            snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, policy, sizeof(*policy));
            break;
        }

        case MODE_SET_RESERVE2:
        {
            if (requests->requestvb->type != ASN_INTEGER)
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
            
            if(*requests->requestvb->val.integer != 0 && *requests->requestvb->val.integer != 1)
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_INCONSISTENTVALUE);
            break;
        }

        case MODE_SET_ACTION:
        {
            int result = policy_callback(requests->requestvb->val.string[0] & 0x000000FF);
            if(result)
                netsnmp_set_request_error(reqinfo, requests, result);
            
            break;
        }
    }

    return SNMP_ERR_NOERROR;
}

template <typename T>
void SnmpHandler::get_integer(T* data, int type, netsnmp_request_info *request, netsnmp_agent_request_info *reqinfo)
{
    if(*data == 0)
    {
        netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
        return;
    }
    
    snmp_set_var_typed_value(request->requestvb, type, data, sizeof(T));
}

void SnmpHandler::get_char(string *data, netsnmp_request_info *request, netsnmp_agent_request_info *reqinfo)
{
    if(data->size() == 0)
    {
        netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
        return;
    }
    
    snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR, data->data(), data->size());
}

int SnmpHandler::check_val(int type, int waiting_type, void *val, vector<int> possible_values)
{
    if (!val)
        return SNMP_ERR_GENERR;
    
    if (type != waiting_type)
        return SNMP_ERR_WRONGTYPE;
    
    if(possible_values.size())
    {
        bool found = false;
        for(auto item : possible_values)
            if(*(reinterpret_cast<int*>(val)) == item)
            {
                found = true;
                break;
            }
        
        if(!found)
            return SNMP_ERR_INCONSISTENTVALUE;
    }
    
    return 0;
}

bool SnmpHandler::check_mask(unsigned int mask)
{
    //Переворачиваем маску, т.к. подразумевается сетевой порядок байт
    mask = htonl(mask);
    
    //Счетчик нужен для избежания бесконечных циклов
    uint8_t counter = 0;
    
    //Проходимся по нулям справа налево
    while(!((mask >> 1) & 0x01))
    {
        mask >>= 1;
        if(++counter >= 8 * sizeof(mask))
        {
            counter--;
            break;
        }
    }
    
    //Проходимся по единицам справа налево
    while(((mask = mask >> 1) & 0x01))
        ++counter;
    
    //Если маска была пройдена целиком, значит она удовлетворяет требованиям
    return (mask == 0x00) && (counter + 1 == 8 * sizeof(mask));
}
