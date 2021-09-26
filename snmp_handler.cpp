#include "snmp_handler.h"

using namespace std;

map<unsigned int, struct rule> SnmpHandler::container = {{1, {inet_addr("192.168.2.12"), inet_addr("131.121.2.3"), inet_addr("255.255.255.252"), inet_addr("255.255.255.0"), "eth0", "eth1", protocol::tcp, {1, 15}, {134, 32412}, 1, 3, "test", 1}},
                                            {2, {inet_addr("192.163.21.1"), inet_addr("114.21.21.2"), inet_addr("255.255.0.0"), inet_addr("255.255.252.0"), "ens5f5", "exr131", protocol::udp, {3, 21}, {321, 13142}, 2, 4, "qwer", 0}}};
map<unsigned int, struct rule>::iterator SnmpHandler::it = {};

SnmpHandler::SnmpHandler(oid* table_oid, unsigned int oid_len, string table_name)
{
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);
    SOCK_STARTUP;
    
    init_agent("Graduation_agent");
    init_snmp("Graduation_snmp");
    
    init_table(table_oid, oid_len, table_name);
}

SnmpHandler::~SnmpHandler()
{
    //TODO: Завершение работы с snmp
}

netsnmp_variable_list* SnmpHandler::get_first_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
    if(!container.size())
        return NULL;
    
    it = container.begin();
    
    *my_loop_context = &it;
    *my_data_context = &it->second;

    netsnmp_variable_list *vptr = put_index_data;
    
    snmp_set_var_value(vptr, &it->first, sizeof(it->first));
    vptr = vptr->next_variable;

    return put_index_data;
}

netsnmp_variable_list* SnmpHandler::get_next_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
{
    if(++it == container.end())
        return NULL;
    
    *my_loop_context = &it;
    *my_data_context = &it->second;

    netsnmp_variable_list *vptr = put_index_data;
    
    snmp_set_var_value(vptr, &it->first, sizeof(it->first));
    vptr = vptr->next_variable;

    return put_index_data;
}

void* SnmpHandler::create_data_context(netsnmp_variable_list *index_data, int column)
{
    return NULL;
}

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
            data_context =  netsnmp_extract_iterator_context(request);
            if (data_context == NULL)
            {
                netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                continue;
            }
            break;

        case MODE_SET_RESERVE1:
        case MODE_SET_ACTION:
            data_context =  netsnmp_extract_iterator_context(request);
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
                switch(table_info->colnum)
                {
                    case COLUMN_SRCADDR:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->src_ip, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_SRCMASK:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->src_mask, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_DSTADDR:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->dst_ip, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_DSTMASK:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->dst_mask, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_INIFACE:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->in_if, request);
                        break;
                    
                    case COLUMN_OUTIFACE:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->out_if, request);
                        break;
                    
                    case COLUMN_PROTO:
                        get_integer<uint8_t>(reinterpret_cast<uint8_t*>(&reinterpret_cast<struct rule*>(data_context)->proto), ASN_INTEGER, request);
                        break;
                    
                    case COLUMN_SRCPORTMIN:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->sport.min), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_SRCPORTMAX:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->sport.max), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_DSTPORTMIN:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->dport.min), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_DSTPORTMAX:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->dport.max), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_STATE:
                        get_integer<uint8_t>(reinterpret_cast<uint8_t*>(&reinterpret_cast<struct rule*>(data_context)->state), ASN_INTEGER, request);
                        break;
                    
                    case COLUMN_ACTION:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->action), ASN_INTEGER, request);
                        break;
                    
                    case COLUMN_ACTIONPARAMS:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->action_params, request);
                        break;
                    
                    case COLUMN_INVERSEFLAGS:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->inv_flags), ASN_OCTET_STR, request);
                        break;
                    
                    default:
                        netsnmp_set_request_error(reqinfo, request, SNMP_NOSUCHINSTANCE);
                }
                break;
            }
            
            case MODE_SET_RESERVE2:
            {
                int ret = -1;
                switch(table_info->colnum)
                {
                    case COLUMN_SRCADDR:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_SRCMASK:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_DSTADDR:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_DSTMASK:
                    {
                        ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_INIFACE:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_OUTIFACE:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_PROTO:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), PROTO_values);
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_SRCPORTMIN:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_SRCPORTMAX:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_DSTPORTMIN:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_DSTPORTMAX:
                    {
                        ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_STATE:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), STATE_values);
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_ACTION:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), ACTION_values);
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_ACTIONPARAMS:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_INVERSEFLAGS:
                    {
                        ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                        if (ret != 0)
                            netsnmp_set_request_error(reqinfo, request, ret);
                        break;
                    }
                    case COLUMN_COMMAND:
                    {
                        ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), COMMAND_values);
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
                switch(table_info->colnum)
                {
                    case COLUMN_SRCADDR:
                    {
                        reinterpret_cast<struct rule*>(data_context)->src_ip = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->src_ip += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_SRCMASK:
                    {
                        reinterpret_cast<struct rule*>(data_context)->src_mask = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->src_mask += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_DSTADDR:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dst_ip = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dst_ip += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_DSTMASK:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dst_mask = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dst_mask += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_INIFACE:
                    {
                        reinterpret_cast<struct rule*>(data_context)->in_if.clear();
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->in_if.push_back(request->requestvb->val.string[j]);
                        
                        break;
                    }
                    case COLUMN_OUTIFACE:
                    {
                        reinterpret_cast<struct rule*>(data_context)->out_if.clear();
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->out_if.push_back(request->requestvb->val.string[j]);
                        
                        break;
                    }
                    case COLUMN_PROTO:
                    {
                        unsigned int temp = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            temp += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        reinterpret_cast<struct rule*>(data_context)->proto = static_cast<protocol>(temp);
                        
                        break;
                    }
                    case COLUMN_SRCPORTMIN:
                    {
                        reinterpret_cast<struct rule*>(data_context)->sport.min = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->sport.min += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_SRCPORTMAX:
                    {
                        reinterpret_cast<struct rule*>(data_context)->sport.max = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->sport.max += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_DSTPORTMIN:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dport.min = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dport.min += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_DSTPORTMAX:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dport.max = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dport.max += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_STATE:
                    {
                        reinterpret_cast<struct rule*>(data_context)->state = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->state += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_ACTION:
                    {
                        reinterpret_cast<struct rule*>(data_context)->dst_mask = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->dst_mask += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_ACTIONPARAMS:
                    {
                        reinterpret_cast<struct rule*>(data_context)->action_params.clear();
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->action_params.push_back(request->requestvb->val.string[j]);
                        
                        break;
                    }
                    case COLUMN_INVERSEFLAGS:
                    {
                        reinterpret_cast<struct rule*>(data_context)->action = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->action += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    case COLUMN_COMMAND:
                    {
                        reinterpret_cast<struct rule*>(data_context)->inv_flags = 0;
                        for(unsigned int j = 0; j < request->requestvb->val_len; j++)
                            reinterpret_cast<struct rule*>(data_context)->inv_flags += (request->requestvb->val.string[j] & 0x000000FF) << (8 * j);
                        
                        break;
                    }
                    
                    break;
                }
            }
        }
    }
    
    return SNMP_ERR_NOERROR;
}

template <typename T>
void SnmpHandler::get_integer(T* data, int type, netsnmp_request_info *request)
{
    if(*data == static_cast<T>(~0))
        return;
    
    snmp_set_var_typed_value(request->requestvb, type, data, sizeof(T));
}

void SnmpHandler::get_ip(in_addr_t* data, int type, netsnmp_request_info *request)
{
    if(*data == 0)
        return;
    
    snmp_set_var_typed_value(request->requestvb, type, data, sizeof(in_addr_t));
}

void SnmpHandler::get_char(string *data, netsnmp_request_info *request)
{
    if(data->size() == 0)
        return;
    
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
