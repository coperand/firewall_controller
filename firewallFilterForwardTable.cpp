#include "firewallFilterForwardTable.h"

using namespace std;

map<unsigned int, struct rule> container;
map<unsigned int, struct rule>::iterator it;

netsnmp_variable_list* firewallFilterForwardTable_get_first_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
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

netsnmp_variable_list* firewallFilterForwardTable_get_next_data_point(void **my_loop_context, void **my_data_context, netsnmp_variable_list *put_index_data, netsnmp_iterator_info *mydata)
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

void* firewallFilterForwardTable_create_data_context(netsnmp_variable_list *index_data, int column)
{
    return NULL;
}

template <typename T>
void get_integer(T* data, int type, netsnmp_request_info *request)
{
    if(*data == static_cast<T>(~0))
        return;
    
    snmp_set_var_typed_value(request->requestvb, type, data, sizeof(T));
}

void get_ip(in_addr_t* data, int type, netsnmp_request_info *request)
{
    if(*data == 0)
        return;
    
    snmp_set_var_typed_value(request->requestvb, type, data, sizeof(in_addr_t));
}

void get_char(string *data, netsnmp_request_info *request)
{
    if(data->size() == 0)
        return;
    
    snmp_set_var_typed_value(request->requestvb, ASN_OCTET_STR, data->data(), data->size());
}

int check_val(int type, int waiting_type, void *val, vector<int> possible_values)
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

void initialize_table_firewallFilterForwardTable()
{
    const oid firewallFilterForwardTable_oid[] = {1, 3, 6, 1, 4, 1, 4, 199, 1, 1};
    netsnmp_table_registration_info *table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    netsnmp_handler_registration *my_handler = netsnmp_create_handler_registration("firewallFilterForwardTable",
                                                firewallFilterForwardTable_handler,
                                                firewallFilterForwardTable_oid,
                                                OID_LENGTH(firewallFilterForwardTable_oid),
                                                HANDLER_CAN_RWRITE);
    netsnmp_iterator_info *iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    
    if (!my_handler || !table_info || !iinfo)
        return;

    netsnmp_table_helper_add_indexes(table_info,
                                  ASN_UNSIGNED, // index: fcFFIndex
                             0);

    table_info->min_column = 2;
    table_info->max_column = 17;

    iinfo->get_first_data_point = firewallFilterForwardTable_get_first_data_point;
    iinfo->get_next_data_point = firewallFilterForwardTable_get_next_data_point;
    iinfo->table_reginfo = table_info;

    netsnmp_register_table_iterator(my_handler, iinfo);
}

void init_firewallFilterForwardTable()
{
    initialize_table_firewallFilterForwardTable();
}

int firewallFilterForwardTable_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
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
                data_context = firewallFilterForwardTable_create_data_context(table_info->indexes, table_info->colnum);
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
                    case COLUMN_FCFFSRCADDR:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->src_ip, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_FCFFSRCMASK:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->src_mask, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_FCFFDSTADDR:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->dst_ip, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_FCFFDSTMASK:
                        get_ip(&reinterpret_cast<struct rule*>(data_context)->dst_mask, ASN_IPADDRESS, request);
                        break;
                    
                    case COLUMN_FCFFINIFACE:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->in_if, request);
                        break;
                    
                    case COLUMN_FCFFOUTIFACE:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->out_if, request);
                        break;
                    
                    case COLUMN_FCFFPROTO:
                        get_integer<uint8_t>(reinterpret_cast<uint8_t*>(&reinterpret_cast<struct rule*>(data_context)->proto), ASN_INTEGER, request);
                        break;
                    
                    case COLUMN_FCFFSRCPORTMIN:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->sport.min), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_FCFFSRCPORTMAX:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->sport.max), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_FCFFDSTPORTMIN:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->dport.min), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_FCFFDSTPORTMAX:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->dport.max), ASN_UNSIGNED, request);
                        break;
                    
                    case COLUMN_FCFFSTATE:
                        get_integer<uint8_t>(reinterpret_cast<uint8_t*>(&reinterpret_cast<struct rule*>(data_context)->state), ASN_INTEGER, request);
                        break;
                    
                    case COLUMN_FCFFACTION:
                        get_integer<uint16_t>(reinterpret_cast<uint16_t*>(&reinterpret_cast<struct rule*>(data_context)->action), ASN_INTEGER, request);
                        break;
                    
                    case COLUMN_FCFFACTIONPARAMS:
                        get_char(&reinterpret_cast<struct rule*>(data_context)->action_params, request);
                        break;
                    
                    case COLUMN_FCFFINVERSEFLAGS:
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
                          case COLUMN_FCFFSRCADDR:
                            ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFSRCMASK:
                            ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFDSTADDR:
                            ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFDSTMASK:
                            ret = check_val(request->requestvb->type, ASN_IPADDRESS, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFINIFACE:
                            ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFOUTIFACE:
                            ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFPROTO:
                            ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), FCFFPROTO_values);
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFSRCPORTMIN:
                            ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFSRCPORTMAX:
                            ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFDSTPORTMIN:
                            ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFDSTPORTMAX:
                            ret = check_val(request->requestvb->type, ASN_UNSIGNED, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFSTATE:
                            ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), FCFFSTATE_values);
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFACTION:
                            ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), FCFFACTION_values);
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFACTIONPARAMS:
                            ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFINVERSEFLAGS:
                            ret = check_val(request->requestvb->type, ASN_OCTET_STR, reinterpret_cast<void*>(request->requestvb->val.string), {});
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                          
                          case COLUMN_FCFFCOMMAND:
                            ret = check_val(request->requestvb->type, ASN_INTEGER, reinterpret_cast<void*>(request->requestvb->val.string), FCFFCOMMAND_values);
                            if (ret != 0)
                                netsnmp_set_request_error(reqinfo, request, ret);
                            break;
                    
                    default:
                       netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOTWRITABLE);
                 }
                break;
            }
            
            case MODE_SET_ACTION:
            {
                switch(table_info->colnum)
                {
                          case COLUMN_FCFFSRCADDR:
                            {
                                //ret = set_fcFFSrcAddr(ci->data_context, (in_addr_t *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFSRCMASK:
                            {
                                //ret = set_fcFFSrcMask(ci->data_context, (in_addr_t *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFDSTADDR:
                            {
                                //ret = set_fcFFDstAddr(ci->data_context, (in_addr_t *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFDSTMASK:
                            {
                                //ret = set_fcFFDstMask(ci->data_context, (in_addr_t *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFINIFACE:
                            {
                                //ret = set_fcFFInIface(ci->data_context, (char *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFOUTIFACE:
                            {
                                //ret = set_fcFFOutIface(ci->data_context, (char *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFPROTO:
                            {
                                //ret = set_fcFFProto(ci->data_context, (long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFSRCPORTMIN:
                            {
                                //ret = set_fcFFSrcPortMin(ci->data_context, (u_long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFSRCPORTMAX:
                            {
                                //ret = set_fcFFSrcPortMax(ci->data_context, (u_long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFDSTPORTMIN:
                            {
                                //ret = set_fcFFDstPortMin(ci->data_context, (u_long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFDSTPORTMAX:
                            {
                                //ret = set_fcFFDstPortMax(ci->data_context, (u_long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFSTATE:
                            {
                                //ret = set_fcFFState(ci->data_context, (long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFACTION:
                            {
                                //ret = set_fcFFAction(ci->data_context, (long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFACTIONPARAMS:
                            {
                                //ret = set_fcFFActionParams(ci->data_context, (char *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFINVERSEFLAGS:
                            {
                                //ret = set_fcFFInverseFlags(ci->data_context, (char *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                          case COLUMN_FCFFCOMMAND:
                            {
                                //ret = set_fcFFCommand(ci->data_context, (long *) request->requestvb->val.string, request->requestvb->val_len);
                                int ret = SNMP_ERR_NOERROR;
                                if (ret)
                                    netsnmp_set_request_error(reqinfo, request, ret);
                            }
                            break;
                 }
                break;
            }
        }
    }

    return SNMP_ERR_NOERROR;
}
