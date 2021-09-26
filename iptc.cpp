#include "iptc.h"

using namespace std;

IpTc::IpTc()
{

}

IpTc::~IpTc()
{

}

int IpTc::del_rule(struct rule conditions, string table, string chain)
{
    //Инициализируем таблицу
    struct xtc_handle *h = iptc_init(table.data());
    if(!h)
    {
        printf("Failed to initialize %s table: %s\n", table.data(), iptc_strerror(errno));
        return -1;
    }
    
    //Проверяем наличие цепочки
    if(!iptc_is_chain(chain.data(), h))
    {
        printf("No %s chain found\n", chain.data());
        iptc_free(h);
        return -1;
    }
    
    bool found;
    do
    {
        int i = 0;
        found = false;
        for (const struct ipt_entry* e = iptc_first_rule(chain.data(), h); e; e = iptc_next_rule(e, h), i++)
        {
            if (conditions.sport.min != 0 || conditions.sport.max != 0 || conditions.dport.min != 0 || conditions.dport.max != 0)
            {
                bool match_found = false;
                for (unsigned int j = sizeof(struct ipt_entry); j < e->target_offset;)
                {
                    struct ipt_entry_match* match = (struct ipt_entry_match *)e + j;
                    
                    int proto = 0;
                    if (strcmp(match->u.user.name, "tcp") == 0)
                        proto = 6;
                    else if (strcmp(match->u.user.name, "udp") == 0)
                        proto = 17;
                    
                    if(proto == 6 || proto == 17)
                    {
                        uint16_t temp[2];
                        
                        if(conditions.sport.min != 0 || conditions.sport.max != 0)
                        {
                            if (conditions.sport.min != ((proto == 6) ? ((struct ipt_tcp *)match->data)->spts[0] : ((struct ipt_udp *)match->data)->spts[0]) ||
                                conditions.sport.max != ((proto == 6) ? ((struct ipt_tcp *)match->data)->spts[1] : ((struct ipt_udp *)match->data)->spts[1]))
                               continue;
                        }
                        if(conditions.dport.min != 0 || conditions.dport.max != 0)
                        {
                            if (conditions.dport.min != ((proto == 6) ? ((struct ipt_tcp *)match->data)->dpts[0] : ((struct ipt_udp *)match->data)->dpts[0]) ||
                                conditions.dport.max != ((proto == 6) ? ((struct ipt_tcp *)match->data)->dpts[1] : ((struct ipt_udp *)match->data)->dpts[1]))
                                continue;
                        }
                         
                        match_found = true;
                        break;
                    }
                    
                    j += match->u.match_size;
                }
                
                if(!match_found)
               {
                    printf("Wrong ports\n");
                    continue;
                }
            }
            if (conditions.src_ip && conditions.src_ip != e->ip.src.s_addr)
                continue;
            if (conditions.dst_ip && conditions.dst_ip != e->ip.dst.s_addr)
                continue;
            if (conditions.in_if.size() && conditions.in_if != string(e->ip.iniface))
                continue;
            if (conditions.out_if.size() && conditions.out_if != string(e->ip.outiface))
                continue;
            if ((conditions.proto == protocol::tcp && e->ip.proto != IPPROTO_TCP) || (conditions.proto == protocol::udp && e->ip.proto != IPPROTO_UDP) ||
                          (conditions.proto == protocol::icmp && e->ip.proto != IPPROTO_ICMP))
                continue;
            if (conditions.action.size() && conditions.action != string(iptc_get_target(e, h)))
                    continue;
            if (conditions.action == string("DNAT") || conditions.action == string("SNAT"))
            {
                struct ipt_entry_target *t = (struct ipt_entry_target *) ((uint8_t*)e + e->target_offset);
                struct ip_nat_multi_range *mr = (struct ip_nat_multi_range *) ((void *) &t->data);

                //TODO: Рассмотреть другие случаи
                if(mr->rangesize != 1)
                    continue;

                struct ip_nat_range *r = mr->range;
                struct ip_nat_range range = parse_range(conditions.action_params);
                if (r->flags != range.flags
                       || r->min_ip != range.min_ip
                       || r->max_ip != range.max_ip
                       || r->min.all != range.min.all
                       || r->max.all != range.max.all)
                    continue;
            }
            
            found = true;
            break;
        }

        if(found)
        {
            if(!iptc_delete_num_entry(chain.data(), i, h))
            {
                printf("Failed to delete entry from netfilter: %s", iptc_strerror(errno));
                iptc_free(h);
                return -1;
            }
        }
    
    } while(found);
    
    if(!iptc_commit(h))
    {
        printf("Failed to commit to %s table: %s\n", table.data(), iptc_strerror(errno));
        iptc_free(h);
        return -1;
    }
    
    iptc_free(h);
    return 0;
}

int IpTc::add_rule(struct rule conditions, string table, string chain, unsigned int index)
{
    //TODO: Обработка флагов инверсии
    
    //Выделяем память
    struct ipt_entry* chain_entry = (struct ipt_entry*) calloc(1, sizeof (struct ipt_entry));
    if(!chain_entry)
    {
        printf("Failed to allocate memory for struct ipt_entry in add_rule function\n");
        return -1;
    }
    
    //Добавляем адреса и маски
    if(conditions.src_ip)
    {
        chain_entry->ip.src.s_addr = conditions.src_ip;
        chain_entry->ip.smsk.s_addr = conditions.src_mask;
    }
    if(conditions.dst_ip)
    {
        chain_entry->ip.dst.s_addr = conditions.dst_ip;
        chain_entry->ip.dmsk.s_addr = conditions.dst_mask;
    }
    
    //Добавляем интерфейсы
    if(conditions.in_if.size())
        memcpy(chain_entry->ip.iniface, conditions.in_if.data(), conditions.in_if.size());
    if(conditions.out_if.size())
        memcpy(chain_entry->ip.outiface, conditions.out_if.data(), conditions.out_if.size());
    
    //Заполняем match в зависимости от протокола
    struct ipt_entry_match *entry_match = get_osi4_match(conditions.proto, conditions.sport, conditions.dport, chain_entry);
    
    //Заполняем target в зависимости от переданного значения
    struct ipt_entry_target* entry_target = NULL;
    if(conditions.action == string("DNAT") || conditions.action == string("SNAT"))
    {
        chain_entry->nfcache |= NFC_UNKNOWN;
        entry_target = get_nat_target(conditions.action, conditions.action_params);
    }
    else
    {
        size_t size = XT_ALIGN(sizeof (struct ipt_entry_target)) + XT_ALIGN(sizeof (int));
        entry_target = (struct ipt_entry_target *) calloc(1, size);
        entry_target->u.user.target_size = size;
        memcpy(entry_target->u.user.name, conditions.action.data(), conditions.action.size());
    }
    
    //Перевыделяем память
    //TODO: А можно ли перенести заполнение вперед и избавиться от динамического выделения памяти?
    long match_size = (entry_match ? entry_match->u.match_size : 0);
    chain_entry = (struct ipt_entry *) realloc(chain_entry, sizeof(struct ipt_entry) + match_size + entry_target->u.target_size);
    
    //Добавляем target
    memcpy(chain_entry->elems + match_size, entry_target, entry_target->u.target_size);
    chain_entry->target_offset = sizeof(struct ipt_entry) + match_size;
    chain_entry->next_offset = chain_entry->target_offset + entry_target->u.target_size;
    
    //Добавляем match
    if (entry_match)
        memcpy(chain_entry->elems, entry_match, match_size);
    
    //Инициализируем таблицу
    xtc_handle *h = iptc_init(table.data());
    if(!h)
    {
        printf("Failed to initialize %s table: %s\n", table.data(), iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if(entry_match)
            free(entry_match);
        return -1;
    }
    
    //Проверяем наличие цепочки
    if(!iptc_is_chain(chain.data(), h))
    {
        printf("No %s chain found\n", chain.data());
        free(chain_entry);
        free(entry_target);
        if(entry_match)
            free(entry_match);
        iptc_free(h);
        return -1;
    }
    
    //TODO: Проверка, что в данную цепочку можно добавлять подобные правила
    
    //Добавляем правило
    ipt_chainlabel labelit = {};
    strncpy(labelit, chain.data(), chain.size());
    if(!iptc_insert_entry(labelit, chain_entry, index, h))
    {
        printf("Failed to add entry to netfilter: %s\n", iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if(entry_match)
            free(entry_match);
        iptc_free(h);
        return -1;
    }
    
    //Применяем внесенные изменения
    if (!iptc_commit(h))
    {
        printf("Failed to commit to %s table: %s\n", table.data(), iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if(entry_match)
            free(entry_match);
        iptc_free(h);
        return -1;
    }
    
    //Освобождаем ресурсы
    if(entry_match)
        free(entry_match);
    free(entry_target);
    free(chain_entry);
    iptc_free(h);
    
    return 0;
}

struct ipt_entry_match* IpTc::get_osi4_match(protocol proto, struct range sport, struct range dport, struct ipt_entry* chain_entry)
{

    //Высчитываем размер
    size_t size = XT_ALIGN(sizeof(struct ipt_entry_match));
    switch(proto)
    {
        case protocol::icmp:
            size += XT_ALIGN(sizeof(struct ipt_icmp));
            break;
        case protocol::tcp:
            size += XT_ALIGN(sizeof(struct ipt_tcp));
            break;
        case protocol::udp:
            size += XT_ALIGN(sizeof(struct ipt_udp));
            break;
    }
    
    //Выделяем память
    struct ipt_entry_match* match = (struct ipt_entry_match *) calloc(1, size);
    match->u.match_size = size;
    
    //Заполняем название
    switch(proto)
    {
        case protocol::icmp:
            strncpy(match->u.user.name, "icmp", IPT_FUNCTION_MAXNAMELEN);
            chain_entry->ip.proto = IPPROTO_ICMP;
            break;
        case protocol::tcp:
            strncpy(match->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);
            chain_entry->ip.proto = IPPROTO_TCP;
            break;
        case protocol::udp:
            strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);
            chain_entry->ip.proto = IPPROTO_UDP;
            break;
    }
    
    //Парсим порты и добавляем информацию о них
    if(proto == protocol::tcp)
    {
        struct ipt_tcp* tcpinfo = (struct ipt_tcp *) match->data;
        ((struct ipt_tcp*)match->data)->spts[1] = ((struct ipt_tcp*)match->data)->dpts[1] = 0xFFFF;
        if(sport.min != 0 || sport.max != 0)
        {
            chain_entry->nfcache |= NFC_IP_SRC_PT;
            ((struct ipt_tcp*)match->data)->spts[0] = sport.min;
            ((struct ipt_tcp*)match->data)->spts[1] = sport.min;
        }
        if(dport.min != 0 || dport.max != 0)
        {
            chain_entry->nfcache |= NFC_IP_DST_PT;
            ((struct ipt_tcp*)match->data)->dpts[0] = dport.min;
            ((struct ipt_tcp*)match->data)->dpts[1] = dport.min;
        }
    }
    else if(proto == protocol::udp)
    {
        if(sport.min != 0 || sport.max != 0)
        {
            chain_entry->nfcache |= NFC_IP_SRC_PT;
            ((struct ipt_udp*)match->data)->spts[0] = sport.min;
            ((struct ipt_udp*)match->data)->spts[1] = sport.max;
        }
        if(dport.min != 0 || dport.max != 0)
        {
            chain_entry->nfcache |= NFC_IP_DST_PT;
            ((struct ipt_udp*)match->data)->dpts[0] = dport.min;
            ((struct ipt_udp*)match->data)->dpts[1] = dport.max;
        }
    }
    
    return match;
}

struct ipt_entry_target* IpTc::get_nat_target(string action, string action_params)
{
    //Высчитываем размер и выделяем память
    size_t size = XT_ALIGN(sizeof(struct ipt_entry_target)) + XT_ALIGN(sizeof(struct ip_nat_multi_range));
    struct ipt_entry_target* target = (struct ipt_entry_target *) calloc(1, size);
    target->u.target_size = size;
    
    //Заполняем имя
    memcpy(target->u.user.name, action.data(), action.size());
    
    //Парсим диапазон
    struct ip_nat_range range = parse_range(action_params);
    
    //Высчитываем новый размер и перевыделяем память
    size = XT_ALIGN(sizeof(struct ipt_natinfo) + ((struct ipt_natinfo*)target)->mr.rangesize * sizeof(struct ip_nat_range));
    struct ipt_natinfo *info = (struct ipt_natinfo *) realloc(target, size);
    
    //Заполняем структуру
    info->t.u.target_size = size;
    info->mr.range[info->mr.rangesize] = range;
    info->mr.rangesize++;
    
    return (struct ipt_entry_target*)info;
}

struct ip_nat_range IpTc::parse_range(string input)
{
    struct ip_nat_range range = {};
    
    char* buffer = &input[0];
    char* colon = strchr(buffer, ':');
    char *dash = NULL;
    if(colon)
    {
        range.flags |= IP_NAT_RANGE_PROTO_SPECIFIED;

        int port = atoi(colon + 1);
        dash = strchr(colon, '-');
        if (!dash)
            range.min.all = range.max.all = htons(port);
        else
        {
            int maxport = atoi(dash + 1);
            range.min.all = htons(port);
            range.max.all = htons(maxport);
        }
        
        *colon = '\0';
    }
    
    range.flags |= IP_NAT_RANGE_MAP_IPS;
    dash = strchr(buffer, '-');
    if (colon && dash && dash > colon)
        dash = NULL;
    if (dash)
        *dash = '\0';
    
    in_addr_t ip = inet_addr(buffer);
    range.min_ip = ip;
    if (dash)
    {
        ip = inet_addr(dash + 1);
        range.max_ip = ip;
    }
    else
        range.max_ip = range.min_ip;
    
    return range;
}

void IpTc::print_rules(string table, string chain)
{
    struct xtc_handle *h = iptc_init(table.data());
    if (!h)
    {
        printf("Failed to initialize %s table: %s\n", table.data(), iptc_strerror(errno));
        return;
    }
    if(!iptc_is_chain(chain.data(), h))
    {
        printf("No %s chain found\n", chain.data());
        return;
    }
    
    struct ipt_counters counters;
    printf("Policy: %s\n\n", iptc_get_policy(chain.data(), &counters, h));
    
    for(const ipt_entry *it = iptc_first_rule(chain.data(), h); it != NULL; it = iptc_next_rule(it, h))
    {
        printf("Rule:\n");
        
        printf("Counters: %llu:%llu\n", it->counters.pcnt, it->counters.bcnt);
        if(it->ip.src.s_addr != 0)
        {
            printf("Src ip: %s\n", inet_ntoa(it->ip.src));
            printf("Src mask: %s\n", inet_ntoa(it->ip.smsk));
        }
        if(it->ip.dst.s_addr != 0)
        {
            printf("Dst ip: %s\n", inet_ntoa(it->ip.dst));
            printf("Dst mask: %s\n", inet_ntoa(it->ip.dmsk));
        }
        if(it->ip.iniface[0] != 0)
            printf("In interface: %s\n", it->ip.iniface);
        if(it->ip.outiface[0] != 0)
            printf("Out interface: %s\n", it->ip.outiface);
        if(it->ip.proto != 0)
            printf("Proto: %d\n", it->ip.proto); //6 - tcp, 17 - udp, 1 - icmp
        if(it->ip.invflags != 0)                            //128  64   32 16  8   4   2   1
            printf("Inv flags: 0x%.2x\n", it->ip.invflags); // hz proto hz dst src hz out in
        
        const char *target = iptc_get_target(it, h);
        printf("Target: %s\n", target);
        
        if(it->target_offset)
        {
            for(unsigned int j = sizeof(struct ipt_entry); j < it->target_offset; )
            {
                struct xt_entry_match* match = (struct xt_entry_match *)((char *)it + j);
                
                printf("Match %s\n", match->u.user.name);
                if(strcmp(match->u.user.name, "conntrack") == 0)
                {
                    printf("Conntrack detected\n");
                    printf("Size: %d\n", match->u.user.match_size);
                    printf("Revision: %d\n", match->u.user.revision);
                    
                    const struct xt_conntrack_mtinfo3 *data = (const struct xt_conntrack_mtinfo3 *)match->data;
                    printf("%x\n", data->state_mask);// 8     4         2         1
                                                     //NEW RELATED ESTABLISHED INVALID
                }
                
                j += match->u.match_size;
            }
        }
        printf("\n\n");
    }
    
    printf("OK\n");
    iptc_free(h);
}