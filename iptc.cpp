#include "iptc.h"

using namespace std;

IpTc::IpTc()
{

}

IpTc::~IpTc()
{

}

int IpTc::add_rule(struct rule conditions)
{
	//TODO: Добавить правило
	return 0;
}

int IpTc::del_rule(struct rule conditions)
{
	//TODO: Удалить правило (и все его дубликаты, если имеются)
	return 0;
}

//TODO: Убрать костыль для компиляции
struct ipt_entry_match* get_osi4_match(protocol proto, struct range sport, struct range dport, unsigned int *nfcache);

int iptc_add_rule(struct rule conditions, string table, string chain, unsigned int index, const char *srcports, const char *destports, const char *target, const char *dnat_to, const int append)
{
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
    struct ipt_entry_match *entry_match = get_osi4_match(conditions.proto, conditions.sport, conditions.dport, &chain_entry->nfcache);
    
    //TODO: Заполняем target в зависимости от переданного значения
    struct ipt_entry_target* entry_target = NULL;
    /*if (strcmp(target, "") == 0 || strcmp(target, IPTC_LABEL_ACCEPT) == 0 || strcmp(target, IPTC_LABEL_DROP) == 0 || strcmp(target, IPTC_LABEL_QUEUE) == 0 || strcmp(target, IPTC_LABEL_RETURN) == 0)
    {
        size_t size = IPT_ALIGN(sizeof (struct ipt_entry_target)) + IPT_ALIGN(sizeof (int));
        struct ipt_entry_target* entry_target = (struct ipt_entry_target *) calloc(1, size);
        entry_target->u.user.target_size = size;
        strncpy(entry_target->u.user.name, target, IPT_FUNCTION_MAXNAMELEN);
    }
    else if (strcmp(target, "DNAT") == 0)
    {
        chain_entry->nfcache |= NFC_UNKNOWN;
        entry_target = get_nat_target(dnat_to, true);
    }
    else if (strcmp(target, "SNAT") == 0)
    {
        chain_entry->nfcache |= NFC_UNKNOWN;
        entry_target = get_nat_target(dnat_to, false);
    }
    else
    {
        printf("Unknown target\n");
        return;
    }*/
    
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
    if(iptc_insert_entry(labelit, chain_entry, index, h))
    {
        printf("Failed to add entry to netfilter: %s", iptc_strerror(errno));
        free(chain_entry);
        free(entry_target);
        if(entry_match)
            free(entry_match);
        iptc_free(h);
        return -1;
    }
    
    //Применяем внесенные изменения
    if (!iptc_commit(h)) {
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

struct ipt_entry_match* get_osi4_match(protocol proto, struct range sport, struct range dport, unsigned int *nfcache)
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
    		break;
    	case protocol::tcp:
    		strncpy(match->u.user.name, "tcp", IPT_FUNCTION_MAXNAMELEN);
    		break;
    	case protocol::udp:
    		strncpy(match->u.user.name, "udp", IPT_FUNCTION_MAXNAMELEN);
    		break;
    }
    
    //Парсим порты и добавляем информацию о них
    if(proto == protocol::tcp)
    {
    	struct ipt_tcp* tcpinfo = (struct ipt_tcp *) match->data;
    	((struct ipt_tcp*)match->data)->spts[1] = ((struct ipt_tcp*)match->data)->dpts[1] = 0xFFFF;
    	if(sport.min != 0 || sport.max != 0)
    	{
        	*nfcache |= NFC_IP_SRC_PT;
        	((struct ipt_tcp*)match->data)->spts[0] = sport.min;
        	((struct ipt_tcp*)match->data)->spts[1] = sport.min;
    	}
    	if(dport.min != 0 || dport.max != 0)
    	{
        	*nfcache |= NFC_IP_DST_PT;
        	((struct ipt_tcp*)match->data)->dpts[0] = dport.min;
        	((struct ipt_tcp*)match->data)->dpts[1] = dport.min;
    	}
    }
    else if(proto == protocol::udp)
    {
    	if(sport.min != 0 || sport.max != 0)
    	{
        	*nfcache |= NFC_IP_SRC_PT;
        	((struct ipt_udp*)match->data)->spts[0] = sport.min;
        	((struct ipt_udp*)match->data)->spts[1] = sport.max;
    	}
    	if(dport.min != 0 || dport.max != 0)
    	{
        	*nfcache |= NFC_IP_DST_PT;
        	((struct ipt_udp*)match->data)->dpts[0] = dport.min;
        	((struct ipt_udp*)match->data)->dpts[1] = dport.max;
    	}
    }

    return match;
}