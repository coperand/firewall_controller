#pragma once

#include <stdint.h>
#include <string>

//Диапазон
struct range
{
    uint16_t min;
    uint16_t max;
};

enum class protocol: uint8_t
{
    none = 0,
    icmp = 1,
    tcp = 6,
    udp = 17
};

//Правило
struct rule
{
    //Ip-адреса
    uint32_t src_ip;
    uint32_t dst_ip;
    //Маски
    uint32_t src_mask;
    uint32_t dst_mask;
    //Интерфейсы
    std::string in_if;
    std::string out_if;
    //Протокол
    protocol proto;
    //Порты
    struct range sport;
    struct range dport;
    //Состояние
    uint8_t state;
    //Действие
    std::string action;
    std::string action_params;
    //Флаги инверсии (побитово)
    uint16_t inv_flags;
    
    bool validate(struct rule entry)
    {
        //TODO: Валидация экземпляра структуры
        return true;
    }
    
    //TODO: Подсчет хеша
};