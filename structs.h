#pragma once

#include <stdint.h>
#include <string>

//Диапазон
struct range
{
    uint16_t min;
    uint16_t max;
};

//Вохможные значения протокола
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
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    //Маски
    uint32_t src_mask = 0;
    uint32_t dst_mask = 0;
    //Интерфейсы
    std::string in_if = {};
    std::string out_if = {};
    //Протокол
    protocol proto = protocol::none;
    //Порты
    struct range sport = {0, 0};
    struct range dport = {0, 0};
    //Состояние
    uint8_t state = 0;
    //Действие
    std::string action;
    std::string action_params;
    //Флаги инверсии (побитово)
    uint16_t inv_flags = 0x1000;
};