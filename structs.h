#pragma once

#include <stdint.h>
#include <string>

//Диапазон
struct range
{
    uint16_t min;
    uint16_t max;
};

//Возможные значения протокола
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
    std::string action = {};
    std::string action_params = {};
    //Флаги инверсии (побитово)
    uint16_t inv_flags = 0x1000;
};

//Структура для хранения даты/времени в формате SNMP
struct dateAndTime
{
    uint16_t year = 0;
    uint8_t month = 0;
    uint8_t day = 0;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;
    uint8_t second_part = 0;
};

//Возможные значения уровня аудита
enum class audit: uint8_t
{
    none = 0,
    error = 1,
    info = 6
};

//Структура события аудита
struct event
{
    audit level = audit::none;
    std::string message = {};
    dateAndTime time = {};
};
