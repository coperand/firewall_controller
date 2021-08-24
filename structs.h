#pragma once

#include <stdint.h>
#include <string>

struct range
{
	uint16_t min;
	uint16_t max;
};

struct rule
{
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t src_mask;
	uint8_t dst_mask;
	std::string in_if;
	std::string out_if;
	struct range sport;
	struct range dport;
	std::string action;
	std::string action_params;
	uint8_t inv_flags;

	bool validate(struct rule entry)
	{
		//TODO: Валидация экземпляра структуры
		return true;
	}

	//TODO: Подсчет хеша
};