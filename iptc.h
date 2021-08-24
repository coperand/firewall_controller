#pragma once

#include "structs.h"

class IpTc
{
public:
	IpTc();
	~IpTc();

	int add_rule(struct rule entry);
	int del_rule(struct rule entry);
};