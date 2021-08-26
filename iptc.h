#pragma once

#include <stdio.h>
#include <string.h>
#include <string>
#include <libiptc/libiptc.h>

#include "structs.h"

class IpTc
{
public:
	IpTc();
	~IpTc();

	int add_rule(struct rule entry);
	int del_rule(struct rule entry);
};