#pragma once

#include <stdio.h>
#include <string.h>
#include <string>
#include <libiptc/libiptc.h>

#include "structs.h"

#define NFC_IP_SRC_PT		0x0200
#define NFC_IP_DST_PT		0x0400

class IpTc
{
public:
	IpTc();
	~IpTc();

	int add_rule(struct rule entry);
	int del_rule(struct rule entry);
};