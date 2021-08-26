#include <stdio.h>

#include "iptc.h"

using namespace std;

int main()
{
	IpTc iptc;
	struct rule conditions = {};
	conditions.src_ip = inet_addr("10.23.12.4");
	conditions.dst_ip = inet_addr("10.23.12.25");;
	conditions.src_mask = inet_addr("255.255.255.0");
	conditions.dst_mask = inet_addr("255.255.255.0");
	conditions.proto = protocol::tcp;
	conditions.sport = {1025, 1025};
	conditions.dport = {1026, 1026};
	conditions.action = string("ACCEPT");

	iptc.add_rule(conditions, "filter", "FORWARD", 0);
}