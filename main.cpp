#include <stdio.h>

//#include "iptc.h"
#include "snmp_handler.h"

using namespace std;

int main()
{
	/*IpTc iptc;
	struct rule conditions = {};
	conditions.src_ip = inet_addr("10.23.12.4");
	//conditions.dst_ip = inet_addr("10.23.12.25");
	conditions.src_mask = inet_addr("255.255.255.255");
	conditions.dst_mask = inet_addr("255.255.255.255");
	conditions.proto = protocol::udp;
	//conditions.sport = {1025, 1025};
	//conditions.dport = {1026, 1026};
	conditions.action = string("DNAT");
	conditions.action_params = string("192.168.1.1-192.168.1.10");

	//iptc.add_rule(conditions, "nat", "PREROUTING", 0);
	iptc.del_rule(conditions, "nat", "PREROUTING");*/
	
	//================================================
	
	SnmpHandler snmp;
	
	while(1)
	{
	    while(agent_check_and_process(0));
	    usleep(500);
	}
}