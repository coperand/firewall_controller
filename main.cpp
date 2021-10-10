#include <stdio.h>

#include "iptc.h"
#include "snmp_handler.h"

using namespace std;

int main()
{
	IpTc iptc;
	struct rule conditions = {};
	conditions.src_ip = inet_addr("10.23.12.4");
	//conditions.dst_ip = inet_addr("10.23.12.25");
	conditions.src_mask = inet_addr("255.255.255.255");
	//conditions.dst_mask = inet_addr("255.255.255.255");
	conditions.proto = protocol::tcp;
	conditions.sport = {1025, 1025};
	//conditions.dport = {1026, 1026};
	conditions.state = 0x03;
	conditions.action = string("ACCEPT");
	//conditions.action_params = string("192.168.1.1-192.168.1.10:11");
	
	//iptc.add_rule(conditions, "filter", "FORWARD", 0);
	//iptc.del_rule(conditions, "filter", "FORWARD");
	//iptc.change_policy("filter", "FORWARD", 0);
	
	auto print_result = iptc.print_rules("filter", "FORWARD");
	auto container = print_result.first;
	printf("==========================\n");
	switch(print_result.second)
        {
            case 0:
                printf("Policy: DROP\n");
                break;
            case 1:
                printf("Policy: ACCEPT\n");
                break;
            default:
                printf("Unknown policy code - %u\n", print_result.second);
        }
        printf("==========================\n");
	for(auto item : container)
	{
	    printf("Rule: %s\n", item.second.action.data());
	    if(item.second.action_params.size() > 0)
	        printf("Params: %s\n", item.second.action_params.data());
	    
	    struct in_addr ip = {};
	    if(item.second.src_ip != 0)
	    {
	        ip.s_addr = item.second.src_ip;
	        printf("Src ip: %s\n", inet_ntoa(ip));
	    }
	    if(item.second.src_mask != 0)
	    {
	        ip.s_addr = item.second.src_mask;
	        printf("Src mask: %s\n", inet_ntoa(ip));
	    }
	    
	    if(item.second.dst_ip != 0)
	    {
	        ip.s_addr = item.second.dst_ip;
	        printf("Dst ip: %s\n", inet_ntoa(ip));
	    }
	    if(item.second.dst_mask != 0)
	    {
	        ip.s_addr = item.second.dst_mask;
	        printf("Dst mask: %s\n", inet_ntoa(ip));
	    }
	    
	    if(item.second.in_if.size() != 0)
	        printf("In interface: %s\n", item.second.in_if.data());
	    if(item.second.in_if.size() != 0)
	        printf("Out interface: %s\n", item.second.out_if.data());
	    
	    switch(item.second.proto)
	    {
	        case protocol::icmp:
	            printf("Icmp protocol\n");
	            break;
	        case protocol::tcp:
	            printf("Tcp protocol\n");
	            break;
	        case protocol::udp:
	            printf("Udp protocol\n");
	            break;
	        default:
	            break;
	    }
	    
	    if(item.second.sport.min != 0 || item.second.sport.max != 0)
	    {
	        printf("Sport min: %u\n", item.second.sport.min);
	        printf("Sport max: %u\n", item.second.sport.max);
	    }
	    if(item.second.dport.min != 0 || item.second.dport.max != 0)
	    {
	        printf("Sport min: %u\n", item.second.dport.min);
	        printf("Sport max: %u\n", item.second.dport.max);
	    }
	    
	    if(item.second.state != 0)
	    {
	        printf("State(s): ");
	        if(item.second.state & 0x01 != 0)
	            printf("Invalid ");
	        if((item.second.state >> 1) & 0x01 != 0)
	            printf("Established ");
	        if((item.second.state >> 2) & 0x01 != 0)
	            printf("Related ");
	        if((item.second.state >> 3) & 0x01 != 0)
	            printf("New ");
	        printf("\n");
	    }
	    
	    printf("InvFlags: 0x%.2x\n", item.second.inv_flags);
	    
	    printf("\n");
	}
	
	//================================================
	
	/*oid filter_forward_oid[] = {1, 3, 6, 1, 4, 1, 4, 199, 1, 1};
	//oid filter_input_oid[] = {1, 3, 6, 1, 4, 1, 4, 199, 1, 2};
	SnmpHandler snmp1(filter_forward_oid, sizeof(filter_forward_oid), "filterForwardTable");
	//SnmpHandler snmp2(filter_input_oid, sizeof(filter_input_oid), "filterInputTable");
	
	while(1)
	{
	    while(agent_check_and_process(0));
	    usleep(500);
	}*/
}
