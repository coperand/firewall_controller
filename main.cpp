#include <stdio.h>
#include <unistd.h>

#include "iptc.h"
#include "snmp_handler.h"
#include "core.h"

using namespace std;

int main()
{
	if(geteuid() != 0)
	{
	    printf("The program requires root privileges\n");
	    exit(EXIT_FAILURE);
	}
	
	oid table_oid[] = {1, 3, 6, 1, 4, 1, 4, 199, 1};
	Core core(3, table_oid, sizeof(table_oid));
	
	core.cycle();
}
