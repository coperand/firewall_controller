#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "iptc.h"
#include "snmp_handler.h"
#include "core.h"

using namespace std;

bool work = true;

void signal_handler(int sig)
{
    work = false;
}

pid_t start_program()
{
    pid_t pid = fork();
    if(!pid)
    {
        oid table_oid[] = {1, 3, 6, 1, 4, 1, 4, 199, 1};
        Core core(3, table_oid, sizeof(table_oid), "test.db", 5);
    
        core.cycle();
    }
    
    return pid;
}

int main()
{
    if(geteuid() != 0)
    {
        printf("The program requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    
    pid_t pid = -1;
    while(work)
    {
        int status = 0;
        if(pid <= 0 || waitpid(pid, &status, WNOHANG) > 0)
            pid = start_program();
        
        sleep(1);
    }
    
    if(pid > 0)
        kill(pid, 9);
}
