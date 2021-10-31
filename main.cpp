#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "iptc.h"
#include "snmp_handler.h"
#include "core.h"

using namespace std;

bool work = true;
int frequency = 3, refresh = 5, threshold = 200;
char* path = NULL;
char default_path[] = "/tmp/fc_database.sqlite3";

void signal_handler(int sig)
{
    work = false;
}

void parse_args(int argc, char *argv[])
{
    char help_str[] =
    "Firewall controller\n"
    "Supported options:\n"
    "-h, --help                      Print help an exit\n"
    "-f, --freq <secs>               Set rules updating frequency (1-60)\n"
    "-p, --path <file>               Set path to the database file\n"
    "-r, --refresh <secs>            Set database refreshing frequency (1-60)\n"
    "-t, --threshold <quantity>      Set maximum audit events quantity (60-6000)\n";
    
    static struct option long_options[] =
    {
        {"help", no_argument, NULL, 'h'},
        {"freq", required_argument, NULL, 'f'},
        {"path", required_argument, NULL, 'p'},
        {"refresh", required_argument, NULL, 'r'},
        {"threshold", required_argument, NULL, 't'},
        {NULL, 0, NULL, 0}
    };
    
    int opt = -1;
    while((opt = getopt_long(argc, argv, "hf:p:r:t:", long_options, NULL)) != -1)
    {
        switch(opt)
        {
            case 'h':
            {
                printf("%s\n", help_str);
                exit(EXIT_SUCCESS);
            }
            case 'f':
            {
                frequency = atoi(optarg);
                break;
            }
            case 'p':
            {
                path = optarg;
                break;
            }
            case 'r':
            {
                refresh = atoi(optarg);
                break;
            }
            case 't':
            {
                threshold = atoi(optarg);
                break;
            }
        }
    }
    
    bool failed = false;
    if(frequency < 1 || frequency > 60)
    {
        printf("Wrong frequency value. Must be 1-60\n");
        failed = true;
    }
    if(path == NULL)
        path = default_path;
    if(refresh < 1 || refresh > 60)
    {
        printf("Wrong refresh value. Must be 1-60\n");
        failed = true;
    }
    if(threshold < 60 || threshold > 6000)
    {
        printf("Wrong refresh value. Must be 60-6000\n");
        failed = true;
    }
    if(failed)
        exit(EXIT_FAILURE);
}

pid_t start_program()
{
    pid_t pid = fork();
    if(!pid)
    {
        Core core(frequency, path, refresh, threshold);
        core.cycle();
    }
    
    return pid;
}

int main(int argc, char *argv[])
{
    if(geteuid() != 0)
    {
        printf("The program requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    parse_args(argc, argv);
    
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
