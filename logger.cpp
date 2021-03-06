#include "logger.h"

using namespace std;

Logger::Logger(map<unsigned int, struct event>* events, map<unsigned int, struct event>::iterator* events_it, uint8_t* audit_lvl, unsigned int threshold) : events{events}, events_it{events_it}, audit_lvl{audit_lvl},
                                                                                                                                                                threshold{threshold}
{
    //Проверяем, что необходимые для работы указатели заполнены
    if(!events)
        throw runtime_error("Events pointer is not spedified in Logger");
    if(!audit_lvl)
        throw runtime_error("Audit event pointer is not spedified in Logger");
}

Logger::~Logger()
{
    
}

void Logger::print(audit level, string message)
{
    //Пропускаем сообщения неподходящего уровня
    if((uint8_t)level > *audit_lvl)
        return;
    
    //Заполняем структуру с датой
    dateAndTime date;
    time_t t = time(NULL);
    struct tm *local = localtime(&t);
    date.year = htons(1900 + local->tm_year);
    date.month = local->tm_mon + 1;
    date.day = local->tm_mday;
    date.hour = local->tm_hour;
    date.minute = local->tm_min;
    date.second = local->tm_sec;
    
    //Добавляем в список
    unsigned int next = (events->rbegin() == events->rend()) ? 1 : (events->rbegin()->first + 1);
    (*events)[next] = {level, message, date};
    
    //Ротация данных
    if(events->size() > threshold)
    {
        while(events->size() > threshold / 2)
            events->erase(events->begin());
    }
    
    *events_it = events->end();
}