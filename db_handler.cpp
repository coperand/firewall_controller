#include "db_handler.h"

using namespace std;

DbHandler::DbHandler(const char* path)
{
    //Подготавливаем объект для работы с бд
    if(sqlite3_open(path, &db))
         throw runtime_error(string("Failed to open database: ") + string(sqlite3_errmsg(db)));
    
    //Создание таблицы
    char *err = NULL;
    char query[] = "CREATE TABLE IF NOT EXISTS journal("
                 "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, "
                 "level INTEGER NOT NULL, "
                 "message TEXT NOT NULL, "
                 "year INTEGER NOT NULL, "
                 "month INTEGER NOT NULL, "
                 "day INTEGER NOT NULL, "
                 "hour INTEGER NOT NULL, "
                 "minute INTEGER NOT NULL, "
                 "second INTEGER NOT NULL, "
                 "second_part INTEGER NOT NULL);";
    if(sqlite3_exec(db, query, NULL, 0, &err) != SQLITE_OK)
        throw runtime_error(string("Failed to create SQL table 'journal': ") + string(err));
}

DbHandler::~DbHandler()
{
    //Завершаем работу с бд
    if(db)
        sqlite3_close(db);
}

int DbHandler::write_to_journal(map<unsigned int, struct event>& events)
{
    //Очищаем таблицу
    char *err = NULL;
    char flush_query[] = "DELETE FROM journal;";
    if(sqlite3_exec(db, flush_query, NULL, 0, &err) != SQLITE_OK)
    {
        printf("Failed to flush SQL table 'journal': %s\n", err);
        return -1;
    }
    
    //Записываес данные, обернув их в транзакцию
    string query = "BEGIN TRANSACTION; ";
    for(auto event : events)
    {
        char temp[255] = {};
        sprintf(temp, "INSERT INTO journal(level, message, year, month, day, hour, minute, second, second_part) VALUES(%u, '%s', %u, %u, %u, %u, %u, %u, %u); ", event.second.level, event.second.message.data(),
                                                                                                                                    event.second.time.year, event.second.time.month, event.second.time.day, event.second.time.hour,
                                                                                                                                    event.second.time.minute, event.second.time.second, event.second.time.second_part);
        query += string(temp);
    }
    query += "COMMIT;";
    if(sqlite3_exec(db, query.data(), NULL, 0, &err) != SQLITE_OK)
    {
        printf("Failed to insert data in SQL table 'journal': %s\n", err);
        return -1;
    }
    
    return 0;
}

map<unsigned int, struct event> DbHandler::read_from_journal()
{
    map<unsigned int, struct event> result = {};
    
    //Считываем данные из таблицы
    char *err = NULL;
    char query[] = "SELECT * FROM journal;";
    if(sqlite3_exec(db, query, read_journal_callback, &result, &err) != SQLITE_OK)
    {
        printf("Failed to read data from SQL table 'journal': %s\n", err);
        return result;
    }
    
    return result;
}

int DbHandler::read_journal_callback(void *data, int argc, char **argv, char **colName)
{
    map<unsigned int, struct event>* result = (map<unsigned int, struct event>*)data;
    
    struct event entry = {};
    for(int i = 0; i < argc; i++)
    {
        if(string(colName[i]) == string("id"))
            continue;
        else if(string(colName[i]) == string("level"))
            entry.level = atoi(argv[i]);
        else if(string(colName[i]) == string("message"))
            entry.message = string(argv[i]);
        else if(string(colName[i]) == string("year"))
            entry.time.year = atoi(argv[i]);
        else if(string(colName[i]) == string("month"))
            entry.time.month = atoi(argv[i]);
        else if(string(colName[i]) == string("day"))
            entry.time.day = atoi(argv[i]);
        else if(string(colName[i]) == string("hour"))
            entry.time.hour = atoi(argv[i]);
        else if(string(colName[i]) == string("minute"))
            entry.time.minute = atoi(argv[i]);
        else if(string(colName[i]) == string("second"))
            entry.time.second = atoi(argv[i]);
        else if(string(colName[i]) == string("second_part"))
            entry.time.second_part = atoi(argv[i]);
    }
    unsigned int next = (result->rbegin() == result->rend()) ? 1 : (result->rbegin()->first + 1);
    (*result)[next] = entry;
    
    return 0;
}
