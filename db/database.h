#ifndef DATABASE_H
#define DATABASE_H

#include "connection.h"

class Query;


class Database
    : public Connection
{
public:
    Database();

    enum Type {
        Unknown, Boolean, Character, Integer, Varchar
    };

    static void setup();
    static Database *handle();

    virtual bool ready() = 0;
    virtual void enqueue( Query * ) = 0;
    virtual void execute() = 0;

    static void query( Query * );

protected:
    static String type();
    static String name();
    static String user();
    static String password();
    static Endpoint server();

    static void addHandle( Database * );
    static void removeHandle( Database * );
};


#endif
