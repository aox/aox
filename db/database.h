#ifndef DATABASE_H
#define DATABASE_H

#include "connection.h"

class Query;
class String;
class Endpoint;
class Transaction;
class PreparedStatement;


class Database
    : public Connection
{
public:
    Database();

    enum Type {
        Unknown, Boolean, Character, Integer, Varchar
    };

    static void setup();
    static Database * handle();
    static void query( Query * );

    virtual bool ready() = 0;
    virtual void prepare( PreparedStatement * ) = 0;
    virtual void submit( Query * ) = 0;

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
