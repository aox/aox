// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DATABASE_H
#define DATABASE_H

#include "list.h"
#include "connection.h"

class Query;


class Database
    : public Connection
{
public:
    Database();

    enum Interface {
        Invalid, Pg
    };

    enum Type {
        Unknown, Boolean, Integer, Bytes
    };

    static String typeName( Type );

    static void setup();
    static Database *handle();

    virtual bool ready() = 0;
    virtual void enqueue( Query * ) = 0;
    virtual void execute() = 0;

    static void query( Query * );
    static void query( List< Query > * );

protected:
    static Interface interface();
    static String name();
    static String user();
    static String password();
    static Endpoint server();

    static void addHandle( Database * );
    static void removeHandle( Database * );
};


#endif
