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

    enum State { Connecting, Idle, InTransaction, FailedTransaction };

    static void setup();
    static void submit( Query * );
    static void submit( List< Query > * );

    virtual void processQueue() = 0;

    static uint numHandles();

protected:
    static List< Query > *queries;

    void setState( State );
    State state() const;

    static void runQueue();

    static void addHandle( Database * );
    static void removeHandle( Database * );

    static Endpoint server();
    static String name();
    static String user();
    static String password();

private:
    State st;
};


#endif
