// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DATABASE_H
#define DATABASE_H

#include "list.h"
#include "connection.h"
#include "configuration.h"


class Query;


class Database
    : public Connection
{
public:
    Database();

    enum User {
        Superuser, DbOwner, DbUser
    };

    enum State {
        Connecting, Idle, InTransaction, FailedTransaction, Broken
    };

    static void setup( int = 0, Database::User = DbUser );
    static void setup( int, const String &, const String & );
    static void submit( Query * );
    static void submit( List< Query > * );
    static void disconnect();

    virtual void processQueue() = 0;

    virtual bool usable() const;

    static uint numHandles();
    static uint handlesNeeded();
    static String type();

    uint connectionNumber() const;

    static uint currentRevision();

    static void checkSchema( class EventHandler * );
    static void checkAccess( class EventHandler * );

    static void notifyWhenIdle( class EventHandler * );
    static bool idle();

protected:
    static List< Query > *queries;

    void setState( State );
    State state() const;

    static void runQueue();

    static void addHandle( Database * );
    static void removeHandle( Database * );

    static Endpoint server();
    static String address();
    static uint port();

    static String name();
    static String user();
    static String password();
    static User loginAs();

    static void recordExecution();
    static void reactToIdleness();

private:
    State st;
    uint number;
};


#endif
