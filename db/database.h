// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    enum User {
        Superuser, DbOwner, DbUser
    };

    enum State {
        Connecting, Idle, InTransaction, FailedTransaction, Broken
    };

    static void setup( uint = 0, Database::User = DbUser );
    static void setup( uint, const EString &, const EString & );
    static void submit( Query * );
    static void submit( List< Query > * );
    static void disconnect();

    virtual void processQueue() = 0;

    virtual bool usable() const;

    static uint numHandles();
    static uint handlesNeeded();
    static uint idleHandles();
    static EString type();

    uint connectionNumber() const;

    static uint currentRevision();

    static void checkSchema( class EventHandler * );
    static void checkAccess( class EventHandler * );

    static void notifyWhenIdle( class EventHandler * );
    static bool idle();

    virtual void cancel( Query * ) = 0;

    static void cancelQuery( Query * );

protected:
    static List< Query > *queries;

    List< Query > * firstSubmittedQuery( bool transactionOK );

    void setState( State );
    State state() const;

    static void runQueue();

    static void addHandle( Database * );
    static void removeHandle( Database * );

    static Endpoint server();
    static EString address();
    static uint port();

    static EString name();
    static EString user();
    static EString password();
    static User loginAs();

    static void recordExecution();
    static void reactToIdleness();

private:
    State st;
    uint number;
};


#endif
