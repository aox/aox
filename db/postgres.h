// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POSTGRES_H
#define POSTGRES_H

#include "database.h"

class Query;


class Postgres
    : public Database
{
public:
    Postgres();
    ~Postgres();

    void processQueue();
    void react( Event );

    bool usable() const;

    bool blocked( const class Transaction * ) const;

    static uint version();

    static void sendListen();

    void cancel( Query * );

private:
    class PgData *d;

    List< Query > * activeQueries() const;

    void processQuery( Query * );
    void authentication( char );
    void backendStartup( char );
    void process( char );
    void unknown( char );
    void serverMessage();
    void error( const EString & );
    void shutdown();
    void countQueries( Query * );
    EString queryString( Query * );
    EString mapped( const EString & ) const;
};


#endif
