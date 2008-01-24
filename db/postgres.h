// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POSTGRES_H
#define POSTGRES_H

#include "database.h"


class Postgres
    : public Database
{
public:
    Postgres();
    ~Postgres();

    void processQueue();
    void react( Event );

    bool usable() const;

private:
    class PgData *d;

    void processQuery( class Query * );
    void authentication( char );
    void backendStartup( char );
    void process( char );
    void unknown( char );
    void serverMessage();
    void error( const String & );
    void shutdown();
    void countQueries( class Query * );
    String mapped( const String & ) const;
};


#endif
