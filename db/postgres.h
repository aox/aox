#ifndef POSTGRES_H
#define POSTGRES_H

#include "database.h"

class Row;


class Postgres
    : public Database
{
public:
    Postgres();
    ~Postgres();

    bool ready();
    void enqueue( class Query * );
    void execute();

    void react( Event e );

    static void updateSchema();

private:
    class PgData *d;

    void authentication( char );
    void backendStartup( char );
    void process( char );
    void unknown( char );
    void error( const String & );

    bool haveMessage();
    Row *composeRow( const class PgDataRow & );
    void processQueue( bool = false );
};


#endif
