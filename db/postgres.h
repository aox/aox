#ifndef POSTGRES_H
#define POSTGRES_H

#include "database.h"

class Row;


class Postgres
    : public Database
{
public:
    Postgres();

    bool ready();
    void submit( Query * );
    void prepare( PreparedStatement * );
    void react( Event e );

private:
    class PgData *d;

    void authentication( char );
    void backendStartup( char );
    void process( char );
    void unknown( char );
    void error( const String & );

    bool haveMessage();
    Row *composeRow( const class PgDataRow & );
    void processQuery( Query * );
};

#endif
