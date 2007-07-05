// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef AOXCOMMAND_H
#define AOXCOMMAND_H

#include "event.h"


class StringList;


class AoxCommand
    : public EventHandler
{
public:
    AoxCommand( StringList * );

    void waitFor( class Query * );

    bool done() const;
    int status() const;

    static AoxCommand * create( StringList * );

protected:
    String next();
    void setopt( char );
    uint opt( char );
    void parseOptions();
    void end();
    void database( bool = false );
    void error( const String & );
    void finish( int = 0 );
    String sqlPattern( const String & );
    bool validUsername( const String & );
    bool choresDone();

private:
    class AoxCommandData * d;
};


#endif
