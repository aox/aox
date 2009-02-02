// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef AOXCOMMAND_H
#define AOXCOMMAND_H

#include "event.h"
#include "ustring.h"


class EStringList;


class AoxCommand
    : public EventHandler
{
public:
    AoxCommand( EStringList * );

    bool done() const;
    int status() const;

    static AoxCommand * create( EStringList * );

protected:
    EString next();
    EStringList * args();
    class Address * nextAsAddress();
    void setopt( char );
    uint opt( char );
    void parseOptions();
    void end();
    void database( bool = false );
    void error( const EString & );
    void finish( int = 0 );
    UString sqlPattern( const UString & );
    bool validUsername( const UString & );
    bool choresDone();
    EString readPassword( const EString & );
    EString readNewPassword();

private:
    class AoxCommandData * d;
};


#endif
