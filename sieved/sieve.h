// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVE_H
#define SIEVE_H

#include "connection.h"

class User;
class String;


class Sieve
    : public Connection
{
public:
    Sieve( int );

    enum State { Unauthorised, Authorised };
    void setState( State );
    State state() const;

    void setUser( User * );
    User * user() const;

    void parse();
    void react( Event );

    void runCommands();

    void ok( const String & );
    void no( const String & );
    void send( const String & );

    void setReserved( bool );
    void setReader( class SieveCommand * );

    bool supports( const String & ) const;

    void capabilities();

    static void setup();

private:
    class SieveData *d;
};


#endif
