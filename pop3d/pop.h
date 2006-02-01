// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POP_H
#define POP_H

#include "connection.h"

class User;
class String;
class Session;


class POP
    : public Connection
{
public:
    POP( int );

    enum State { Authorization, Transaction, Update };
    void setState( State );
    State state() const;

    void setUser( User * );
    User * user() const;

    void setSession( Session * );
    Session * session() const;

    void parse();
    void react( Event );

    void runCommands();

    void ok( const String & );
    void err( const String & );

    void setReserved( bool );
    void setReader( class PopCommand * );

    bool supports( const String & ) const;

    void markForDeletion( uint );

    static void setup();

private:
    class PopData *d;
};


#endif
