// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POP_H
#define POP_H

#include "saslconnection.h"

class User;
class String;
class Session;


class POP
    : public SaslConnection
{
public:
    POP( int );

    enum State { Authorization, Transaction, Update };
    void setState( State );
    State state() const;

    virtual void setUser( User *, const String & );

    void setSession( Session * );
    Session * session() const;

    class Message * message( uint );

    void parse();
    void react( Event );

    void runCommands();

    void ok( const String & );
    void err( const String & );

    void setReserved( bool );
    void setReader( class PopCommand * );

    void markForDeletion( uint );

    void badUser();

    virtual void sendChallenge( const String & );

private:
    class PopData *d;
};


#endif
