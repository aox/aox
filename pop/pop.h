// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef POP_H
#define POP_H

#include "saslconnection.h"

#include "map.h"

class User;
class EString;
class Session;
class Message;


class POP
    : public SaslConnection
{
public:
    POP( int );

    enum State { Authorization, Transaction, Update };
    void setState( State );
    State state() const;

    virtual void setUser( User *, const EString & );

    void setSession( Session * );
    Session * session() const;

    class Message * message( uint );

    void parse();
    void react( Event );

    void runCommands();

    void ok( const EString & );
    void err( const EString & );
    void abort( const EString & );

    void setReserved( bool );
    void setReader( class PopCommand * );

    void markForDeletion( uint );
    void setMessageMap( Map<Message> * );

    void badUser();

    virtual void sendChallenge( const EString & );

    EString challenge() const;

private:
    class PopData *d;
};


class POPS
    : public POP
{
public:
    POPS( int );
};


#endif
