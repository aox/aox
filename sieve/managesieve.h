// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MANAGESIEVE_H
#define MANAGESIEVE_H

#include "saslconnection.h"

class User;
class EString;


class ManageSieve
    : public SaslConnection
{
public:
    ManageSieve( int );

    enum State { Unauthorised, Authorised };
    void setState( State );
    State state() const;

    void parse();
    void react( Event );

    void runCommands();

    void ok( const EString & );
    void no( const EString & );
    void send( const EString & );

    void setReserved( bool );
    void setReader( class ManageSieveCommand * );

    void capabilities();

    virtual void sendChallenge( const EString & );

private:
    class ManageSieveData *d;

    void addCommand();
};


#endif
