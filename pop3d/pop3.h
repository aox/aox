// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POP3_H
#define POP3_H

#include "connection.h"

class String;


class POP3
    : public Connection
{
public:
    POP3( int );
    ~POP3();

    enum State { Authorization, Transaction, Update };
    void setState( State );
    State state() const;

    void parse();
    void react( Event );

private:
    class PopData *d;

    void ok( const String & );
    void err( const String & );
};


#endif
