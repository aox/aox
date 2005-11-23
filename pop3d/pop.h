// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POP_H
#define POP_H

#include "connection.h"

class String;


class POP
    : public Connection
{
public:
    POP( int );

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
