// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OCSERVER_H
#define OCSERVER_H

#include "list.h"
#include "connection.h"

class String;


class OCServer
    : public Connection
{
public:
    OCServer( int );

    void parse();
    void react( Event );

    static void send( const String & );
    static List< OCServer > *connections();

private:
    class OCSData *d;
};


#endif
