// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OCCLIENT_H
#define OCCLIENT_H

#include "connection.h"

class String;


class OCClient
    : public Connection
{
public:
    OCClient( int );
    ~OCClient();

    void parse();
    void react( Event );

    static void setup();
    static void send( const String & );

private:
    void updateMailbox( const String & );

private:
    class OCCData *d;
};


#endif
