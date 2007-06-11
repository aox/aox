// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPCLIENT_H
#define SMTPCLIENT_H

#include "connection.h"
#include "event.h"


class String;
class Message;
class Address;
class Recipient;


class SmtpClient
    : public Connection
{
public:
    SmtpClient( const Endpoint &, EventHandler * );

    void react( Event );

    bool ready() const;
    void send( Address *, List<Recipient> *, const String &, EventHandler * );

private:
    class SmtpClientData * d;

    void parse();
    void sendCommand();
    void handleFailure( const String &, bool );
    void finish();
    void recordExtension( const String & );

    static String dotted( const String & );
};


#endif
