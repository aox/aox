// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPCLIENT_H
#define SMTPCLIENT_H

#include "connection.h"
#include "event.h"


class String;
class Message;
class Address;


class SmtpClient
    : public Connection
{
public:
    SmtpClient( const String &, const String &, const String &,
                EventHandler * );
    SmtpClient( const Endpoint &, Message *,
                const String &, const String &,
                EventHandler * );

    void react( Event );

    bool done() const;
    bool failed() const;
    String error() const;
    bool permanentFailure() const;

private:
    class SmtpClientData * d;

    void parse();
    void sendCommand();

    static String dotted( const String & );
};


#endif
