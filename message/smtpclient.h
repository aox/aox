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
    ~SmtpClient();

    void react( Event );

    bool failed() const;

private:
    class SmtpClientData * d;

    void parse();
    void sendCommand();

    static String dotted( const String & );
};


#endif
