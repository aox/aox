#ifndef SMTPCLIENT_H
#define SMTPCLIENT_H

#include "connection.h"


class Message;
class Address;


class SmtpClient
    : public Connection
{
public:
    SmtpClient( Message *, Address * );
    ~SmtpClient();

    void react( Event );

private:
    class SmtpClientData * d;

    void parse();
    void sendCommand();

    static String dotted( const String & );
};


#endif
