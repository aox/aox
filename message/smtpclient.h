#ifndef SMTPCLIENT_H
#define SMTPCLIENT_H

#include "connection.h"


class Message;
class Address;


class SmtpClient: public Connection
{
public:
    SmtpClient( Message *, Address * );

    void react( Event );

private:
    void parse();
    void sendCommand();

    static String dotted( const String & );

private:
    class SmtpClientData * d;
};


#endif
