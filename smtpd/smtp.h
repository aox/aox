#ifndef SMTP_H
#define SMTP_H

#include "connection.h"


class String;
class Command;
class Mailbox;
class Address;


class SMTP : public Connection {
public:
    SMTP( int s );
    ~SMTP();

    void react( Event e );

    void parse();

    virtual void helo();
    virtual void ehlo();
    virtual void lhlo();
    void rset();
    void mail();
    void rcpt();
    void data();
    void body( String & );
    virtual void noop();
    void help();
    void quit();
    void starttls();

    Address * address();
    void respond( int, const String & );
    void sendResponses();
    bool ok() const;
    bool rcptOk( Address * );
    void inject();
    virtual void reportInjection();

    enum State {
        Initial,
        MailFrom,
        RcptTo,
        Data,
        Body,
        Injecting
    };
    State state() const;

    void setHeloString();

private:
    class SMTPData * d;
    friend class LMTP;
};

class LMTP : public SMTP {
public:
    LMTP( int s );

    void helo();
    void ehlo();
    void lhlo();
    void reportInjection();
};

#endif
