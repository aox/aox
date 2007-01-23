// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPCOMMAND_H
#define SMTPCOMMAND_H

#include "event.h"


class SmtpParser;


class SmtpCommand
    : public EventHandler
{
public:
    SmtpCommand( class SMTP * );

    bool done() const;
    String response() const;
    bool ok() const;

    void finish();

    void respond( uint, const String & );

    void execute();

    static SmtpCommand * create( SMTP *, const String & );

    SMTP * server() const;

private:
    class SmtpCommandData * d;
};


class SmtpRset
    : public SmtpCommand
{
public:
    SmtpRset( SMTP *, SmtpParser * );

    void execute();
};


class SmtpNoop
    : public SmtpCommand
{
public:
    SmtpNoop( SMTP *, SmtpParser * );
};


class SmtpHelp
    : public SmtpCommand
{
public:
    SmtpHelp( SMTP *, SmtpParser * );
};


class SmtpStarttls
    : public SmtpCommand
{
public:
    SmtpStarttls( SMTP *, SmtpParser * );

    void execute();

private:
    class TlsServer * tlsServer;
};


class SmtpQuit
    : public SmtpCommand
{
public:
    SmtpQuit( SMTP *, SmtpParser * );

    void execute();
};


#endif
