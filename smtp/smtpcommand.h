// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
    bool ok() const;

    void finish();

    void respond( uint, const EString &, const char * = 0 );
    void emitResponses();

    void execute();

    static SmtpCommand * create( SMTP *, const EString & );

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
    bool startedTls;
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
