// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SMTPMAILRCPT_H
#define SMTPMAILRCPT_H

#include "smtpcommand.h"


class SmtpMailFrom
    : public SmtpCommand
{
public:
    SmtpMailFrom( SMTP *, SmtpParser * );

    void addParam( const EString &, const EString & );

    void execute();

private:
    class SmtpMailFromData * d;
};


class SmtpRcptTo
    : public SmtpCommand
{
public:
    SmtpRcptTo( SMTP *, SmtpParser * );

    void addParam( const EString &, const EString & );

    void execute();

    class Address * address() const;
    bool remote() const;

private:
    class SmtpRcptToData * d;
};




#endif
