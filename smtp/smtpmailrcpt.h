// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPMAILRCPT_H
#define SMTPMAILRCPT_H

#include "smtpcommand.h"


class SmtpMailFrom
    : public SmtpCommand
{
public:
    SmtpMailFrom( SMTP *, SmtpParser * );

    void addParam( const String &, const String & );

    void execute();

private:
    class SmtpMailFromData * d;
};


class SmtpRcptTo
    : public SmtpCommand
{
public:
    SmtpRcptTo( SMTP *, SmtpParser * );

    void addParam( const String &, const String & );

    void execute();

    class Address * address() const;
    bool remote() const;

private:
    class SmtpRcptToData * d;
};




#endif
