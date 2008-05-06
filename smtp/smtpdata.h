// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPDATA_H
#define SMTPDATA_H

#include "smtpcommand.h"

#include "field.h"


class SmtpData
    : public SmtpCommand
{
public:
    SmtpData( SMTP *, SmtpParser * );

    void execute();

    class Message * message( const String & );

    void makeCopy() const;

    void checkField( HeaderField::Type );
    bool addressPermitted( Address * ) const;

private:
    class SmtpDataData * d;
};


class SmtpBdat
    : public SmtpData
{
public:
    SmtpBdat( SMTP *, SmtpParser * );

    void execute();

private:
    class SmtpBdatData * d;
};


class SmtpBurl
    : public SmtpData
{
public:
    SmtpBurl( SMTP *, SmtpParser * );

    void execute();

private:
    class SmtpBurlData * d;
};




#endif
