// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPAUTH_H
#define SMTPAUTH_H

#include "smtpcommand.h"


class SmtpAuth
    : public SmtpCommand
{
public:
    SmtpAuth( SMTP *, SmtpParser * );

    void execute();

private:
    class SmtpAuthData * d;
};




#endif
