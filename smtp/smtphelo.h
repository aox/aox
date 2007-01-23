// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPHELO_H
#define SMTPHELO_H

#include "smtpcommand.h"


class SmtpHelo
    : public SmtpCommand
{
public:
    enum Type{ Helo, Ehlo, Lhlo };

    SmtpHelo( SMTP *, SmtpParser *, Type );
};


#endif
