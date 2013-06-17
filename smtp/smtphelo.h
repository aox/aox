// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SMTPHELO_H
#define SMTPHELO_H

#include "smtpcommand.h"


class SmtpHelo
    : public SmtpCommand
{
public:
    enum Type{ Helo, Ehlo, Lhlo };

    SmtpHelo( SMTP *, SmtpParser *, Type );

    static void setUnicodeSupported( bool );
};


#endif
