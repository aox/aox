// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
