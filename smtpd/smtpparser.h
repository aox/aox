// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPPARSER_H
#define SMTPPARSER_H

#include "abnfparser.h"


class SmtpParser
    : public AbnfParser
{
public:
    SmtpParser( const String & );
};


#endif
