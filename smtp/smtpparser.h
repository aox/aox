// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPPARSER_H
#define SMTPPARSER_H

#include "abnfparser.h"


class SmtpParser
    : public AbnfParser
{
public:
    SmtpParser( const String & );

    String command();

    void whitespace();

    String domain();
    String subDomain();

    class Address * address();

    String dotString();
    String quotedString();
    String atom();

    String esmtpParam();
    String esmtpValue();
};


#endif
