// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SMTPPARSER_H
#define SMTPPARSER_H

#include "abnfparser.h"


class SmtpParser
    : public AbnfParser
{
public:
    SmtpParser( const EString & );

    EString command();

    void whitespace();

    EString domain();
    EString subDomain();

    class Address * address();

    EString dotString();
    EString quotedString();
    EString atom();

    EString esmtpKeyword();
    EString esmtpValue();
};


#endif
