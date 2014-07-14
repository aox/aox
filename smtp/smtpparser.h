// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SMTPPARSER_H
#define SMTPPARSER_H

#include "abnfparser.h"

#include "ustring.h"


class SmtpParser
    : public AbnfParser
{
public:
    SmtpParser( const EString & );

    EString command();

    void whitespace();

    UString domain();
    UString subDomain();

    class Address * address();

    UString dotString();
    UString quotedString();
    UString atom();

    EString esmtpKeyword();
    EString esmtpValue();
};


#endif
