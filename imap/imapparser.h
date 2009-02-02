// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPPARSER_H
#define IMAPPARSER_H

#include "abnfparser.h"
#include "integerset.h"


class ImapParser
    : public AbnfParser
{
public:
    ImapParser( const EString & );

    EString firstLine();

    EString tag();
    EString command();
    uint nzNumber();
    void nil();
    EString atom();
    EString listChars();
    EString quoted();
    EString literal();
    EString string();
    EString nstring();
    EString astring();
    EString listMailbox();
    EString flag();
    EString dotLetters( uint, uint );
};


#endif
