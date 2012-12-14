// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
    EString uquoted();
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
