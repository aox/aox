// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPPARSER_H
#define IMAPPARSER_H

#include "abnfparser.h"
#include "messageset.h"
#include "date.h"


class ImapParser
    : public AbnfParser
{
public:
    ImapParser( const String & );

    String firstLine();

    String tag();
    String command();
    uint nzNumber();
    void nil();
    String atom();
    String listChars();
    String quoted();
    String literal();
    String string();
    String nstring();
    String astring();
    String listMailbox();
    String flag();
    String dotLetters( uint, uint );
    Date dateTime();
};


#endif
