// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PARSER_H
#define PARSER_H

#include "string.h"
#include "abnfparser.h"

class UString;


class Parser822
    : public AbnfParser
{
public:
    Parser822( const String & os ) : AbnfParser( os ), mime( false ) {}
    
    void setMime( bool );
    bool isMime() const { return mime; }

    UString whitespace();

    String comment();
    String string();
    String dotAtom();
    String domain();
    String atom();
    String mimeToken();
    String mimeValue();
    uint number();

    enum EncodedText { Text, Comment, Phrase };
    UString encodedWord( EncodedText = Text );
    UString encodedWords( EncodedText = Text );
    UString phrase();
    UString text();

    bool isAtext( char ) const;

    static UString de2047( const String & );

    String lastComment() const;

    int cfws();

    bool valid() { return error().isEmpty(); }

private:
    bool mime;
    String lc;
};


#endif
