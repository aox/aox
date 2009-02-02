// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PARSER_H
#define PARSER_H

#include "estring.h"
#include "abnfparser.h"

class UString;


class EmailParser
    : public AbnfParser
{
public:
    EmailParser( const EString & os ) : AbnfParser( os ), mime( false ) {}

    void setMime( bool );
    bool isMime() const { return mime; }

    UString whitespace();

    EString comment();
    EString string();
    EString dotAtom();
    EString domain();
    EString atom();
    EString mimeToken();
    EString mimeValue();
    uint number();

    enum EncodedText { Text, Comment, Phrase };
    UString encodedWord( EncodedText = Text );
    UString encodedWords( EncodedText = Text );
    UString phrase();
    UString text();

    bool isAtext( char ) const;

    static UString de2047( const EString & );

    EString lastComment() const;

    int cfws();

    bool valid() { return error().isEmpty(); }

private:
    bool mime;
    EString lc;
};


#endif
