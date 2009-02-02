// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ABNFPARSER_H
#define ABNFPARSER_H

#include "global.h"
#include "estring.h"


class AbnfParser
    : public Garbage
{
public:
    AbnfParser( const EString & );
    virtual ~AbnfParser();

    bool ok() const;
    EString error() const;

    uint pos() const;
    EString input() const;

    char nextChar() const;
    void step( uint = 1 );
    bool present( const EString & );
    void require( const EString & );
    EString digits( uint, uint );
    EString letters( uint, uint );
    uint number();
    void end();
    const EString following() const;

    bool atEnd() const;

    uint mark();
    void restore();
    void restore( uint );

protected:
    EString str;

    void setError( const EString & );

private:
    class AbnfParserData * d;
};


#endif
