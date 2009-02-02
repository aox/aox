// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DIGESTMD5_H
#define DIGESTMD5_H

#include "mechanism.h"
#include "list.h"


class DigestMD5
    : public SaslMechanism
{
public:
    DigestMD5( EventHandler * );

    EString challenge();
    void setChallenge( const EString & );
    void parseResponse( const EString & );
    void verify();

    class Variable
        : public Garbage
    {
    public:
        EString name;
        EString value() const { return *values.first(); }
        bool unique() const  { return values.count() == 1; }
        bool operator !=( const EString &s ) { return name != s; }
        List< EString > values;
    };

    static bool parse( const EString &s, List< Variable > &l );

private:
    class DigestData *d;

private:
    void require( class Variable *, const EString & );
};


#endif
