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

    String challenge();
    void setChallenge( const String & );
    void readResponse( const String & );
    void verify();

    class Variable {
    public:
        String name;
        String value() const { return *values.first(); }
        bool unique() const  { return values.count() == 1; }
        bool operator !=( const String &s ) { return name != s; }
        List< String > values;
    };

    static bool parse( const String &s, List< Variable > &l );

private:
    class DigestData *d;

private:
    void require( class Variable *, const String & );
};


#endif
