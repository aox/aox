// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "ace.h"

#include "punycode.h"
#include "ustring.h"


UString ACE::decode(const UString & input) {
    UString result;
    int n = 0;
    bool done = false;
    while ( !done ) {
        UString s = input.section( ".", n++ );
        done = s.isEmpty();
        if ( !done ) {
            if ( s.startsWith( "xn--" ) )
                s = Punycode::decode( s.mid( 4 ) );
            if ( !result.isEmpty() )
                result.append( "." );
            result.append( s );
        }
    }
    return result;
}
