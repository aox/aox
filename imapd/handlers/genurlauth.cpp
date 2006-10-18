// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "genurlauth.h"

#include "imapurl.h"
#include "list.h"


class GenUrlauthData
    : public Garbage
{
public:
    GenUrlauthData()
        : urls( 0 )
    {}

    List<ImapUrl> * urls;
};


/*! \class GenUrlauth genurlauth.h
    Implements the GENURLAUTH command specified in URLAUTH (RFC 4467).
*/

GenUrlauth::GenUrlauth()
    : d( new GenUrlauthData )
{
}


void GenUrlauth::parse()
{
    d->urls = new List<ImapUrl>;
    do {
        space();

        // XXX: We're assuming that the URL is just the next "word". How
        // can we do better? Give the ImapUrl a copy of our parser? What
        // about the p->end() assertion in ImapUrl::parse()?
        String s;
        char c = nextChar();
        while ( c != '\0' && c != ' ' ) {
            step();
            s.append( c );
            c = nextChar();
        }
        if ( s.isEmpty() ) {
            error( Bad, "Expected URL, but saw: " + following() );
            return;
        }

        space();
        if ( !present( "INTERNAL" ) ) {
            error( Bad, "Expected INTERNAL, but saw: " + following() );
            return;
        }

        ImapUrl * url = new ImapUrl( s );
        if ( !url->valid() ) {
            error( Bad, "Invalid URL: " + s );
            return;
        }

        d->urls->append( url );
    }
    while ( nextChar() == ' ' );
    end();
}


void GenUrlauth::execute()
{
    finish();
}
