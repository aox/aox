// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "urlfetch.h"

#include "imapurl.h"
#include "list.h"


class UrlFetchData
    : public Garbage
{
public:
    UrlFetchData()
        : urls( 0 )
    {}

    List<ImapUrl> * urls;
};


/*! \class UrlFetch urlfetch.h
    Implements the URLFETCH command specified in URLAUTH (RFC 4467).
*/

UrlFetch::UrlFetch()
    : d( new UrlFetchData )
{
}


void UrlFetch::parse()
{
    d->urls = new List<ImapUrl>;
    do {
        space();

        String s;
        char c = nextChar();
        while ( c != '\0' && c != ' ' ) {
            step();
            s.append( c );
            c = nextChar();
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


void UrlFetch::execute()
{
    finish();
}
