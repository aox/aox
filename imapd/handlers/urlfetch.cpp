// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "urlfetch.h"

#include "list.h"
#include "imapurl.h"
#include "imapurlfetcher.h"
#include "stringlist.h"
#include "mailbox.h"
#include "user.h"


class UrlFetchData
    : public Garbage
{
public:
    UrlFetchData()
        : urls( 0 ), urlFetcher( 0 )
    {}

    List<ImapUrl> * urls;
    ImapUrlFetcher * urlFetcher;
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

        String s( astring() );
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
    if ( !d->urlFetcher ) {
        d->urlFetcher = new ImapUrlFetcher( d->urls, this );
        d->urlFetcher->execute();
    }

    if ( !d->urlFetcher->done() )
        return;

    if ( d->urlFetcher->failed() ) {
        error( No, d->urlFetcher->error() );
        return;
    }

    StringList l;
    List<ImapUrl>::Iterator it( d->urls );
    while ( it ) {
        l.append( imapQuoted( it->orig() ) );
        l.append( imapQuoted( it->text() ) );
        ++it;
    }

    respond( "URLFETCH " + l.join( " " ) );
    finish();
}
