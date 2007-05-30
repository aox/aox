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

        // We want an authimapurlfull, which is an absolute URL that has
        // a URLAUTH component. We'll validate the access component when
        // we execute().
        String s( astring() );
        ImapUrl * url = new ImapUrl( s );
        if ( !url->valid() ) {
            // XXX: We're required to send a NIL URLFETCH response for
            // any valid URL that doesn't refer to a single message or
            // message section. But we can't do that, because we don't
            // even begin to know how to parse any such URL.
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
    if ( state() != Executing )
        return;

    if ( !d->urlFetcher ) {
        List<ImapUrl>::Iterator it( d->urls );
        while ( it ) {
            ImapUrl * u = it;

            // We verify that the currently logged in user meets the
            // access criteria specified in the URLAUTH component. We
            // leave the URLAUTH verification to ImapUrlFetcher.
            //
            // XXX: "smtpserver" is a blatant concession to the lemonade
            // interop event. We'll need to do something better later.
            String access( u->access() );
            if ( ( access.startsWith( "user+" ) &&
                   access != "user+" + imap()->user()->login() ) ||
                 ( access.startsWith( "submit+" ) &&
                   imap()->user()->login() != "smtpserver" ) )
            {
                error( Bad, "Invalid URL: " + u->orig() );
                return;
            }

            ++it;
        }

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
