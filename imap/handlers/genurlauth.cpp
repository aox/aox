// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "genurlauth.h"

#include "md5.h"
#include "list.h"
#include "query.h"
#include "imapurl.h"
#include "estringlist.h"
#include "configuration.h"
#include "transaction.h"
#include "entropy.h"
#include "mailbox.h"
#include "user.h"


struct UrlKey
    : public Garbage
{
    UrlKey( ImapUrl * u )
        : q( 0 ), url( u ), mailbox( 0 )
    {}

    Query * q;
    EString key;
    ImapUrl * url;
    Mailbox * mailbox;
};


class GenUrlauthData
    : public Garbage
{
public:
    GenUrlauthData()
        : state( 0 ), urlKeys( 0 )
    {}

    uint state;
    List<UrlKey> * urlKeys;
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
    d->urlKeys = new List<UrlKey>;
    do {
        space();

        EString s( astring() );
        ImapUrl * url = new ImapUrl( s );
        if ( !url->valid() ) {
            error( Bad, "Invalid URL: " + s );
            return;
        }
        space();
        if ( !present( "INTERNAL" ) ) {
            error( Bad, "Expected INTERNAL, but saw: " + following() );
            return;
        }

        d->urlKeys->append( new UrlKey( url ) );
    }
    while ( nextChar() == ' ' );
    end();
}


void GenUrlauth::execute()
{
    if ( d->state == 0 ) {
        uint port = Configuration::scalar( Configuration::ImapPort );

        List<UrlKey>::Iterator it( d->urlKeys );
        while ( it ) {
            ImapUrl * u = it->url;
            Mailbox * m = imap()->user()->mailbox( u->mailboxName() );

            // XXX: We don't return an invalid URLAUTH token for invalid
            // userids; in fact, we don't even bother to verify that any
            // userid specified in "access" is valid.

            if ( u->user()->login() != imap()->user()->login() ||
                 !( u->host().lower() == Configuration::hostname().lower() &&
                    u->port() == port ) ||
                 !m || !u->isRump() )
            {
                error( Bad, "Invalid URL" );
                return;
            }

            it->mailbox = m;

            ++it;
        }

        d->state = 1;
    }

    if ( d->state == 1 ) {
        setTransaction( new Transaction( this ) );

        Query * q = new Query( "lock access_keys in exclusive mode", this );
        transaction()->enqueue( q );

        List<UrlKey>::Iterator it( d->urlKeys );
        while ( it ) {
            it->q = new Query( "select key from access_keys where userid=$1 "
                               "and mailbox=$2", this );
            it->q->bind( 1, imap()->user()->id() );
            it->q->bind( 2, it->mailbox->id() );
            transaction()->enqueue( it->q );
            ++it;
        }

        transaction()->execute();
        d->state = 2;
    }

    if ( d->state == 2 ) {
        List<UrlKey>::Iterator it( d->urlKeys );
        while ( it ) {
            Query * q = it->q;

            if ( !q->done() )
                return;

            if ( q->hasResults() ) {
                Row * r = q->nextRow();
                it->key = r->getEString( "key" );
            }
            else if ( q->rows() == 0 ) {
                it->key = Entropy::asString( 16 ).e64();
                q = new Query( "insert into access_keys "
                               "(userid,mailbox,key) values ($1,$2,$3)",
                               this );
                q->bind( 1, imap()->user()->id() );
                q->bind( 2, it->mailbox->id() );
                q->bind( 3, it->key );
                transaction()->enqueue( q );
            }

            ++it;
        }

        transaction()->commit();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !transaction()->done() )
            return;

        if ( transaction()->failed() ) {
            error( No, "Database error: " + transaction()->error() );
            return;
        }

        EStringList l;
        List<UrlKey>::Iterator it( d->urlKeys );
        while ( it ) {
            EString orig( it->url->orig() );
            EString u( orig );
            u.append( ":internal:0" );
            u.append( MD5::HMAC( it->key.de64(), orig ).hex() );
            l.append( imapQuoted( u ) );
            ++it;
        }

        respond( "GENURLAUTH " + l.join( " " ) );
    }

    finish();
}
