// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "subscribe.h"

#include "imap.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"


/*! \class Subscribe subscribe.h
    Adds a mailbox to the subscription list (RFC 3501 section 6.3.6)
*/

Subscribe::Subscribe()
    : q( 0 ), m( 0 )
{}


/*! \class Unsubscribe subscribe.h
    Removes a mailbox from the subscription list (RFC 3501 section 6.3.7)
*/

Unsubscribe::Unsubscribe()
    : Command(), q( 0 )
{
}


void Subscribe::parse()
{
    space();
    m = mailbox();
    end();
    if ( ok() )
        log( "Subscribe " + m->name().ascii() );
}


void Subscribe::execute()
{
    if ( state() != Executing )
        return;

    if ( m->deleted() )
        error( No, "Cannot subscribe to deleted mailbox" );
    else if ( m->synthetic() )
        error( No, "Cannot subscribe to synthetic mailbox" );

    requireRight( m, Permissions::Lookup );

    if ( !ok() || !permitted() )
        return;

    if ( !q ) {
        // this query has a race: the select can return an empty set
        // while someone else is running the same query, then the
        // insert fails because of the 'unique' constraint. the db is
        // still valid, so the race only leads to an unnecessary error
        // in the pg log file.
        q = new Query( "insert into subscriptions (owner, mailbox) "
                       "select $1, $2 where not exists "
                       "(select owner, mailbox from subscriptions"
                       " where owner=$1 and mailbox=$2)", this );
        q->bind( 1, imap()->user()->id() );
        q->bind( 2, m->id() );
        q->canFail();
        q->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() )
        log( "Ignoring duplicate subscription" );
    finish();
}


void Unsubscribe::parse()
{
    space();
    n = mailboxName();
    end();
    if ( ok() )
        log( "Unsubscribe " + n.ascii() );
}


void Unsubscribe::execute()
{
    if ( !q ) {
        UString c = imap()->user()->mailboxName( n );
        Mailbox * m = Mailbox::find( c, true );
        if ( !m ) {
            finish();
            return;
        }
        else if ( !m->id() ) {
            finish();
            return;
        }
        q = new Query( "delete from subscriptions "
                       "where owner=$1 and mailbox=$2", this );
        q->bind( 1, imap()->user()->id() );
        q->bind( 2, m->id() );
        q->execute();
    }

    if ( q && !q->done() )
        return;

    finish();
}
