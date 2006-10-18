// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "expunge.h"

#include "flag.h"
#include "imap.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "mailbox.h"
#include "imapsession.h"
#include "permissions.h"
#include "messageset.h"


class ExpungeData
    : public Garbage
{
public:
    ExpungeData()
        : uid( false ), s( 0 ), q( 0 ), e( 0 )
    {}

    bool uid;
    Session * s;
    Query * q;
    Query * e;
    MessageSet uids;
};


/*! \class Expunge expunge.h
    This command is responsible for removing "\Deleted" messages.

    It implements EXPUNGE, as specified in RFC 3501 section 6.4.3 and
    UID EXPUNGE, as specified in RFC 2359 section 4.1, and helps
    Close.

    RFC 2180 discusses expunging in situations where multiple users
    may access the mailbox. Our present approach is to delete the
    message early, so that when we tell the expunging client that a
    message is gone, it really is. Seems advisable from a
    confidentiality point of view.

    The UID of an expunged message may still exist in different
    sessions, although the message itself is no longer accessible.
*/

/*! Creates a new EXPUNGE handler if \a u is false, or a UID EXPUNGE
    handler if it is true.
*/

Expunge::Expunge( bool u )
    : d( new ExpungeData )
{
    d->uid = u;
}


void Expunge::parse()
{
    if ( d->uid ) {
        space();
        d->uids = set( false );
        shrink( &d->uids );
    }
    end();
}


/*! This function expunges the current mailbox, emitting EXPUNGE
    responses if \a chat is true and being silent if \a chat is false.

    It returns true if the job was done, and false if it needs to be
    called again.
*/

bool Expunge::expunge( bool chat )
{
    if ( !d->s ) {
        d->s = imap()->session();
        if ( !d->s || !d->s->mailbox() ) {
            error( No, "No mailbox to expunge" );
            return true;
        }
        requireRight( d->s->mailbox(), Permissions::Expunge );
    }

    if ( !d->q ) {
        if ( !permitted() )
            return !ok();

        Flag * f = Flag::find( "\\deleted" );
        if ( !f ) {
            error( No, "Internal error - no \\Deleted flag" );
            return true;
        }

        String query( "select uid from flags left join deleted_messages dm "
                      "using (mailbox,uid) where mailbox=$1 and flag=$2 and "
                      "dm.uid is null" );
        if ( d->uid )
            query.append( " and (" + d->uids.where() + ")" );

        d->q = new Query( query, this );
        d->q->bind( 1, d->s->mailbox()->id() );
        d->q->bind( 2, f->id() );
        d->q->execute();
        d->uids.clear();
    }

    Row * r;
    while ( ( r = d->q->nextRow() ) != 0 ) {
        uint n = r->getInt( "uid" );
        d->uids.add( n );
    }
    if ( !d->q->done() )
        return false;
    if ( d->uids.isEmpty() )
        return true;
       
    if ( !d->e ) {
        log( "Expunge " + fn( d->uids.count() ) + " messages" );
        d->e = new Query( "insert into deleted_messages "
                          "(mailbox, uid, deleted_by, reason) "
                          "select mailbox, uid, $2, $3 "
                          "from messages where mailbox=$1 and "
                          "(" + d->uids.where() + ")",
                          this );
        d->e->bind( 1, d->s->mailbox()->id() );
        d->e->bind( 2, imap()->user()->id() );
        d->e->bind( 3, "IMAP expunge " + Scope::current()->log()->id() );
        d->e->execute();
    }

    if ( !d->e->done() )
        return false;

    if ( d->e->failed() )
        error( No, "Database error. Messages not expunged." );

    if ( chat && imap()->session() ) {
        imap()->session()->expunge( d->uids );
        imap()->session()->emitResponses();
    }

    return true;
}


void Expunge::execute()
{
    if ( !expunge( true ) )
        return;
    finish();
}
