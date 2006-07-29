// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "status.h"

#include "flag.h"
#include "imap.h"
#include "query.h"
#include "mailbox.h"
#include "session.h"
#include "imapsession.h"


class StatusData
    : public Garbage
{
public:
    StatusData() :
        messages( false ), uidnext( false ), uidvalidity( false ),
        recent( false ), unseen( false ),
        mailbox( 0 ), session( 0 ), permissions( 0 ), unseenCount( 0 )
        {}
    String name;
    bool messages, uidnext, uidvalidity, recent, unseen;
    Mailbox * mailbox;
    Session * session;
    Permissions * permissions;
    Query * unseenCount;
};


/*! \class Status status.h
    Returns the status of the specified mailbox (RFC 3501 section 6.3.10)
*/

Status::Status()
    : d( new StatusData )
{
    setGroup( 4 );
}


void Status::parse()
{
    space();
    d->name = astring();
    space();
    require( "(" );

    String l( "Status " + d->name + ":" );
    bool atEnd = false;
    while ( !atEnd ) {
        String item = letters( 1, 11 ).lower();
        l.append( " " );
        l.append( item );

        if ( item == "messages" )
            d->messages = true;
        else if ( item == "recent" )
            d->recent = true;
        else if ( item == "uidnext" )
            d->uidnext = true;
        else if ( item == "uidvalidity" )
            d->uidvalidity = true;
        else if ( item == "unseen" )
            d->unseen = true;
        else
            error( Bad, "Unknown STATUS item: " + item );

        if ( nextChar() == ' ' )
            space();
        else
            atEnd = true;
    }

    require( ")" );
    end();
    if ( ok() )
        log( l );
}


void Status::execute()
{
    // first part: set up what we need.
    if ( !d->mailbox ) {
        d->mailbox = Mailbox::find( imap()->mailboxName( d->name ) );
        if ( !d->mailbox ) {
            error( No, "Can't open " + d->name );
            finish();
            return;
        }
    }

    if ( !d->permissions )
        d->permissions = new Permissions( d->mailbox, imap()->user(), this );

    if ( !d->session && ( d->messages || d->recent ||
                          ( d->mailbox->view() && d->uidnext ) ) )
    {
        if ( imap()->session() &&
             imap()->session()->mailbox() == d->mailbox )
            d->session = imap()->session();
        else
            d->session = new Session( d->mailbox, true );
        d->session->refresh( this );
    }

    if ( d->unseen && !d->unseenCount ) {
        // UNSEEN is a bit of a special case. we have to issue our own
        // select and make the database reveal the number.
        d->unseenCount
            = new Query( "select "
                         "(select count(*) from messages "
                         "where mailbox=$1)::integer"
                         "-"
                         "(select count(*) from flags "
                         "where mailbox=$1 and flag=$2)::integer"
                         " as count", this );
        d->unseenCount->bind( 1, d->mailbox->id() );
        Flag * f = Flag::find( "\\seen" );
        if ( f ) {
            d->unseenCount->bind( 1, f->id() );
            d->unseenCount->execute();
        }
        else {
            // what can we do? at least not crash.
            d->unseen = false;
            d->unseenCount = false;
        }

    }

    // second part: wait until we have the information
    if ( d->permissions && !d->permissions->ready() )
        return;
    if ( d->session && !d->session->initialised() )
        return;
    if ( d->unseenCount && !d->unseenCount->done() )
        return;

    // third part: do we have permission to return this? now?
    if ( d->permissions &&
         !d->permissions->allowed( Permissions::Read ) ) {
        error( No, "No read access for " + d->mailbox->name() );
        return;
    }

    // fourth part: return the payload.
    StringList status;

    if ( d->messages )
        status.append( "MESSAGES " + fn( d->session->count() ) );
    if ( d->recent )
        status.append( "RECENT " + fn( d->session->recent().count() ) );
    if ( d->uidnext )
        status.append( "UIDNEXT " + fn( d->mailbox->uidnext() ) );
    if ( d->uidvalidity )
        status.append( "UIDVALIDITY " +
                       fn( d->mailbox->uidvalidity() ) );
    if ( d->unseen ) {
        Row * r = d->unseenCount->nextRow();
        if ( r )
            status.append( "UNSEEN " + fn( r->getInt( "count" ) ) );
    }

    respond( "STATUS " + d->name + " (" + status.join( " " ) + ")" );

    finish();
}
