// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "status.h"

#include "flag.h"
#include "imap.h"
#include "query.h"
#include "mailbox.h"
#include "imapsession.h"


class StatusData
    : public Garbage
{
public:
    StatusData() :
        messages( false ), uidnext( false ), uidvalidity( false ),
        recent( false ), unseen( false ),
        modseq( false ),
        mailbox( 0 ), 
        unseenCount( 0 ), highestModseq( 0 ),
        messageCount( 0 ), recentCount( 0 )
        {}
    bool messages, uidnext, uidvalidity, recent, unseen, modseq;
    Mailbox * mailbox;
    Query * unseenCount;
    Query * highestModseq;
    Query * messageCount;
    Query * recentCount;
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
    d->mailbox = mailbox();
    space();
    require( "(" );

    String l( "Status " );
    if ( d->mailbox ) {
        l.append(  d->mailbox->name().ascii() );
        l.append( ":" );
    }
    bool atEnd = false;
    while ( !atEnd ) {
        String item = letters( 1, 13 ).lower();
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
        else if ( item == "highestmodseq" )
            d->modseq = true;
        else
            error( Bad, "Unknown STATUS item: " + item );

        if ( nextChar() == ' ' )
            space();
        else
            atEnd = true;
    }

    require( ")" );
    end();
    if ( !ok() )
        return;

    log( l );
    requireRight( d->mailbox, Permissions::Read );
}


void Status::execute()
{
    if ( state() != Executing )
        return;

    Session * session = imap()->session();
    Mailbox * current = 0;
    if ( session )
        current = session->mailbox();

    if ( d->unseen && !d->unseenCount ) {
        // UNSEEN is horribly slow. I don't think this is fixable
        // really.
        d->unseenCount 
            = new Query( "select "
                         "(select count(*)::int from mailbox_messages"
                         " where mailbox=$1)-"
                         "(select count(*)::int from flags"
                         " where mailbox=$1 and flag=$2) "
                         "as unseen", this );
        d->unseenCount->bind( 1, d->mailbox->id() );

        uint sid = Flag::id( "\\seen" );
        if ( sid ) {
            d->unseenCount->bind( 2, sid );
            d->unseenCount->execute();
        }
        else {
            // what can we do? at least not crash.
            d->unseen = false;
            d->unseenCount = false;
        }
    }

    if ( !d->recent ) {
        // nothing doing
    }
    else if ( d->mailbox == current ) {
        // we'll pick it up from the session
    }
    else if ( !d->recentCount ) {
        d->recentCount = new Query( "select uidnext-first_recent as recent "
                                    "from mailboxes "
                                    "where id=$1", this );
        d->recentCount->bind( 1, d->mailbox->id() );
        d->recentCount->execute();
    }

    if ( !d->messages ) {
        // we don't need to collect
    }
    else if ( d->mailbox == current ) {
        // we'll pick it up
    }
    else if ( d->messages && !d->messageCount ) {
        d->messageCount 
            = new Query( "select count(*)::int as messages "
                         "from mailbox_messages where mailbox=$1", this );
        d->messageCount->bind( 1, d->mailbox->id() );
        d->messageCount->execute();
    }

    if ( d->modseq && !d->highestModseq ) {
        // HIGHESTMODSEQ too needs a DB query
        d->highestModseq
            = new Query( "select coalesce(max(modseq),1) as hm "
                         "from mailbox_messages "
                         "where mailbox=$1", this );
        d->highestModseq->bind( 1, d->mailbox->id() );
        d->highestModseq->execute();
    }

    // second part: wait until we have the information
    if ( !permitted() )
        return;
    if ( d->unseenCount && !d->unseenCount->done() )
        return;
    if ( d->highestModseq && !d->highestModseq->done() )
        return;
    if ( d->messageCount && !d->messageCount->done() )
        return;
    if ( d->recentCount && !d->recentCount->done() )
        return;

    // third part: return the payload.
    StringList status;

    if ( d->messageCount ) {
        Row * r = d->messageCount->nextRow();
        if ( r )
            status.append( "MESSAGES " + fn( r->getInt( "messages" ) ) );
    }
    else if ( d->messages && d->mailbox == current ) {
        status.append( "MESSAGES " + fn( session->messages().count() ) );
    }
    if ( d->recentCount ) {
        Row * r = d->recentCount->nextRow();
        if ( r )
            status.append( "RECENT " + fn( r->getInt( "messages" ) ) );
    }
    else if ( d->recent ) {
        status.append( "RECENT " + fn( session->recent().count() ) );
    }
    if ( d->uidnext ) {
        status.append( "UIDNEXT " + fn( d->mailbox->uidnext() ) );
    }
    if ( d->uidvalidity ) {
        status.append( "UIDVALIDITY " + fn( d->mailbox->uidvalidity() ) );
    }
    if ( d->unseen ) {
        Row * r = d->unseenCount->nextRow();
        if ( r )
            status.append( "UNSEEN " + fn( r->getInt( "unseen" ) ) );
    }
    if ( d->modseq ) {
        Row * r = d->highestModseq->nextRow();
        if ( r )
            status.append( "HIGHESTMODSEQ " + fn( r->getBigint( "hm" ) ) );
    }

    respond( "STATUS " + imapQuoted( d->mailbox ) +
             " (" + status.join( " " ) + ")" );

    finish();
}
