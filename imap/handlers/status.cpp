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
        modseq( false ),
        mailbox( 0 ), session( 0 ), unseenCount( 0 ),
        highestModseq( 0 )
        {}
    String name;
    bool messages, uidnext, uidvalidity, recent, unseen, modseq;
    Mailbox * mailbox;
    Session * session;
    Query * unseenCount;
    Query * highestModseq;
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
    if ( ok() )
        log( l );
}


void Status::execute()
{
    if ( state() != Executing )
        return;

    // first part: set up what we need.
    if ( !d->mailbox ) {
        d->mailbox = mailbox( d->name );
        if ( !d->mailbox ) {
            error( No, "Can't open " + d->name );
            finish();
            return;
        }
        requireRight( d->mailbox, Permissions::Read );
    }

    if ( !d->session &&
         ( d->messages ||
           d->recent ||
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
            = new Query( "select count(*)::int as unseen "
                         "from messages m "
                         "left join deleted_messages dm using (mailbox,uid) "
                         "left join flags f on "
                         "(m.uid=f.uid and m.mailbox=f.mailbox and f.flag=$2) "
                         "where m.mailbox=$1 and "
                         "dm.uid is null and f.flag is null", this );
        d->unseenCount->bind( 1, d->mailbox->id() );
        Flag * f = Flag::find( "\\seen" );
        if ( f ) {
            d->unseenCount->bind( 2, f->id() );
            d->unseenCount->execute();
        }
        else {
            // what can we do? at least not crash.
            d->unseen = false;
            d->unseenCount = false;
        }
    }

    if ( d->modseq && !d->highestModseq ) {
        // HIGHESTMODSEQ too needs a DB query
        d->highestModseq
            = new Query( "select coalesce(max(modseq),1) as hm "
                         "from modsequences "
                         "where mailbox=$1", this );
        d->highestModseq->bind( 1, d->mailbox->id() );
        d->highestModseq->execute();
    }

    // second part: wait until we have the information
    if ( !permitted() )
        return;
    if ( d->session && !d->session->initialised() )
        return;
    if ( d->unseenCount && !d->unseenCount->done() )
        return;
    if ( d->highestModseq && !d->highestModseq->done() )
        return;

    // third part: return the payload.
    StringList status;

    // session hasn't told anyone about its messages, so it won't
    // admit to their existence. since it's a Session, not an
    // ImapSession, emitResponses() won't cause output, so we just
    // force it.
    if ( d->session )
        d->session->emitResponses( Session::New );

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
            status.append( "UNSEEN " + fn( r->getInt( "unseen" ) ) );
    }
    if ( d->modseq ) {
        Row * r = d->highestModseq->nextRow();
        if ( r )
            status.append( "HIGHESTMODSEQ " + fn( r->getBigint( "hm" ) ) );
    }

    respond( "STATUS " + d->name + " (" + status.join( " " ) + ")" );

    finish();
}
