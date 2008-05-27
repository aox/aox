// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "undelete.h"

#include "transaction.h"
#include "messageset.h"
#include "mailbox.h"
#include "session.h"
#include "query.h"
#include "utf.h"

class UndeleteData
    : public Garbage
{
public:
    UndeleteData()
        : uid( 0 ), q( 0 ), m( 0 ), t( 0 ), fetch( 0 )
    {}

    UString mailbox;
    uint uid;
    Query * q;
    Mailbox * m;
    Transaction * t;
    Query * fetch;
};


/*! \class Undelete Undelete.h
    This class handles the "aox undelete" command.
*/

Undelete::Undelete( StringList * args )
    : AoxCommand( args ), d( new UndeleteData )
{
}


void Undelete::execute()
{
    if ( d->mailbox.isEmpty() ) {
        bool ok = false;
        parseOptions();
        Utf8Codec c;
        d->mailbox.append( c.toUnicode( next() ) );
        d->uid = next().number( &ok );
        end();

        if ( !c.valid() )
            error( "Mailbox name was not encoded using UTF-8: " + c.error() );

        if ( d->mailbox.isEmpty() )
            error( "No mailbox name supplied." );

        if ( d->uid < 1 || !ok )
            error( "No valid UID supplied." );

        database( true );
        Mailbox::setup( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->q ) {
        d->m = Mailbox::obtain( d->mailbox, false );
        if ( !d->m )
            error( "No mailbox named " + d->mailbox.utf8().quoted() );

        d->q = new Query( "select message from deleted_messages "
                          "where mailbox=$1 and uid=$2", this );
        d->q->bind( 1, d->m->id() );
        d->q->bind( 2, d->uid );
        d->q->execute();
    }

    if ( !d->t ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r )
            error( "Couldn't find a deleted message with uid " +
                   fn( d->uid ) + " in mailbox " +
                   d->mailbox.utf8().quoted() );

        uint message = r->getInt( "message" );

        d->t = new Transaction( this );
        d->q = new Query( "delete from deleted_messages where mailbox=$1 "
                          "and uid=$2", this );
        d->q->bind( 1, d->m->id() );
        d->q->bind( 2, d->uid );
        d->t->enqueue( d->q );

        d->q = new Query( "insert into mailbox_messages "
                          "(mailbox,uid,message,idate,modseq) "
                          "select $1,uidnext,$2,"
                          "extract(epoch from current_timestamp),"
                          "nextmodseq from mailboxes where id=$1 "
                          "for update", this );
        d->q->bind( 1, d->m->id() );
        d->q->bind( 2, message );
        d->t->enqueue( d->q );

        d->fetch = new Query( "select uidnext,nextmodseq from mailboxes "
                              "where id=$1", this );
        d->fetch->bind( 1, d->m->id() );
        d->t->enqueue( d->fetch );

        d->q = new Query( "update mailboxes set uidnext=uidnext+1, "
                          "nextmodseq=nextmodseq+1 where id=$1", this );
        d->q->bind( 1, d->m->id() );
        d->t->enqueue( d->q );
        d->t->enqueue( new Query( "notify mailboxes_updated", 0 ) );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        error( "Couldn't undelete message: " + d->t->error() );
    }
    else {
        Row * r = d->fetch->nextRow();

        if ( r ) {
            uint uidnext = r->getInt( "uidnext" );
            int64 nextmodseq = r->getBigint( "nextmodseq" );

            List<Session>::Iterator si( d->m->sessions() );
            while ( si ) {
                MessageSet dummy;
                dummy.add( uidnext );
                si->addUnannounced( dummy );
                ++si;
            }

            Mailbox * m = d->m;
            if ( m->uidnext() <= uidnext || m->nextModSeq() <= nextmodseq )
                m->setUidnextAndNextModSeq( 1+uidnext, 1+nextmodseq );
        }
    }

    finish();
}
