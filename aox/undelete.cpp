// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "undelete.h"

#include "searchsyntax.h"
#include "transaction.h"
#include "messageset.h"
#include "selector.h"
#include "mailbox.h"
#include "query.h"
#include "utf.h"

#include <stdlib.h> // exit()
#include <stdio.h> // printf()


class UndeleteData
    : public Garbage
{
public:
    UndeleteData(): state( 0 ), m( 0 ), t( 0 ), find( 0 ), uidnext( 0 ) {}

    uint state;
    Mailbox * m;
    Transaction * t;

    Query * find;
    Query * uidnext;
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
    if ( d->state == 0 ) {
        database( true );
        Mailbox::setup();
        d->state = 1;
    }

    if ( d->state == 1 ) {
        if ( !choresDone() )
            return;
        d->state = 2;
    }

    if ( d->state == 2 ) {
        Utf8Codec c;
        UString m = c.toUnicode( next() );

        if ( !c.valid() )
            error( "Encoding error in mailbox name: " + c.error() );
        else if ( m.isEmpty() )
            error( "No mailbox name" );
        else
            d->m = Mailbox::find( m, true );
        if ( !d->m )
            error( "No such mailbox: " + m.utf8() );

        Selector * s = parseSelector( args() );
        if ( !s )
            exit( 1 );
        s->simplify();

        d->t = new Transaction( this );
        if ( d->m->deleted() ) {
            if ( !d->m->create( d->t, 0 ) )
                error( "Mailbox was deleted; recreating failed: " +
                       d->m->name().utf8() );
            printf( "aox: Note: Mailbox %s is recreated.\n"
                    "     Its ownership and permissions could not be restored.\n",
                    d->m->name().utf8().cstr() );
        }

        StringList wanted;
        wanted.append( "uid" );

        d->find = s->query( 0, d->m, 0, 0, true, &wanted, true );
        d->t->enqueue( d->find );

        d->uidnext = new Query( "select uidnext, nextmodseq "
                                "from mailboxes "
                                "where id=$1 for update", this );
        d->uidnext->bind( 1, d->m->id() );
        d->t->enqueue( d->uidnext );

        d->t->execute();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !d->uidnext->done() )
            return;

        Row * r = d->uidnext->nextRow();
        if ( !r )
            error( "Internal error - could not read mailbox UID" );
        uint uidnext = r->getInt( "uidnext" );
        int64 modseq = r->getBigint( "nextmodseq" );

        MessageSet s;
        r = d->find->nextRow();
        while ( r ) {
            s.add( r->getInt( "uid" ) );
            r = d->find->nextRow();
        }

        if ( s.isEmpty() )
            error( "No such deleted message (search returned 0 results)" );

        Query * q;

        q = new Query( "update messages set idate="
                       "extract(epoch from current_timestamp) "
                       "from mailbox_messages mm where "
                       "mm.message=messages.id and "
                       "mm.mailbox=$1 and mm.uid=any($2)", 0 );
        q->bind( 1, d->m->id() );
        q->bind( 2, s );
        d->t->enqueue( q );

        q = new Query( "insert into mailbox_messages "
                       "(mailbox,uid,message,modseq) "
                       "select $1,generate_series($2::int,$3::int),"
                       "message,$4 "
                       "from deleted_messages "
                       "where mailbox=$1 and uid=any($5)", 0 );
        q->bind( 1, d->m->id() );
        q->bind( 2, uidnext );
        q->bind( 3, uidnext + s.count() - 1 );
        q->bind( 4, modseq );
        q->bind( 5, s );
        d->t->enqueue( q );

        q = new Query( "delete from deleted_messages "
                       "where mailbox=$1 and uid=any($2)", 0 );
        q->bind( 1, d->m->id() );
        q->bind( 5, s );
        d->t->enqueue( q );

        q = new Query( "update mailboxes "
                       "set uidnext=$1, nextmodseq=$2 "
                       "where id=$3", 0 );
        q->bind( 1, uidnext + s.count() );
        q->bind( 2, modseq + 1 );
        q->bind( 3, d->m->id() );
        d->t->enqueue( q );

        Mailbox::refreshMailboxes( d->t );

        d->t->commit();
        d->state = 4;
    }

    if ( d->state == 4 ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() )
            error( "Undelete failed." );
        finish();
    }
}
