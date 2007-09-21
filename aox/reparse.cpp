// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "reparse.h"

#include "query.h"
#include "message.h"
#include "mailbox.h"
#include "injector.h"
#include "fieldcache.h"
#include "transaction.h"
#include "addresscache.h"

#include <stdio.h>


class ReparseData
    : public Garbage
{
public:
    ReparseData()
        : q( 0 ), row( 0 ), injector( 0 ), t( 0 )
    {}

    Query * q;
    Row * row;
    Injector * injector;
    Transaction * t;
};


/*! \class Reparse reparse.h
    This class handles the "aox reparse" command.
*/

Reparse::Reparse( StringList * args )
    : AoxCommand( args ), d( new ReparseData )
{
}


void Reparse::execute()
{
    if ( !d->q ) {
        end();

        printf( "Looking for messages with parse failures\n" );

        database( true );
        AddressCache::setup();
        FieldNameCache::setup();
        Mailbox::setup( this );

        d->q = new Query( "select p.mailbox,p.uid,b.id as bodypart,"
                          "b.text,b.data "
                          "from unparsed_messages u "
                          "join bodyparts b on (u.bodypart=b.id) "
                          "join part_numbers p on (p.bodypart=b.id) "
                          "left join deleted_messages dm on "
                          "(p.mailbox=dm.mailbox and p.uid=dm.uid) "
                          "where dm.mailbox is null", this );
        d->q->execute();
    }

    if ( !choresDone() )
        return;

    if ( d->injector ) {
        if ( !d->injector->done() )
            return;

        if ( d->injector->failed() ) {
            error( "Couldn't inject reparsed message: " +
                   d->injector->error() );
        }
        else {
            d->injector->announce();
            Mailbox * m = d->injector->mailboxes()->first();
            d->t = new Transaction( this );
            Query * q =
                new Query( "delete from unparsed_messages where "
                           "bodypart=$1", this );
            q->bind( 1, d->row->getInt( "bodypart" ) );
            d->t->enqueue( q );
            q = new Query( "insert into deleted_messages "
                           "(mailbox,uid,deleted_by,reason) "
                           "values ($1,$2,$3,$4)", this );
            q->bind( 1, d->row->getInt( "mailbox" ) );
            q->bind( 2, d->row->getInt( "uid" ) );
            q->bindNull( 3 );
            q->bind( 4,
                     String( "reparsed as uid " ) +
                     fn( d->injector->uid( m ) )+
                     " by aox " +
                     Configuration::compiledIn( Configuration::Version ) );
            d->t->enqueue( q );
            d->t->commit();
            printf( "- reparsed %s:%d (new UID %d)\n",
                    m->name().utf8().cstr(),
                    d->row->getInt( "uid" ),
                    d->injector->uid( m ) );
        }

        d->injector = 0;
    }
    else if ( d->t ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() )
            error( "Couldn't delete reparsed message: " + d->t->error() );

        d->t = 0;
    }

    while ( d->q->hasResults() && !d->injector ) {
        Row * r = d->q->nextRow();

        String text;
        if ( r->isNull( "data" ) )
            text = r->getString( "text" );
        else
            text = r->getString( "data" );
        Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
        Message * msg = new Message( text );
        if ( m && msg->valid() ) {
            d->row = r;
            d->injector = new Injector( msg, this );
            SortedList<Mailbox> * l = new SortedList<Mailbox>;
            l->append( m );
            d->injector->setMailboxes( l );
            d->injector->execute();
            return;
        }
        else {
            printf( "- parsing %s:%d still fails: %s\n",
                    m->name().utf8().cstr(), r->getInt( "uid" ),
                    msg->error().simplified().cstr() );
        }
    }

    finish();
}
