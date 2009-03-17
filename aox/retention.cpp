// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "retention.h"

#include "utf.h"
#include "query.h"
#include "search.h"
#include "selector.h"
#include "mailbox.h"
#include "transaction.h"
#include "searchsyntax.h"

#include <stdio.h>
#include <stdlib.h>


class SetRetentionData
    : public Garbage
{
public:
    SetRetentionData()
        : state( 0 ), duration( 0 ), m( 0 ), selector( 0 ), t( 0 )
    {}

    int state;
    EString action;
    int duration;
    Mailbox * m;
    Selector * selector;
    Transaction * t;
};


/*! \class SetRetention retention.h
    Sets mailbox retention policies.
*/

// XXX: Listen to the documentation: "create", not "set".

static AoxFactory<SetRetention>
a( "set", "retention", "Set mailbox retention policies",
   "    Synopsis: aox set retention <retain|delete> <days> [mailbox] [search]\n\n"
   "    This command creates a retention policy. The action (retain or delete)\n"
   "    and the duration (a positive number, or \"forever\") must be specified.\n"
   "    Optionally, a mailbox name and a search expression may be specified, to\n"
   "    limit the scope of the policy to matching messages.\n" );


SetRetention::SetRetention( EStringList * args )
    : AoxCommand( args ), d( new SetRetentionData )
{
}


void SetRetention::execute()
{
    if ( d->state == 0 ) {
        parseOptions();

        d->action = next();
        if ( !( d->action == "retain" || d->action == "delete" ) )
            error( "Unknown retention policy action: " + d->action );

        EString ds( next() );
        if ( ds != "forever" ) {
            bool ok = false;
            d->duration = ds.number( &ok );
            if ( !ok )
                error( "Invalid retention duration: " + ds );
        }

        if ( d->action == "delete" && d->duration == 0 )
            error( "'delete after forever' is not a valid policy." );

        d->state = 1;

        database( true );
        Mailbox::setup();
    }

    if ( d->state == 1 ) {
        if ( !choresDone() )
            return;

        // Is a mailbox name specified?

        if ( !args()->isEmpty() ) {
            EString s( *args()->first() );
            if ( s[0] == '/' ) {
                Utf8Codec c;
                UString m = c.toUnicode( s );

                if ( !c.valid() )
                    error( "Encoding error in mailbox name: " + c.error() );
                d->m = Mailbox::find( m, true );
                if ( !d->m )
                    error( "No such mailbox: " + m.utf8() );

                (void)args()->shift();
            }
        }

        // Are any search terms specified?

        if ( !args()->isEmpty() ) {
            d->selector = parseSelector( args() );
            if ( !d->selector )
                exit( 1 );
            d->selector->simplify();
        }

        end();

        d->state = 2;
    }

    if ( d->state == 2 ) {
        d->t = new Transaction( this );
        Query * q;
        q = new Query( "delete from retention_policies "
                       "where mailbox=$1 and action=$2 and selector=$3", 0 );
        if ( d->m )
            q->bind( 1, d->m->id() );
        else
            q->bindNull( 1 );
        q->bind( 2, d->action );
        if ( d->selector )
            q->bind( 3, d->selector->string() );
        else
            q->bindNull( 3 );
        d->t->enqueue( q );

        q = new Query( "insert into retention_policies "
                       "(action, duration, mailbox, selector) "
                       "values ($1, $2, $3, $4)", 0 );
        q->bind( 1, d->action );
        q->bind( 2, d->duration );
        if ( d->m )
            q->bind( 3, d->m->id() );
        else
            q->bindNull( 3 );
        if ( d->selector )
            q->bind( 4, d->selector->string() );
        else
            q->bindNull( 4 );
        d->t->enqueue( q );

        d->t->commit();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !d->t->done() )
            return;

        if ( d->t->failed() )
            error( "Couldn't set retention policy: " + d->t->error() );
    }

    finish();
}


class ShowRetentionData
    : public Garbage
{
public:
    ShowRetentionData()
        : q( 0 )
    {}

    Query * q;
};


static AoxFactory<ShowRetention>
b( "show", "retention", "Display mailbox retention policies",
   "    Synopsis: aox show retention [mailbox]\n\n"
   "    This command displays the retention policies related to the\n"
   "    specified mailbox, or all existing policies if no mailbox is\n"
   "    specified.\n" );


/*! \class ShowRetention retention.h
    Displays mailbox retention policies created with "set retention".
*/

ShowRetention::ShowRetention( EStringList * args )
    : AoxCommand( args ), d( new ShowRetentionData )
{
    database( true );
    Mailbox::setup();
}

void ShowRetention::execute()
{
    if ( !choresDone() )
        return;

    if ( !d->q ) {
        parseOptions();

        Mailbox * m = 0;
        if ( !args()->isEmpty() ) {
            EString s( *args()->first() );
            Utf8Codec c;
            UString name = c.toUnicode( s );

            if ( !c.valid() )
                error( "Encoding error in mailbox name: " + c.error() );
            m = Mailbox::find( name, true );
            if ( !m )
                error( "No such mailbox: " + name.utf8() );

            (void)args()->shift();
        }

        end();

        EString q(
            "select coalesce(m.name,'Global') as name, action, duration, id "
            "selector "
            "from retention_policies rp left join mailboxes m "
            "on (m.id=rp.mailbox)"
        );

        if ( m )
            q.append( " where m.name is null or m.name=any($1::text[])" );

        q.append( " order by name='Global'," // global first, others after
                  " lower(name) asc," // others sorted by mailbox
                  " action desc," // retain before delete
                  " duration asc," // and increasing time
                  " id" ); // and as tiebreaker, older policy first

        d->q = new Query( q, this );

        if ( m ) {
            IntegerSet ids;
            while ( m ) {
                if ( m->id() )
                    ids.add( m->id() );
                m = m->parent();
            }
            d->q->bind( 1, ids );
        }

        d->q->execute();
    }

    UString last;
    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();

        UString name( r->getUString( "name" ) );

        if ( name != last ) {
            printf( "%s:\n", name.utf8().cstr() );
            last = name;
        }

        printf( "  %s %d days\n", r->getEString( "action" ).cstr(),
                r->getInt( "duration" ) );
        if ( !r->isNull( "selector" ) ) {
            Selector * s = Selector::fromString( r->getEString( "selector" ) );
            if ( s )
                dumpSelector( s, 1 );
        }
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() )
        error( "Couldn't fetch retention policies: " + d->q->error() );

    finish();
}
