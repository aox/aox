// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "retention.h"

#include "query.h"
#include "selector.h"
#include "mailbox.h"
#include "utf.h"
#include "searchsyntax.h"

#include <stdlib.h>


class SetRetentionData
    : public Garbage
{
public:
    SetRetentionData()
        : state( 0 ), duration( 0 ), m( 0 ), selector( 0 ), q( 0 )
    {}

    int state;
    EString action;
    int duration;
    Mailbox * m;
    Selector * selector;
    Query * q;
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
        d->q = new Query( "insert into retention_policies "
                          "(action, duration, mailbox, selector) "
                          "values ($1, $2, $3, $4)", this );
        d->q->bind( 1, d->action );
        d->q->bind( 2, d->duration );
        if ( d->m )
            d->q->bind( 3, d->m->id() );
        else
            d->q->bindNull( 3 );
        if ( d->selector )
            d->q->bind( 4, d->selector->string() );
        else
            d->q->bindNull( 4 );
        d->q->execute();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() )
            error( "Couldn't set retention policy: " + d->q->error() );
    }

    finish();
}


static AoxFactory<ShowRetention>
b( "show", "retention", "Display mailbox retention policies",
   "" );


/*! \class ShowRetention retention.h
    Displays mailbox retention policies created with "set retention".
*/

ShowRetention::ShowRetention( EStringList * args )
    : AoxCommand( args )
{
}

void ShowRetention::execute()
{
}
