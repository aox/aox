// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "db.h"

#include "query.h"
#include "schema.h"
#include "recipient.h"
#include "transaction.h"
#include "configuration.h"

#include <stdio.h>


static const char * versions[] = {
    "", "", "0.91", "0.92", "0.92", "0.92 to 0.93", // 0-5
    "0.93", "0.93", "0.94 to 0.95", "0.96 to 0.97", // 6-9
    "0.97", "0.97", "0.98", "0.99", "1.0", "1.01",  // 10-15
    "1.05", "1.05", "1.06", "1.07", "1.08", "1.09", // 16-21
    "1.10", "1.10", "1.11", "1.11", "1.11", "1.11", // 22-27
    "1.12", "1.12", "1.12", "1.12", "1.13", "1.13", // 28-33
    "1.15", "1.15", "1.16", "1.16", "1.16", "1.17", // 34-39
    "1.17", "1.17", "1.17", "2.0", "2.0", "2.0",    // 40-45
    "2.0", "2.0", "2.0", "2.01", "2.01", "2.01",    // 46-51
    "2.01", "2.01", "2.01", "2.02", "2.04", "2.04", // 52-57
    "2.05", "2.05", "2.06", "2.06", "2.06", "2.06", // 58-63
    "2.06"
};
static int nv = sizeof( versions ) / sizeof( versions[0] );


/*! \class ShowSchema schema.h
    This class handles the "aox show schema" command.
*/

ShowSchema::ShowSchema( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void ShowSchema::execute()
{
    if ( !q ) {
        end();

        database();
        q = new Query( "select revision from mailstore", this );
        q->execute();
    }

    if ( !q->done() )
        return;

    Row * r = q->nextRow();
    if ( r ) {
        int rev = r->getInt( "revision" );

        String s;
        if ( rev >= nv ) {
            s = "too new for ";
            s.append( Configuration::compiledIn( Configuration::Version ) );
        }
        else {
            s = versions[rev];
            if ( rev == nv-1 )
                s.append( " - latest known version" );
            else
                s.append( " - needs to be upgraded" );
        }

        if ( !s.isEmpty() )
            s = " (" + s + ")";
        printf( "%d%s\n", rev, s.cstr() );
    }

    finish();
}



/*! \class UpgradeSchema schema.h
    This class handles the "aox upgrade schema" command.
*/

UpgradeSchema::UpgradeSchema( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void UpgradeSchema::execute()
{
    if ( !q ) {
        parseOptions();
        end();

        bool commit = true;
        if ( opt( 'n' ) > 0 )
            commit = false;

        database( true );
        Schema * s = new Schema( this, true, commit );
        q = s->result();
        s->execute();
    }

    if ( !q->done() )
        return;

    finish();
}



/*! \class Vacuum Vacuum.h
    This class handles the "aox vacuum" command.
*/

Vacuum::Vacuum( StringList * args )
    : AoxCommand( args ), t( 0 )
{
}


void Vacuum::execute()
{
    if ( !t ) {
        parseOptions();
        end();

        database( true );
        t = new Transaction( this );
        uint days = Configuration::scalar( Configuration::UndeleteTime );
        Query * q = 0;
        q = new Query( "delete from deliveries "
                       "where injected_at<current_timestamp-'" +
                       fn( days ) + " days'::interval "
                       "and id in "
                       "(select delivery from delivery_recipients "
                       " where action=$1 or action=$2) "
                       "and id not in "
                       "(select delivery from delivery_recipients "
                       " where action!=$1 and action!=$2)", 0 );
        q->bind( 1, Recipient::Delivered );
        q->bind( 2, Recipient::Relayed );
        t->enqueue( q );
        // what's best, complex but plannable ...
        q = new Query( "delete from messages "
                       "where id in "
                       "(select message from deleted_messages "
                       " left join mailbox_message mm on "
                       " (dm.message=mm.message) "
                       " left join deliveries d on "
                       " (dm.message=d.message) "
                       " where mm.message is null and d.message is null "
                       " and dm.deleted_at<current_timestamp-'" + fn( days ) +
                       "  days'::interval", 0 );
        // ... or simple but not terribly plannable?
        q = new Query( "delete from messages "
                       "where id in "
                       "(select message from deleted_messages dm"
                       " where dm.deleted_at<current_timestamp-'" +
                       fn( days ) + " days'::interval) "
                       "and id not in (select message from deliveries) "
                       "and id not in (select message from mailbox_messages)",
                       0 );
        t->enqueue( q );
        q = new Query( "delete from bodyparts where id in (select id "
                       "from bodyparts b left join part_numbers p on "
                       "(b.id=p.bodypart) where bodypart is null)", 0 );
        t->enqueue( q );
        t->commit();
    }

    if ( !t->done() )
        return;

    if ( t->failed() )
        error( t->error() );

    finish();
}
