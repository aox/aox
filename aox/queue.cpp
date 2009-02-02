// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "queue.h"

#include "query.h"
#include "recipient.h"

#include <stdio.h>


/*! \class ShowQueue schema.h
    This class handles the "aox show queue" command.
*/

ShowQueue::ShowQueue( EStringList * args )
    : AoxCommand( args ), q( 0 ), qr( 0 )
{
}


void ShowQueue::execute()
{
    if ( !q ) {
        parseOptions();
        end();

        database();

        EString s(
            "select d.id, d.message, "
            "a.localpart||'@'||a.domain as sender, "
            "to_char(d.injected_at, 'YYYY-MM-DD HH24:MI:SS') as submitted, "
            "to_char(max(dr.last_attempt), 'YYYY-MM-DD HH24:MI:SS') as tried, "
            "(extract(epoch from d.expires_at)-extract(epoch from current_timestamp))::bigint as expires_in "
            "from deliveries d join addresses a on (d.sender=a.id) "
            "join delivery_recipients dr on (d.id=dr.delivery) "
        );
        if ( !opt( 'a' ) )
            s.append( "where dr.action=$1 or dr.action=$2 " );
        s.append( "group by d.id, d.message, "
                  "a.domain, a.localpart, d.injected_at, d.expires_at "
                  "order by submitted, tried, sender" );

        q = new Query( s, this );
        if ( !opt( 'a' ) ) {
            q->bind( 1, Recipient::Unknown );
            q->bind( 2, Recipient::Delayed );
        }
        q->execute();
    }

    while ( qr || q->hasResults() ) {
        if ( !qr ) {
            Row * r = q->nextRow();
            uint delivery = r->getInt( "id" );
            uint message = r->getInt( "message" );
            EString sender( r->getEString( "sender" ) );

            if ( sender == "@" )
                sender = "<>";

            printf( "%d: Message %d from %s (submitted %s)\n",
                    delivery, message, sender.cstr(),
                    r->getEString( "submitted" ).cstr() );
            bool nl = false;
            if ( !r->isNull( "tried" ) ) {
                printf( "\t(last tried %s",
                        r->getEString( "tried" ).cstr() );
                nl = true;
            }
            int64 expires = r->getBigint( "expires_in" );
            if ( expires > 0 && expires < 604800 ) {
                printf( "%sexpires in %d:%02d:%02d",
                        nl ? ", " : "\t(",
                        (int)expires / 3600, ( (int)expires / 60 ) % 60,
                        (int)expires % 60 );
                nl = true;
            }
            if ( nl )
                printf( ")\n" );

            EString s(
                "select action, status, "
                "lower(a.domain) as domain, a.localpart, "
                "a.localpart||'@'||a.domain as recipient "
                "from delivery_recipients dr join addresses a "
                "on (dr.recipient=a.id) where dr.delivery=$1 "
                "order by dr.action, lower(a.domain), a.localpart"
            );
            qr = new Query( s, this );
            qr->bind( 1, delivery );
            qr->execute();
        }

        while ( qr->hasResults() ) {
            Row * r = qr->nextRow();

            EString recipient( r->getEString( "recipient" ) );
            printf( "\t%s", recipient.cstr() );

            uint action = r->getInt( "action" );
            switch ( action ) {
            case 0:
                printf( " (not tried yet" );
                break;
            case 1:
                printf( " (failed" );
                break;
            case 2:
                printf( " (delayed" );
                break;
            case 3:
                printf( " (delivered" );
                break;
            case 4:
                printf( " (relayed" );
                break;
            case 5:
                printf( " (expanded" );
                break;
            }

            EString status;
            if ( !r->isNull( "status" ) )
                status = r->getEString( "status" );
            if ( opt( 'v' ) && !status.isEmpty() )
                printf( ": status is %s", status.cstr() );
            printf( ")\n" );
        }

        if ( !qr->done() )
            return;

        if ( q->hasResults() )
            printf( "\n" );

        qr = 0;
    }

    if ( !q->done() )
        return;

    finish();
}
