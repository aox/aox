// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "queue.h"

#include "query.h"
#include "recipient.h"

#include <stdio.h>


/*! \class ShowQueue schema.h
    This class handles the "aox show queue" command.
*/

ShowQueue::ShowQueue( StringList * args )
    : AoxCommand( args ), q( 0 ), qr( 0 )
{
}


void ShowQueue::execute()
{
    if ( !q ) {
        parseOptions();
        end();

        database();

        String s(
            "select distinct d.id, d.message, "
            "a.localpart||'@'||a.domain as sender, "
            "to_char(d.injected_at, 'YYYY-MM-DD HH24:MI:SS') as submitted, "
            "(d.expires_at-current_timestamp)::text as expires_in, "
            "(current_timestamp-tried_at)::text as tried_at "
            "from deliveries d join addresses a on (d.sender=a.id) "
        );

        if ( !opt( 'a' ) )
            s.append( "join delivery_recipients dr on (d.id=dr.delivery) "
                      "where dr.action=$1 or dr.action=$2 " );
        s.append( "order by d.injected_at" );

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
            String sender( r->getString( "sender" ) );
            String submitted( r->getString( "submitted" ) );

            if ( sender == "@" )
                sender = "<>";

            printf( "%d: Message %d from %s (%s)\n",
                    delivery, message, sender.cstr(), submitted.cstr() );

            String s(
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

            String recipient( r->getString( "recipient" ) );
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

            String status;
            if ( !r->isNull( "status" ) )
                status = r->getString( "status" );
            if ( opt( 'v' ) && !status.isEmpty() )
                printf( ": %s", status.cstr() );
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
