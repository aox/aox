// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "stats.h"

#include "query.h"

#include <stdio.h>


class ShowCountsData
    : public Garbage
{
public:
    ShowCountsData()
        : state( 0 ), query( 0 )
    {}

    int state;
    Query * query;
};


/*! \class ShowCounts stats.h
    This class handles the "aox show counts" command.
*/

ShowCounts::ShowCounts( StringList * args )
    : AoxCommand( args ), d( new ShowCountsData )
{
}


void ShowCounts::execute()
{
    if ( d->state == 0 ) {
        parseOptions();
        end();

        database();
        d->state = 1;
        d->query =
            new Query( "select "
                       "(select count(*) from users)::int as users,"
                       "(select count(*) from mailboxes where"
                       " deleted='f')::int as mailboxes,"
                       "(select reltuples from pg_class where"
                       " relname='messages')::int as messages,"
                       "(select reltuples from pg_class where"
                       " relname='deleted_messages')::int as dm,"
                       "(select reltuples from pg_class where"
                       " relname='bodyparts')::int as bodyparts,"
                       "(select reltuples from pg_class where"
                       " relname='addresses')::int as addresses", this );
        d->query->execute();
    }

    if ( d->state == 1 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch estimates." );

        printf( "Users: %d\n", r->getInt( "users" ) );
        printf( "Mailboxes: %d\n", r->getInt( "mailboxes" ) );

        if ( opt( 'f' ) == 0 ) {
            printf( "Messages: %d", r->getInt( "messages" ) );
            if ( r->getInt( "dm" ) != 0 )
                printf( " (%d marked for deletion)", r->getInt( "dm" ) );
            printf( " (estimated)\n" );
            printf( "Bodyparts: %d (estimated)\n",
                    r->getInt( "bodyparts" ) );
            printf( "Addresses: %d (estimated)\n",
                    r->getInt( "addresses" ) );
            d->state = 666;
            finish();
            return;
        }

        d->query =
            new Query( "select count(*)::int as messages, "
                       "sum(rfc822size)::bigint as totalsize, "
                       "(select count(*) from deleted_messages)::int "
                       "as dm from messages", this );
        d->query->execute();
        d->state = 2;
    }

    if ( d->state == 2 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch messages/deleted_messages counts." );

        int m = r->getInt( "messages" );
        int dm = r->getInt( "dm" );

        printf( "Messages: %d", m-dm );
        if ( dm != 0 )
            printf( " (%d marked for deletion)", dm );
        printf( " (total size: %s)\n",
                String::humanNumber( r->getBigint( "totalsize" ) ).cstr() );

        d->query =
            new Query( "select count(*)::int as bodyparts,"
                       "sum(length(text))::bigint as textsize,"
                       "sum(length(data))::bigint as datasize "
                       "from bodyparts", this );
        d->query->execute();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch bodyparts counts." );

        printf( "Bodyparts: %d (text size: %s, data size: %s)\n",
                r->getInt( "bodyparts" ),
                String::humanNumber( r->getBigint( "textsize" ) ).cstr(),
                String::humanNumber( r->getBigint( "datasize" ) ).cstr() );

        d->query =
            new Query( "select count(*)::int as addresses "
                       "from addresses", this );
        d->query->execute();
        d->state = 4;
    }

    if ( d->state == 4 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch addresses counts." );

        printf( "Addresses: %d\n", r->getInt( "addresses" ) );
        d->state = 666;
    }

    finish();
}
