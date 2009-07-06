// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "stats.h"

#include "query.h"
#include "configuration.h"

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


static AoxFactory<ShowCounts>
f( "show", "counts", "Show number of users, messages etc..",
   "    Synopsis: aox show counts [-f]\n\n"
   "    Displays the number of rows in the most important tables,\n"
   "    as well as the total size of the mail stored.\n"
   "\n"
   "    The -f flag makes aox collect slow-but-accurate counts.\n"
   "    Without it, by default, you get quick estimates.\n" );


/*! \class ShowCounts stats.h
    This class handles the "aox show counts" command.
*/

ShowCounts::ShowCounts( EStringList * args )
    : AoxCommand( args ), d( new ShowCountsData )
{
}


static EString tuples( const EString & table )
{
    EString s( "select reltuples from pg_class c join "
              "pg_namespace n on (c.relnamespace=n.oid) "
              "where n.nspname=$1 and c.relname='" );
    s.append( table );
    s.append( "'" );
    return s;
}


void ShowCounts::execute()
{
    if ( d->state == 0 ) {
        parseOptions();
        end();

        database();
        d->state = 1;

        EString s( Configuration::text( Configuration::DbSchema ) );

        d->query = new Query(
            "select "
            "(select count(*) from users)::int as users,"
            "(select count(*) from mailboxes where deleted='f')::int"
            " as mailboxes,"
            "(" + tuples( "messages" ) + ")::int as messages,"
            "(" + tuples( "bodyparts" ) + ")::int as bodyparts,"
            "(" + tuples( "addresses" ) + ")::int as addresses,"
            "(" + tuples( "deleted_messages" ) + ")::int as dm",
            this
        );

        d->query->bind( 1, s );
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
                EString::humanNumber( r->getBigint( "totalsize" ) ).cstr() );

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
                EString::humanNumber( r->getBigint( "textsize" ) ).cstr(),
                EString::humanNumber( r->getBigint( "datasize" ) ).cstr() );

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
