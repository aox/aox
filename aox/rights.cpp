// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "rights.h"

#include "query.h"
#include "mailbox.h"
#include "stringlist.h"
#include "permissions.h"

#include <stdio.h>


class ListRightsData
    : public Garbage
{
public:
    ListRightsData()
        : q( 0 )
    {}

    String mailbox;
    String identifier;
    Query * q;
};


/*! \class ListRights rights.h
    This class handles the "aox list rights" command.
*/

ListRights::ListRights( StringList * args )
    : AoxCommand( args ), d( new ListRightsData )
{
}


void ListRights::execute()
{
    if ( d->mailbox.isEmpty() ) {
        parseOptions();
        d->mailbox = next();
        d->identifier = next();
        end();

        if ( d->mailbox.isEmpty() )
            error( "No mailbox name supplied." );

        database();
        Mailbox::setup( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->q ) {
        Mailbox * m = Mailbox::obtain( d->mailbox, false );
        if ( !m )
            error( "No mailbox named '" + d->mailbox + "'" );

        String s( "select identifier,rights from permissions p "
                  "join mailboxes m on (p.mailbox=m.id) where "
                  "mailbox=$1" );
        if ( !d->identifier.isEmpty() )
            s.append( " and identifier=$2" );

        d->q = new Query( s, this );
        d->q->bind( 1, m->id() );
        if ( !d->identifier.isEmpty() )
            d->q->bind( 2, d->identifier );
        d->q->execute();
    }

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        printf( "%s: %s\n", r->getString( "identifier" ).cstr(),
                describe( r->getString( "rights" ) ).cstr() );
    }

    if ( !d->q->done() )
        return;

    if ( d->q->rows() == 0 ) {
        if ( d->identifier.isEmpty() )
            printf( "No rights found.\n" );
        else
            printf( "No rights found for identifier '%s'.\n",
                    d->identifier.cstr() );
    }

    finish();
}


/*! Returns a string describing the rights string \a s, depending on
    whether the user used -v or not.
*/

String ListRights::describe( const String &s )
{
    String p( s );

    if ( opt( 'v' ) > 0 ) {
        StringList l;
        uint i = 0;
        while ( i < s.length() )
            l.append( Permissions::describe( s[i++] ) );
        p.append( " (" );
        p.append( l.join( ", " ) );
        p.append( ")" );
    }

    return p;
}
