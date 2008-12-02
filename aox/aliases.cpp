// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "aliases.h"

#include "utf.h"
#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "transaction.h"
#include "helperrowcreator.h"

#include <stdio.h>


/*! \class ListAliases aliases.h
    This class handles the "aox list aliases" command.
*/

ListAliases::ListAliases( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void ListAliases::execute()
{
    if ( !q ) {
        Utf8Codec c;
        UString pattern = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );

        database();
        String s( "select localpart||'@'||domain as address, m.name "
                  "from aliases join addresses a on (address=a.id) "
                  "join mailboxes m on (mailbox=m.id)" );
        if ( !pattern.isEmpty() )
            s.append( " where localpart||'@'||domain like $1 or "
                      "m.name like $1" );
        q = new Query( s, this );
        if ( !pattern.isEmpty() )
            q->bind( 1, sqlPattern( pattern ) );
        q->execute();
    }

    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        printf( "%s: %s\n",
                r->getString( "address" ).cstr(),
                r->getUString( "name" ).utf8().cstr() );
    }

    if ( !q->done() )
        return;

    finish();
}



class CreateAliasData
    : public Garbage
{
public:
    CreateAliasData()
        : address( 0 ), t( 0 ), q( 0 )
    {}

    Address * address;
    Address * destination;
    UString mailbox;
    Transaction * t;
    Query * q;
};


/*! \class CreateAlias aliases.h
    This class handles the "aox add alias" command.
*/

CreateAlias::CreateAlias( StringList * args )
    : AoxCommand( args ), d( new CreateAliasData )
{
}


void CreateAlias::execute()
{
    if ( !d->t ) {
        parseOptions();
        Utf8Codec c;
        d->address = nextAsAddress();
        String * first = args()->firstElement();
        if ( first && !first->startsWith( "/" ) && first->contains( "@" ) )
            d->destination = nextAsAddress();
        else
            d->mailbox = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );

        database( true );
        d->t = new Transaction( this );
        List< Address > l;
        l.append( d->address );
        if ( d->destination )
            l.append( d->destination );
        AddressCreator * ac = new AddressCreator( &l, d->t );
        ac->execute();
    }

    if ( !d->address->id() || ( d->destination && !d->destination->id() ) )
        return;

    if ( !d->q ) {
        if ( d->destination ) {
            d->q = new Query( "insert into aliases (address, mailbox) "
                              "select $1, mailbox from aliases "
                              "where address=$2",
                              this );
            d->q->bind( 1, d->address->id() );
            d->q->bind( 2, d->destination->id() );
        }
        else {
            d->q = new Query( "insert into aliases (address, mailbox) "
                              "select $1, id from mailboxes where name=$2",
                              this );
            d->q->bind( 1, d->address->id() );
            d->q->bind( 2, d->mailbox );
        }
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() )
        error( "Couldn't create alias" );

    if ( d->q->rows() < 1 )
        error( "Could not locate destination for alias" );
    else if ( d->q->rows() > 1 )
        error( "Internal error: Inserted " + fn( d->q->rows() ) +
               " instead of 1. Not committing." );

    d->t->commit();

    finish();
}



/*! \class DeleteAlias aliases.h
    This class handles the "aox delete alias" command.
*/

DeleteAlias::DeleteAlias( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void DeleteAlias::execute()
{
    if ( !q ) {
        parseOptions();
        String address = next();
        end();

        if ( address.isEmpty() )
            error( "No address specified." );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        database( true );
        Address * a = p.addresses()->first();
        q = new Query( "delete from aliases where address=any(select id "
                       "from addresses where lower(localpart)=$1 and "
                       "lower(domain)=$2 and name='')", this );
        q->bind( 1, a->localpart().lower() );
        q->bind( 2, a->domain().lower() );
        q->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() )
        error( "Couldn't delete alias" );

    finish();
}
