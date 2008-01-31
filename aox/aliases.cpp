// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "aliases.h"

#include "utf.h"
#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "transaction.h"
#include "addresscache.h"

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
    UString s;
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
        String address = next();
        UString mailbox = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( address.isEmpty() )
            error( "No address specified." );

        if ( mailbox.isEmpty() )
            error( "No mailbox specified." );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        AddressCache::setup();

        d->s = mailbox;
        d->address = p.addresses()->first();

        database( true );
        d->t = new Transaction( this );
        List< Address > l;
        l.append( d->address );
        AddressCache::lookup( d->t, &l, this );
        d->t->commit();

        Mailbox::setup( this );
    }

    if ( !choresDone() || !d->t->done() )
        return;

    if ( !d->q ) {
        Mailbox * m = Mailbox::obtain( d->s, false );
        if ( !m )
            error( "Invalid mailbox specified: " + d->s.utf8().quoted() );

        d->q = new Query( "insert into aliases (address, mailbox) "
                          "values ($1, $2)", this );
        d->q->bind( 1, d->address->id() );
        d->q->bind( 2, m->id() );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() )
        error( "Couldn't create alias: " + d->q->error() );

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
        q = new Query( "delete from aliases where address=(select id "
                       "from addresses where lower(localpart)=$1 and "
                       "lower(domain)=$2 and name='')", this );
        q->bind( 1, a->localpart().lower() );
        q->bind( 2, a->domain().lower() );
        q->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() )
        error( "Couldn't delete alias: " + q->error() );

    finish();
}
