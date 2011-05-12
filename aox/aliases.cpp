// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "aliases.h"

#include "utf.h"
#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "transaction.h"
#include "helperrowcreator.h"

#include <stdio.h>


static AoxFactory<ListAliases>
f( "list", "aliases", "Display delivery aliases.",
   "    Synopsis: aox list aliases [pattern]\n\n"
   "    Displays a list of aliases where either the address or the\n"
   "    target mailbox matches the specified shell glob pattern.\n"
   "    Without a pattern, all aliases are listed.\n\n"
   "    ls is an acceptable abbreviation for list.\n\n"
   "    Examples:\n\n"
   "      aox list aliases\n"
   "      aox ls aliases /users/\\*\n" );



/*! \class ListAliases aliases.h
    This class handles the "aox list aliases" command.
*/

ListAliases::ListAliases( EStringList * args )
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
        EString s( "select localpart||'@'||domain as address, m.name "
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
                r->getEString( "address" ).cstr(),
                r->getUString( "name" ).utf8().cstr() );
    }

    if ( !q->done() )
        return;

    finish();
}


static AoxFactory<CreateAlias>
f2( "create", "alias", "Create a delivery alias.",
    "    Synopsis: aox add alias <address> <destination>\n\n"
    "    Creates an alias that instructs the L/SMTP server to accept\n"
    "    mail to a given address, and deliver it to a given mailbox.\n"
    "    The destination mailbox can be specified by name (starting\n"
    "    with '/') or by email address (ie. creating another alias for\n"
    "    the same mailbox).\n" );


class CreateAliasData
    : public Garbage
{
public:
    CreateAliasData()
        : address( 0 ), mailbox( 0 ), t( 0 ), q( 0 )
    {}

    Address * address;
    Address * destination;
    UString mailboxName;
    Mailbox * mailbox;
    Transaction * t;
    Query * q;
};


/*! \class CreateAlias aliases.h
    This class handles the "aox add alias" command.
*/

CreateAlias::CreateAlias( EStringList * args )
    : AoxCommand( args ), d( new CreateAliasData )
{
}


void CreateAlias::execute()
{
    if ( !d->address ) {
        Utf8Codec c;
        parseOptions();
        d->address = nextAsAddress();
        EString * first = args()->firstElement();
        if ( first && !first->startsWith( "/" ) && first->contains( "@" ) )
            d->destination = nextAsAddress();
        else
            d->mailboxName = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );

        database( true );
        if ( !d->mailboxName.isEmpty() )
            Mailbox::setup( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->t ) {
        if ( !d->mailboxName.isEmpty() ) {
            d->mailbox = Mailbox::obtain( d->mailboxName, false );
            if ( !d->mailbox || d->mailbox->deleted() )
                error( "No mailbox named " + d->mailboxName.utf8() );
        }

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
                              "select $1, mailbox from aliases al "
                              "join addresses a on (al.address=a.id) "
                              "where lower(a.localpart)=$2"
                              " and lower(a.domain)=$3 "
                              "limit 1",
                              this );
            d->q->bind( 1, d->address->id() );
            d->q->bind( 2, d->destination->localpart().lower() );
            d->q->bind( 3, d->destination->domain().lower() );
        }
        else {
            d->q = new Query( "insert into aliases (address, mailbox) "
                              "values ($1, $2)", this );
            d->q->bind( 1, d->address->id() );
            d->q->bind( 2, d->mailbox->id() );
        }
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() )
        error( "Couldn't create alias: " + d->q->error() );

    if ( d->q->rows() < 1 )
        error( "Could not locate destination for alias" );
    else if ( d->q->rows() > 1 )
        error( "Internal error: Inserted " + fn( d->q->rows() ) +
               " instead of 1. Not committing." );

    d->t->commit();

    finish();
}


static AoxFactory<DeleteAlias>
f3( "delete", "alias", "Delete a delivery alias.",
    "    Synopsis: aox delete alias <address>\n\n"
    "    Deletes the alias that associated the specified address\n"
    "    with a mailbox.\n" );


/*! \class DeleteAlias aliases.h
    This class handles the "aox delete alias" command.
*/

DeleteAlias::DeleteAlias( EStringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void DeleteAlias::execute()
{
    if ( !q ) {
        parseOptions();
        EString address = next();
        end();

        if ( address.isEmpty() )
            error( "No address specified." );

        AddressParser p( address );
        p.assertSingleAddress();
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );

        database( true );
        Address * a = p.addresses()->first();
        q = new Query( "delete from aliases where address=any(select a.id "
                       "from addresses a "
                       "join aliases al on (a.id=al.adress) "
                       "where lower(a.localpart)=$1 and lower(a.domain)=$2)",
                       this );
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
