// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "users.h"

#include "utf.h"
#include "user.h"
#include "query.h"
#include "address.h"
#include "mailbox.h"
#include "occlient.h"
#include "transaction.h"
#include "addresscache.h"

#include <stdio.h>
#include <stdlib.h>


/*! \class ListUsers users.h
    This class handles the "aox list users" command.
*/

ListUsers::ListUsers( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void ListUsers::execute()
{
    if ( !q ) {
        Utf8Codec c;
        UString pattern = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );

        database();
        String s( "select login, localpart||'@'||domain as address "
                  "from users u join aliases al on (u.alias=al.id) "
                  "join addresses a on (al.address=a.id)" );
        if ( !pattern.isEmpty() )
            s.append( " where login like $1" );
        q = new Query( s, this );
        if ( !pattern.isEmpty() )
            q->bind( 1, sqlPattern( pattern ) );
        q->execute();
    }

    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        printf( "%-16s %s\n",
                r->getUString( "login" ).utf8().cstr(),
                r->getString( "address" ).cstr() );
    }

    if ( !q->done() )
        return;

    finish();
}



class CreateUserData
    : public Garbage
{
public:
    CreateUserData()
        : user( 0 ), query( 0 )
    {}

    User * user;
    Query * query;
};


/*! \class CreateUser users.h
    This class handles the "aox create user" command.
*/

CreateUser::CreateUser( StringList * args )
    : AoxCommand( args ), d( new CreateUserData )
{
}


void CreateUser::execute()
{
    if ( !d->user ) {
        parseOptions();
        Utf8Codec c;
        UString login = c.toUnicode( next() );
        UString passwd = c.toUnicode( next() );
        String address = next();
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( login.isEmpty() || passwd.isEmpty() || address.isEmpty() )
            error( "Username, password, and address must be non-empty." );
        if ( !validUsername( login ) )
            error( "Invalid username: " + login.utf8() );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        database( true );
        OCClient::setup();
        AddressCache::setup();
        Mailbox::setup( this );

        d->user = new User;
        d->user->setLogin( login );
        d->user->setSecret( passwd );
        d->user->setAddress( p.addresses()->first() );
        d->user->refresh( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->query ) {
        if ( d->user->state() == User::Unverified )
            return;

        if ( d->user->state() != User::Nonexistent )
            error( "User " + d->user->login().utf8() + " already exists." );

        d->query = d->user->create( this );
        d->user->execute();
    }

    if ( !d->query->done() )
        return;

    if ( d->query->failed() )
        error( "Couldn't create user: " + d->query->error() );

    finish();
}



class DeleteUserData
    : public Garbage
{
public:
    DeleteUserData()
        : user( 0 ), t( 0 ), query( 0 )
    {}

    User * user;
    Transaction * t;
    Query * query;
};


/*! \class DeleteUser users.h
    This class handles the "aox delete user" command.
*/

DeleteUser::DeleteUser( StringList * args )
    : AoxCommand( args ), d( new DeleteUserData )
{
}


void DeleteUser::execute()
{
    if ( !d->user ) {
        parseOptions();
        Utf8Codec c;
        UString login = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( login.isEmpty() )
            error( "No username supplied." );
        if ( !validUsername( login ) )
            error( "Invalid username: " + login.utf8() );

        database( true );
        OCClient::setup();
        AddressCache::setup();
        Mailbox::setup( this );

        d->user = new User;
        d->user->setLogin( login );
        d->user->refresh( this );

        d->query =
            new Query( "select m.id,m.name from mailboxes m join users u "
                       "on (m.owner=u.id) where u.login=$1", this );
        d->query->bind( 1, login );
        d->query->execute();
    }

    if ( !choresDone() )
        return;

    if ( d->user->state() == User::Unverified )
        return;

    if ( !d->query->done() )
        return;

    if ( !d->t ) {
        if ( d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login().utf8() );

        if ( !opt( 'f' ) && d->query->hasResults() ) {
            fprintf( stderr, "User %s still owns the following mailboxes:\n",
                     d->user->login().utf8().cstr() );
            while ( d->query->hasResults() ) {
                Row * r = d->query->nextRow();
                String s = r->getString( "name" );
                fprintf( stderr, "%s\n", s.cstr() );
            }
            fprintf( stderr, "(Use 'aox delete user -f %s' to delete the "
                     "mailboxes too.)\n", d->user->login().utf8().cstr() );
            exit( -1 );
        }

        List<Query> aliases;
        d->t = new Transaction( this );
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();
            UString s = r->getUString( "name" );
            Mailbox * m = Mailbox::obtain( s, false );
            if ( !m || m->remove( d->t ) == 0 )
                error( "Couldn't delete mailbox " + s.utf8() );
            Query * q = new Query( "delete from aliases where mailbox=$1", 0 );
            q->bind( 1, r->getInt( "id" ) );
            aliases.append( q );
        }
        d->query = d->user->remove( d->t );
        List<Query>::Iterator it( aliases );
        while ( it ) {
            d->t->enqueue( it );
            ++it;
        }
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't delete user: " + d->t->error() );

    finish();
}



/*! \class ChangePassword users.h
    This class handles the "aox change password" command.
*/

ChangePassword::ChangePassword( StringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void ChangePassword::execute()
{
    if ( !q ) {
        parseOptions();
        Utf8Codec c;
        UString login = c.toUnicode( next() );
        UString passwd = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( login.isEmpty() || passwd.isEmpty() )
            error( "No username and password supplied." );
        if ( !validUsername( login ) )
            error( "Invalid username: " + login.utf8() );

        database( true );

        User * u = new User;
        u->setLogin( login );
        u->setSecret( passwd );
        q = u->changeSecret( this );
        if ( q->failed() )
            error( q->error() );
        u->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() )
        error( "Couldn't change password: " + q->error() );

    finish();
}



class ChangeUsernameData
    : public Garbage
{
public:
    ChangeUsernameData()
        : user( 0 ), t( 0 ), query( 0 )
    {}

    User * user;
    UString newname;
    Transaction * t;
    Query * query;
};


/*! \class ChangeUsername users.h
    This class handles the "aox change username" command.
*/

ChangeUsername::ChangeUsername( StringList * args )
    : AoxCommand( args ), d( new ChangeUsernameData )
{
}


void ChangeUsername::execute()
{
    if ( !d->user ) {
        parseOptions();
        Utf8Codec c;
        UString name = c.toUnicode( next() );
        d->newname = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( name.isEmpty() || d->newname.isEmpty() )
            error( "Old and new usernames not supplied." );
        if ( !validUsername( name ) )
            error( "Invalid username: " + name.utf8() );
        if ( !validUsername( d->newname ) )
            error( "Invalid username: " + d->newname.utf8() );

        database( true );
        AddressCache::setup();
        Mailbox::setup( this );

        d->user = new User;
        d->user->setLogin( name );
        d->user->refresh( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->t ) {
        if ( d->user->state() == User::Unverified )
            return;

        if ( d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login().utf8() );

        d->t = new Transaction( this );

        Query * q =
            new Query( "update users set login=$2 where id=$1", this );
        q->bind( 1, d->user->id() );
        q->bind( 2, d->newname );
        d->t->enqueue( q );

        d->query =
            new Query( "select name from mailboxes where deleted='f' and "
                       "name like '/users/'||$1||'/%'", this );
        d->query->bind( 1, d->user->login() );
        d->t->enqueue( d->query );

        d->t->execute();
    }

    if ( d->query && d->query->done() ) {
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();

            UString name = r->getUString( "name" );
            UString newname = name;
            int i = name.find( '/' );
            newname.truncate( i );
            newname.append( d->newname );
            i = name.find( '/', i+1 );
            if ( i >= 0 )
                newname.append( name.mid( i ) );

            Query * q;

            Mailbox * from = Mailbox::obtain( name );
            uint uidvalidity = from->uidvalidity();

            Mailbox * to = Mailbox::obtain( newname );
            if ( to->deleted() ) {
                if ( to->uidvalidity() > uidvalidity ||
                     to->uidnext() > 1 )
                    uidvalidity = to->uidvalidity() + 1;
                q = new Query( "delete from mailboxes where id=$1", this );
                q->bind( 1, to->id() );
                d->t->enqueue( q );
            }

            q = new Query( "update mailboxes set name=$2,uidvalidity=$3 "
                           "where id=$1", this );
            q->bind( 1, from->id() );
            q->bind( 2, newname );
            q->bind( 3, uidvalidity );

            d->t->enqueue( q );
        }

        d->t->commit();
        d->query = 0;
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't change username: " + d->t->error() );

    finish();
}



class ChangeAddressData
    : public Garbage
{
public:
    ChangeAddressData()
        : user( 0 ), address( 0 ), t( 0 ), query( 0 )
    {}

    User * user;
    Address * address;
    Transaction * t;
    Query * query;
};


/*! \class ChangeAddress users.h
    This class handles the "aox change address" command.
*/

ChangeAddress::ChangeAddress( StringList * args )
    : AoxCommand( args ), d( new ChangeAddressData )
{
}


void ChangeAddress::execute()
{
    if ( !d->user ) {
        parseOptions();
        Utf8Codec c;
        UString name = c.toUnicode( next() );
        String address = next();
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( name.isEmpty() || address.isEmpty() )
            error( "Username and address must be non-empty." );
        if ( !validUsername( name ) )
            error( "Invalid username: " + name.utf8() );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        database( true );
        AddressCache::setup();
        Mailbox::setup( this );

        d->address = p.addresses()->first();
        d->user = new User;
        d->user->setLogin( name );
        d->user->refresh( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->t ) {
        if ( d->user->state() == User::Unverified )
            return;

        if ( d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login().utf8() );

        d->t = new Transaction( this );
        List< Address > l;
        l.append( d->address );
        AddressCache::lookup( d->t, &l, this );
        d->t->execute();
    }

    if ( d->address->id() == 0 )
        return;

    if ( !d->query ) {
        d->query =
            new Query( "update aliases set address=$2 where id="
                       "(select alias from users where id=$1)", this );
        d->query->bind( 1, d->user->id() );
        d->query->bind( 2, d->address->id() );
        d->t->enqueue( d->query );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't change address: " + d->t->error() );

    finish();
}
