// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailboxes.h"

#include "utf.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "estringlist.h"
#include "transaction.h"

#include <stdio.h>


static AoxFactory<ListMailboxes>
f4( "list", "mailboxes", "Display existing mailboxes.",
    "    Synopsis: aox list mailboxes [-d] [-o user] [pattern]\n\n"
    "    Displays a list of mailboxes matching the specified shell\n"
    "    glob pattern. Without a pattern, all mailboxes are listed.\n\n"
    "    The -d flag includes deleted mailboxes in the list.\n\n"
    "    The \"-o username\" flag restricts the list to mailboxes\n"
    "    owned by the specified user.\n\n"
    "    The -s flag shows a count of messages and the total size\n"
    "    of messages in each mailbox.\n\n"
    "    ls is an acceptable abbreviation for list.\n\n"
    "    Examples:\n\n"
    "      aox list mailboxes\n"
    "      aox ls mailboxes /users/ab?cd*\n" );


/*! \class ListMailboxes mailboxes.h
    This class handles the "aox list mailboxes" command.
*/

ListMailboxes::ListMailboxes( EStringList * args )
    : AoxCommand( args ), q( 0 )
{
}


void ListMailboxes::execute()
{
    if ( !q ) {
        EString owner;
        EString p( next() );

        while ( p[0] == '-' ) {
            if ( p == "-d" ) {
                setopt( 'd' );
            }
            else if ( p == "-s" ) {
                setopt( 's' );
            }
            else if ( p == "-o" ) {
                setopt( 'o' );
                owner = next();
                if ( owner.isEmpty() )
                    error( "No username specified with -o." );
            }
            else {
                error( "Bad option name: " + p.quoted() );
            }

            p = next();
        }

        Utf8Codec c;
        UString pattern = c.toUnicode( p );
        if ( !c.valid() )
            error( "Pattern encoding: " + c.error() );
        end();

        database();

        EString s( "select name,login as owner" );
        if ( opt( 's' ) > 0 ) {
            EString num( "select count(*) from mailbox_messages "
                         "where mailbox=m.id" );
            EString size( "select sum(rfc822size) from messages ma "
                          "join mailbox_messages mm on (ma.id=mm.message) "
                          "where mm.mailbox=m.id" );
            s.append( ", coalesce((" + num + "), 0)::bigint as messages"
                      ", coalesce((" + size + "), 0)::bigint as size" );
        }
        s.append( " from mailboxes m left join users u on (m.owner=u.id)" );

        int n = 1;
        EStringList where;
        if ( opt( 'd' ) == 0 )
            where.append( "not deleted" );
        if ( !pattern.isEmpty() )
            where.append( "name like $" + fn( n++ ) );
        if ( opt( 'o' ) > 0 )
            where.append( "login like $" + fn( n ) );

        if ( !where.isEmpty() ) {
            s.append( " where " );
            s.append( where.join( " and " ) );
        }

        q = new Query( s, this );
        if ( !pattern.isEmpty() )
            q->bind( 1, sqlPattern( pattern ) );
        if ( !owner.isEmpty() )
            q->bind( n, owner );
        q->execute();
    }

    while ( q->hasResults() ) {
        Row * r = q->nextRow();

        UString n( r->getUString( "name" ) );
        printf( "%s", n.utf8().cstr() );

        if ( opt( 's' ) > 0 ) {
            EString s;
            int64 messages = r->getBigint( "messages" );
            int64 size = r->getBigint( "size" );
            s.appendNumber( messages );
            if ( messages == 1 )
                s.append( " message, " );
            else
                s.append( " messages, " );
            s.append( EString::humanNumber( size ) );
            s.append( " bytes" );
            if ( messages != 0 )
                printf( " (%s)", s.cstr() );
        }
        printf( "\n" );
    }

    if ( !q->done() )
        return;

    finish();
}



class CreateMailboxData
    : public Garbage
{
public:
    CreateMailboxData()
        : user( 0 ), m( 0 ), t( 0 ), q( 0 )
    {}

    UString name;
    User * user;
    Mailbox * m;
    Transaction * t;
    Query * q;
};


static AoxFactory<CreateMailbox>
f2( "create", "mailbox", "Create a new mailbox.",
    "    Synopsis: aox add mailbox <name> [username]\n\n"
    "    Creates a new mailbox with the specified name and,\n"
    "    if a username is specified, owned by that user.\n\n"
    "    The mailbox name must be fully-qualified (begin with /),\n"
    "    unless a username is specified, in which case unqualified\n"
    "    names are assumed to be under the user's home directory.\n" );


/*! \class CreateMailbox mailboxes.h
    This class handles the "aox add mailbox" command.
*/

CreateMailbox::CreateMailbox( EStringList * args )
    : AoxCommand( args ), d( new CreateMailboxData )
{
}


void CreateMailbox::execute()
{
    if ( d->name.isEmpty() ) {
        parseOptions();
        Utf8Codec c;
        d->name = c.toUnicode( next() );
        UString owner = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( d->name.isEmpty() )
            error( "No mailbox name supplied." );

        database( true );
        Mailbox::setup( this );

        if ( !owner.isEmpty() ) {
            d->user = new User;
            d->user->setLogin( owner );
            d->user->refresh( this );
        }
    }

    if ( !choresDone() )
        return;

    if ( d->user && d->user->state() == User::Unverified )
        return;

    if ( !d->t ) {
        if ( d->user && d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login().utf8() );

        if ( d->user && !d->name.startsWith( "/" ) )
            d->name = d->user->home()->name() + "/" + d->name;

        d->m = Mailbox::obtain( d->name );
        if ( !d->m )
            error( "Can't create mailbox named " + d->name.utf8() );

        d->t = new Transaction( this );
        if ( d->m->create( d->t, d->user ) == 0 )
            error( "Couldn't create mailbox " + d->name.utf8() );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't create mailbox" );

    finish();
}



class DeleteMailboxData
    : public Garbage
{
public:
    DeleteMailboxData()
        : m( 0 ), t( 0 ), count( 0 ), zap( 0 )
    {}

    UString name;
    Mailbox * m;
    Transaction * t;
    Query * count;
    Query * zap;
};


static AoxFactory<DeleteMailbox>
f3( "delete", "mailbox", "Delete a mailbox.",
    "    Synopsis: aox delete mailbox [-f] <name>\n\n"
    "    Deletes the specified mailbox.\n\n"
    "    If -f is specified, the mailbox and any messages it contains\n"
    "    are deleted permanently. Otherwise only empty mailboxes are\n"
    "    deleted.\n\n"
    "    This command is synonymous with \"aox delete view\", and may\n"
    "    be used to delete mailboxes created with \"aox add view\".\n" );


/*! \class DeleteMailbox mailboxes.h
    This class handles the "aox delete mailbox" command.
*/

DeleteMailbox::DeleteMailbox( EStringList * args )
    : AoxCommand( args ), d( new DeleteMailboxData )
{
}


void DeleteMailbox::execute()
{
    if ( d->name.isEmpty() ) {
        parseOptions();
        Utf8Codec c;
        d->name = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( d->name.isEmpty() )
            error( "No mailbox name supplied." );

        database( true );
        Mailbox::setup( this );
    }

    if ( !choresDone() )
        return;

    if ( !d->t ) {
        d->m = Mailbox::obtain( d->name, false );
        if ( !d->m )
            error( "No mailbox named " + d->name.utf8() );

        d->t = new Transaction( this );
        Query * lock = new Query( "select * from mailboxes where "
                                  "id=$1 for update", this );
        lock->bind( 1, d->m->id() );
        d->t->enqueue( lock );
    }

    if ( opt( 'f' ) == 0 && !d->zap ) {
        if ( !d->count ) {
            d->count = new Query(
                "select "
                "(select count(*)::bigint from mailbox_messages"
                " where mailbox=$1)"
                "+"
                "(select count(*)::bigint from deleted_messages"
                " where mailbox=$1) "
                "as messages", this
            );
            d->count->bind( 1, d->m->id() );
            d->t->enqueue( d->count );
            d->t->execute();
        }

        if ( !d->count->done() )
            return;

        Row * r = d->count->nextRow();
        if ( d->count->failed() || !r )
            error( "Could not determine if any messages exist." );

        int64 messages = r->getBigint( "messages" );
        if ( messages != 0 )
            error( "Cannot delete mailbox: " + fn( messages ) +
                   " messages exist. (Use -f to force.)" );
    }

    if ( !d->zap ) {
        // First, we expunge the existing messages.
        Query * q = new Query(
            "insert into deleted_messages "
            "(mailbox,uid,message,modseq,deleted_by,reason) "
            "select mailbox,uid,message,modseq,$2,$3 "
            "from mailbox_messages where mailbox=$1",
            this
        );
        q->bind( 1, d->m->id() );
        q->bindNull( 2 );
        q->bind( 3, "aox delete -f" );
        d->t->enqueue( q );

        // Then we remove the messages that correspond to the
        // just-deleted messages, so long as they are not used
        // elsewhere. This is like what "aox vacuum" does. If
        // we were to just delete from deleted_messages, we'd
        // leave orphaned messages that vacuum wouldn't touch.

        q = new Query(
            "delete from messages where id in "
            "(select dm.message from deleted_messages dm"
            " left join mailbox_messages mm on (dm.message=mm.message)"
            " left join deliveries d on (dm.message=d.message)"
            " where mm.message is null and d.message is null and"
            " dm.mailbox=$1)", this
        );
        q->bind( 1, d->m->id() );
        d->t->enqueue( q );

        d->zap = d->m->remove( d->t );
        if ( !d->zap )
            error( "Couldn't delete mailbox " + d->name.utf8() );

        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't delete mailbox: " + d->t->error() );

    finish();
}
