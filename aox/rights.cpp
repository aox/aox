// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "rights.h"

#include "utf.h"
#include "user.h"
#include "query.h"
#include "mailbox.h"
#include "estringlist.h"
#include "permissions.h"
#include "transaction.h"

#include <stdio.h>


class ListRightsData
    : public Garbage
{
public:
    ListRightsData()
        : q( 0 )
    {}

    UString mailbox;
    UString identifier;
    Query * q;
};


static AoxFactory<ListRights>
f( "list", "rights", "Display permissions on a mailbox.",
   "    Synopsis: aox list rights <mailbox> [username]\n\n"
   "    Displays a list of users and the rights they have been\n"
   "    granted to the specified mailbox. If a username is given,\n"
   "    only that user's rights are displayed.\n\n"
   "    ls is an acceptable abbreviation for list.\n\n"
   "    Examples:\n\n"
   "      aox list rights /archives/mailstore-users anonymous\n"
   "      aox list rights /users/xyzzy/shared\n" );


/*! \class ListRights rights.h
    This class handles the "aox list rights" command.
*/

ListRights::ListRights( EStringList * args )
    : AoxCommand( args ), d( new ListRightsData )
{
}


void ListRights::execute()
{
    if ( d->mailbox.isEmpty() ) {
        parseOptions();
        Utf8Codec c;
        d->mailbox = c.toUnicode( next() );
        d->identifier = c.toUnicode( next() );
        end();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
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
            error( "No mailbox named " + d->mailbox.utf8().quoted() );

        EString s( "select identifier,rights from permissions p "
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
        printf( "%s: %s\n", r->getEString( "identifier" ).cstr(),
                describe( r->getEString( "rights" ) ).cstr() );
    }

    if ( !d->q->done() )
        return;

    if ( d->q->rows() == 0 ) {
        if ( d->identifier.isEmpty() )
            printf( "No rights found.\n" );
        else
            printf( "No rights found for identifier '%s'.\n",
                    d->identifier.utf8().cstr() );
    }

    finish();
}


/*! Returns a string describing the rights string \a s, depending on
    whether the user used -v or not.
*/

EString ListRights::describe( const EString &s )
{
    EString p( s );

    if ( opt( 'v' ) > 0 ) {
        EStringList l;
        uint i = 0;
        while ( i < s.length() )
            l.append( Permissions::describe( s[i++] ) );
        p.append( " (" );
        p.append( l.join( ", " ) );
        p.append( ")" );
    }

    return p;
}



class SetAclData
    : public Garbage
{
public:
    SetAclData()
        : mode( 0 ), user( 0 ), m( 0 ), t( 0 ), fetch( 0 ), store( 0 )
    {}

    int mode;
    UString mailbox;
    UString identifier;
    EString rights;
    EString oldRights;
    User * user;
    Mailbox * m;
    Transaction * t;
    Query * fetch;
    Query * store;
};


static AoxFactory<SetAcl>
f2( "setacl", "", "Manipulate permissions on a mailbox.",
    "    Synopsis: setacl [-d] <mailbox> <identifier> <rights>\n\n"
    "    Assigns the specified rights to the given identifier on the\n"
    "    mailbox. If the rights begin with + or -, the specified rights\n"
    "    are added to or subtracted from the existing rights; otherwise,\n"
    "    the rights are set to exactly those given.\n\n"
    "    With -d, the identifier's rights are deleted altogether.\n\n"
    "    A summary of the changes made is displayed when the operation\n"
    "    completes.\n" );

/*! \class SetAcl rights.h
    This class handles the "aox setacl" command.
*/

SetAcl::SetAcl( EStringList * args )
    : AoxCommand( args ), d( new SetAclData )
{
}


void SetAcl::execute()
{
    if ( d->mailbox.isEmpty() ) {
        parseOptions();
        Utf8Codec c;
        d->mailbox = c.toUnicode( next() );
        d->identifier = c.toUnicode( next() );
        d->rights = next();

        if ( !c.valid() )
            error( "Argument encoding: " + c.error() );
        if ( d->mailbox.isEmpty() || d->identifier.isEmpty() )
            error( "Mailbox and username must be non-empty." );

        if ( opt( 'd' ) == 0 ) {
            if ( d->rights[0] == '-' || d->rights[0] == '+' ) {
                if ( d->rights[0] == '+' )
                    d->mode = 1;
                else
                    d->mode = 2;
                d->rights = d->rights.mid( 1 );
            }

            if ( !Permissions::validRights( d->rights ) )
                error( "Invalid rights: " + d->rights.quoted() );
        }
        else {
            if ( !d->rights.isEmpty() )
                error( "No rights may be supplied with -d." );
        }

        database( true );
        Mailbox::setup( this );

        if ( d->identifier != "anyone" ) {
            d->user = new User;
            d->user->setLogin( d->identifier );
            d->user->refresh( this );
        }
    }

    if ( !choresDone() )
        return;

    if ( !d->fetch ) {
        if ( d->user ) {
            if ( d->user->state() == User::Unverified )
                return;
            if ( opt( 'd' ) == 0 && d->user->state() == User::Nonexistent )
                error( "No user named " + d->identifier.utf8().quoted() );
        }

        d->m = Mailbox::obtain( d->mailbox, false );
        if ( !d->m )
            error( "No mailbox named " + d->mailbox.utf8() );

        if ( d->user && d->user->id() == d->m->owner() )
            error( "Can't change mailbox owner's rights." );

        d->t = new Transaction( this );
        Query * q = new Query( "lock permissions in exclusive mode", this );
        d->t->enqueue( q );
        d->fetch = new Query( "select rights from permissions where "
                              "mailbox=$1 and identifier=$2", this );
        d->fetch->bind( 1, d->m->id() );
        d->fetch->bind( 2, d->identifier );
        d->t->enqueue( d->fetch );
        d->t->execute();
    }

    if ( !d->fetch->done() )
        return;

    if ( !d->store ) {
        Row * r = d->fetch->nextRow();
        if ( r )
            d->oldRights = r->getEString( "rights" );

        Permissions * p =
            new Permissions( d->m, d->identifier, d->oldRights );

        if ( opt( 'd' ) > 0 ) {
            d->store =
                new Query( "delete from permissions where mailbox=$1 "
                           "and identifier=$2", this );
            d->store->bind( 1, d->m->id() );
            d->store->bind( 2, d->identifier );
        }
        else {
            if ( d->mode == 0 )
                p->set( d->rights );
            else if ( d->mode == 1 )
                p->allow( d->rights );
            else if ( d->mode == 2 )
                p->disallow( d->rights );

            if ( r )
                d->store = new Query( "update permissions set rights=$3 "
                                      "where mailbox=$1 and identifier=$2",
                                      this );
            else
                d->store = new Query( "insert into permissions "
                                      "(mailbox,identifier,rights) "
                                      "values ($1,$2,$3)", this );

            d->store->bind( 1, d->m->id() );
            d->store->bind( 2, d->identifier );
            d->store->bind( 3, p->string() );
        }

        d->t->enqueue( d->store );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't assign rights" );

    if ( opt( 'd' ) > 0 ) {
        printf( "Deleted rights on mailbox '%s' for user '%s'\n",
                d->mailbox.utf8().cstr(), d->identifier.utf8().cstr() );
    }
    else {
        if ( d->mode == 0 ) {
            printf( "Granted rights '%s' on mailbox '%s' to user '%s'\n",
                    d->rights.cstr(), d->mailbox.utf8().cstr(),
                    d->identifier.utf8().cstr() );
        }
        else if ( d->mode == 1 ) {
            printf( "Granted rights '%s'+%s on mailbox '%s' to user '%s'\n",
                    d->rights.cstr(), d->oldRights.cstr(),
                    d->mailbox.utf8().cstr(), d->identifier.utf8().cstr() );
        }
        else if ( d->mode == 2 ) {
            printf( "Removed rights '%s' on mailbox '%s' from user '%s'\n",
                    d->rights.cstr(), d->mailbox.utf8().cstr(),
                    d->identifier.utf8().cstr() );
        }
    }

    finish();
}
