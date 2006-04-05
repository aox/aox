// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "user.h"

#include "allocator.h"
#include "address.h"
#include "mailbox.h"
#include "query.h"
#include "configuration.h"
#include "transaction.h"
#include "addresscache.h"
#include "occlient.h"


class UserData
    : public Garbage
{
public:
    UserData()
        : id( 0 ), inbox( 0 ), home( 0 ), address( 0 ),
          q( 0 ), result( 0 ), t( 0 ), user( 0 ),
          state( User::Unverified ),
          mode( LoungingAround )
    {}

    String login;
    String secret;
    uint id;
    Mailbox * inbox;
    Mailbox * home;
    Address * address;
    Query * q;
    Query * result;
    Transaction * t;
    EventHandler * user;
    String error;
    User::State state;

    enum Operation {
        LoungingAround,
        Creating,
        Refreshing,
        ChangingSecret
    };
    Operation mode;
};


/*! \class User user.h

    The User class models a single Archiveopteryx user, which may be
    able to log in, own Mailbox objects, etc.
*/


/*! Constructs an empty User. The result does not map to anything in
    the database.
*/

User::User()
    : d( new UserData )
{
    // nothing
}


/*! Returns the user's state, which is either Unverified (the object has
    made no attempt to refresh itself from the database), Refreshed (the
    object was successfully refreshed) or Nonexistent (the object tried
    to refresh itself, but there was no corresponsing user in the
    database).

    The state is Unverified initially and is changed by refresh().
*/

User::State User::state() const
{
    return d->state;
}


/*! Returns the user's ID, ie. the primary key from the database, used
    to link various other tables to this user.
*/

uint User::id() const
{
    return d->id;
}


/*! Sets this User object to have login \a string. The database is not
    updated - \a string is not used except to create Query objects
    during e.g. refresh().
*/

void User::setLogin( const String & string )
{
    d->login = string;
}


/*! Returns the User's login string, which is an empty string
    initially and is set up by refresh().
*/

String User::login() const
{
    return d->login;
}


/*! Sets this User to have \a secret as password. The database isn't
    updated unless e.g. create() is called.
*/

void User::setSecret( const String & secret )
{
    d->secret = secret;
}


/*! Returns the User's secret (password), which is an empty string
    until refresh() has fetched the database contents.
*/

String User::secret() const
{
    return d->secret;
}


/*! Returns a pointer to the user's inbox, or a null pointer if this
    object doesn't know it or if the user has none.
*/

Mailbox * User::inbox() const
{
    return d->inbox;
}


/*! Sets this User object to have address \a a. The database is not
    updated - \a a is not used except maybe to search in refresh().
*/

void User::setAddress( Address * a )
{
    d->address = a;
}


/*! Returns the address belonging to this User object, or a null
    pointer if this User has no Address.
*/

Address * User::address()
{
    if ( !d->address ) {
        // XXX: This does not match the documentation above.
        String dom = Configuration::hostname();
        uint i = dom.find( '.' );
        if ( i > 0 )
            dom = dom.mid( i+1 );
        d->address = new Address( "", d->login, dom );
    }
    return d->address;
}


/*! Returns the user's "home directory" - the mailbox under which all
    of the user's mailboxes reside.

    This is read-only since at the moment, the Archiveopteryx servers
    only permit one setting: "/users/" + login. However, the database
    permits more namespaces than just "/users", so one day this may
    change.
*/

Mailbox * User::home() const
{
    return d->home;
}


/*! Returns true if this user is known to exist in the database, and
    false if it's unknown or doesn't exist.
*/

bool User::exists()
{
    return d->id > 0;
}


void User::execute()
{
    switch( d->mode ) {
    case UserData::Creating:
        createHelper();
        break;
    case UserData::Refreshing:
        refreshHelper();
        break;
    case UserData::ChangingSecret:
        csHelper();
        break;
    case UserData::LoungingAround:
        break;
    }
}


static PreparedStatement * psl;
static PreparedStatement * psa;


/*! Starts refreshing this object from the database, and remembers to
    call \a user when the refresh is complete.
*/

void User::refresh( EventHandler * user )
{
    if ( d->q )
        return;
    d->user = user;
    if ( !psl ) {
        psl = new PreparedStatement(
            "select u.id, u.login, u.secret, a.name, a.localpart, "
            "a.domain, al.mailbox as inbox, n.name as parentspace "
            "from users u join aliases al on (u.alias=al.id) "
            "join addresses a on (al.address=a.id) "
            "join namespaces n on (u.parentspace=n.id) "
            "where lower(u.login)=$1"
        );

        psa = new PreparedStatement(
            "select u.id, u.login, u.secret, a.name, a.localpart, "
            "a.domain, al.mailbox as inbox, n.name as parentspace "
            "from users u join aliases al on (u.alias=al.id) "
            "join addresses a on (al.address=a.id) "
            "join namespaces n on (u.parentspace=n.id) "
            "where lower(a.localpart)=$1 and lower(a.domain)=$2"
        );
        Allocator::addEternal( psl, "select user by login" );
        Allocator::addEternal( psa, "select user by address" );
    }
    if ( !d->login.isEmpty() ) {
        d->q = new Query( *psl, this );
        d->q->bind( 1, d->login.lower() );
    }
    else if ( d->address ) {
        d->q = new Query( *psa, this );
        d->q->bind( 1, d->address->localpart().lower() );
        d->q->bind( 2, d->address->domain().lower() );
    }
    if ( d->q ) {
        d->q->execute();
        d->mode = UserData::Refreshing;
    }
    else {
        user->execute();
    }
}


/*! Parses the query results for refresh(). */

void User::refreshHelper()
{
    if ( !d->q || !d->q->done() )
        return;

    d->state = Nonexistent;
    Row *r = d->q->nextRow();
    if ( r ) {
        d->id = r->getInt( "id" );
        d->login = r->getString( "login" );
        d->secret = r->getString( "secret" );
        d->inbox = Mailbox::find( r->getInt( "inbox" ) );
        d->home = Mailbox::obtain( r->getString( "parentspace" ) + "/" +
                                   d->login, true );
        String n = r->getString( "name" );
        String l = r->getString( "localpart" );
        String h = r->getString( "domain" );
        d->address = new Address( n, l, h );
        d->state = Refreshed;
    }
    if ( d->user )
        d->user->execute();
}


/*! This function is used to create a user on behalf of \a owner.

    It returns a pointer to a Query that can be used to track the
    progress of the operation. If (and only if) this Query hasn't
    already failed upon return from this function, the caller must
    call execute() to initiate the operation.

    The query may fail immediately if the user is not valid(), or if it
    already exists().

    This function (indeed, this whole class) is overdue for change.
*/

Query * User::create( EventHandler * owner )
{
    Query *q = new Query( owner );

    if ( !valid() ) {
        q->setError( "Invalid user data." );
    }
    else if ( exists() ) {
        q->setError( "User exists already." );
    }
    else {
        d->q = 0;
        d->t = new Transaction( this );
        d->mode = UserData::Creating;
        d->user = owner;
        d->result = q;
    }

    return q;
}


/*! This private function carries out create() work on behalf of
    execute().
*/

void User::createHelper()
{
    Address * a = address();

    if ( !d->q ) {
        if ( !a->id() ) {
            List< Address > l;
            l.append( a );
            AddressCache::lookup( d->t, &l, this );
        }

        d->q = new Query( "select name from namespaces where id="
                          "(select max(id) from namespaces)", this );
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( d->q->done() && a->id() && !d->inbox ) {
        Row *r = d->q->nextRow();
        if ( !r ) {
            d->t->commit();
            return;
        }

        String m = r->getString( "name" ) + "/" + d->login + "/INBOX";
        d->inbox = Mailbox::obtain( m, true );

        if ( d->inbox->deleted() ) {
            d->q = new Query( "update mailboxes set deleted='f' where id=$1",
                              this );
            d->q->bind( 1, d->inbox->id() );
        }
        else {
            d->q = new Query( "insert into mailboxes (name) values ($1)",
                              this );
            d->q->bind( 1, m );
        }
        d->t->enqueue( d->q );

        Query * q1
            = new Query( "insert into aliases (address, mailbox) values "
                         "($1, (select id from mailboxes where name=$2))",
                         this );
        q1->bind( 1, a->id() );
        q1->bind( 2, m );
        d->t->enqueue( q1 );

        Query * q2
            = new Query( "insert into users "
                         "(alias,parentspace,login,secret) values "
                         "((select id from aliases where address=$1),"
                         "(select max(id) from namespaces),$2,$3)",
                         this );
        q2->bind( 1, a->id() );
        q2->bind( 2, d->login );
        q2->bind( 3, d->secret );
        d->t->enqueue( q2 );

        Query *q3 =
            new Query( "update mailboxes set "
                       "owner=(select currval('users_id_seq')::int) "
                       "where name=$1", this );
        q3->bind( 1, m );
        d->t->enqueue( q3 );

        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        d->result->setError( d->t->error() );
    }
    else {
        d->result->setState( Query::Completed );

        OCClient::send( "mailbox " + d->inbox->name().quoted() + " new" );
    }

    d->result->notify();
}


/*! Enqueues a query to remove this user in the Transaction \a t, and
    returns the Query. Does not commit the Transaction.

    XXX: This function doesn't tell ocd about the user going away, and
    ocd wouldn't know what to do about it anyway.
*/

Query * User::remove( Transaction * t )
{
    Query * q = new Query( "delete from users where login=$1", 0 );
    q->bind( 1, d->login );
    t->enqueue( q );
    return q;
}


/*! This function changes a user's password on behalf of \a owner.

    It returns a pointer to a Query that can be used to track the
    progress of the operation. If (and only if) this Query hasn't
    already failed upon return from this function, the caller must
    call execute() to initiate the operation.

    XXX: This function doesn't tell ocd about the user going away, and
    ocd wouldn't know what to do about it anyway.
*/

Query * User::changeSecret( EventHandler * owner )
{
    Query *q = new Query( owner );

    d->q = 0;
    d->mode = UserData::ChangingSecret;
    d->user = owner;
    d->result = q;

    return q;
}


/*! Finish the work of changeSecret(). */

void User::csHelper()
{
    if ( !d->q ) {
        d->q =
            new Query( "update users set secret=$1 where login=$2",
                       this );
        d->q->bind( 1, d->secret );
        d->q->bind( 2, d->login );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() )
        d->result->setError( d->q->error() );
    else
        d->result->setState( Query::Completed );

    d->result->notify();
}


/*! Returns true if this user is valid, that is, if it has the
    information that must be present in order to write it to the
    database and do not have defaults.

    Sets error() if applicable.
*/

bool User::valid()
{
    if ( d->login.isEmpty() ) {
        d->error = "Login name must be supplied";
        return false;
    }

    return true;
}


/*! Returns a textual description of the last error seen, or a null
    string if everything is in order. The string is set by valid() and
    perhaps other functions.
*/

String User::error() const
{
    return d->error;
}
