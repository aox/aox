// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "allocator.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "configuration.h"
#include "logclient.h"
#include "address.h"
#include "addresscache.h"
#include "user.h"
#include "loop.h"
#include "log.h"
#include "mailbox.h"

#include <stdlib.h>
#include <stdio.h>


static int status;
static Query *query;
static const char * name;


/*! \nodoc */

class AdminHelper : public EventHandler {
public:
    void execute() {
        if ( query->failed() ) {
            fprintf( stderr, "%s: SQL error: %s\n",
                     name, query->error().cstr() );
            status = -1;
        }
        if ( query->done() )
            Loop::shutdown();
    }
};


static void error( String m )
{
    fprintf( stderr, "%s: %s\nUsage:\n  %s verb noun arguments\n",
             name, m.cstr(), name );
    fprintf( stdout,
             "Examples:\n"
             "    %s create user <login> <password> <address@domain>\n"
             "    %s rename user <login> <newlogin>\n"
             "    %s rename user <login> <newaddress@newdomain>\n"
             "    %s delete user <login>\n",
             name, name, name, name );
    exit( -1 );
}

static void addRoot( void * v )
{
    Allocator::addRoot( v );
}


static void createUser( const char * login, const char * password,
                        const char * address = 0 )
{
    User * u = new User;
    addRoot( u );
    u->setLogin( login );
    u->setSecret( password );
    if ( !u->valid() )
        error( u->error() );

    if ( address ) {
        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );
        u->setAddress( p.addresses()->first() );
    }

    query = u->create( new AdminHelper );
    if ( !query || query->failed() ) {
        fprintf( stderr, "%s: Internal error. Couldn't create user.", name );
        Loop::shutdown();
    }
}


static void deleteUser( const char * login )
{
    User * u = new User;
    addRoot( u );
    u->setLogin( login );
    if ( !u->valid() )
        error( u->error() );

    u->remove( new AdminHelper );
}


int main( int argc, char *argv[] )
{
    Scope global;

    // initial setup
    String verb, noun;
    status = 0;

    name = argv[0];
    verb = argv[1];
    noun = argv[2];
    verb = verb.lower();
    noun = noun.lower();

    // undocumented synomyms to please irritable users like... me. uh.
    if ( verb == "add" || verb == "new" )
        verb = "create";
    else if ( verb == "remove" || verb == "del" )
        verb = "delete";

    // get rid of illegal verbs and nouns
    if ( verb != "create" &&
         verb != "rename" &&
         verb != "delete" )
        error( verb + ": unknown verb" );

    if ( noun != "user" && noun != "mailbox" )
        error( noun + ": unknown noun" );

    // typical mailstore crud
    Configuration::setup( "mailstore.conf" );

    Loop::setup();

    Log l( Log::General );
    global.setLog( &l );
    LogClient::setup();

    Database::setup();
    AddressCache::setup();
    Configuration::report();
    Mailbox::setup();

    // check each combination
    if ( verb == "create" && noun == "user" ) {
        if ( argc <= 4 )
            error( "Too few arguments (need login and password)" );
        else if ( argc == 5 )
            createUser( argv[3], argv[4] );
        else if ( argc == 6 )
            createUser( argv[3], argv[4], argv[5] );
        else
            error( "Unknown argument following login, password and address" );
    }
    else if ( verb == "delete" && noun == "user" ) {
        if ( argc <= 2 )
            error( "Too few arguments (need login)" );
        else
            deleteUser( argv[3] );
    }
    else if ( ( verb == "create" || verb == "delete" ) &&
              noun == "mailbox" )
    {
        if ( argc < 4 )
            error( "Too few arguments (need a mailbox name)." );
        else if ( argc > 4 )
            error( "Unknown argument following mailbox name." );

        Mailbox *m = new Mailbox( argv[3] );
        addRoot( m );
        if ( verb == "create" )
            query = m->create( new AdminHelper );
        else if ( verb == "delete" )
            query = m->remove( new AdminHelper );

        if ( !query || query->failed() ) {
            fprintf( stderr, "%s: Internal error. Couldn't create mailbox.",
                     argv[3] );
            exit( -1 );
        }
        else if ( query->done() ) {
            exit( 0 );
        }
    }
    else { // .. and if we don't know that verb/noun combination:
        error( "Sorry, not implemented: " + verb + " " + noun );
    }

    addRoot( query );
    Loop::start();
    return status;
}
