// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "allocator.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "configuration.h"
#include "occlient.h"
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


class AdminHelper: public EventHandler {
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


class UserLister: public AdminHelper {
public:
    void execute() {
        AdminHelper::execute();
        if ( !query->done() )
            return;
        Row * r = query->nextRow();
        while ( r ) {
            fprintf( stdout, "%s\n", r->getString( "login" ).cstr() );
            r = query->nextRow();
        }
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


static void addEternal( void * v, const char * t )
{
    Allocator::addEternal( v, t );
}


static void createUser( const char * login, const char * password,
                        const char * address = 0 )
{
    User * u = new User;
    addEternal( u, "user" );
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
        fprintf( stderr, "%s: Internal error. Couldn't create user.\n",
                 name );
        Loop::shutdown();
    }
}


static void deleteUser( const char * login )
{
    User * u = new User;
    addEternal( u, "user" );
    u->setLogin( login );
    u->remove( new AdminHelper );
}


void changePassword( const char * login, const char * password )
{
    User * u = new User;
    addEternal( u, "user" );
    u->setLogin( login );
    u->setSecret( password );
    query = u->changeSecret( new AdminHelper );
    if ( !query || query->failed() ) {
        fprintf( stderr, "%s: Internal error. "
                 "Couldn't change password for user %s.\n", name, login );
        Loop::shutdown();
    }
}


void listUsers( const char * pattern )
{
    String p;
    uint i = 0;
    while ( pattern[i] ) {
        if ( pattern[i] == '*' )
            p.append( '%' );
        else
            p.append( pattern[i] );
        i++;
    }
    query = new Query( "select login from users where login like $1",
                       new UserLister );
    query->bind( 1, p );
    query->execute();
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
         verb != "change" &&
         verb != "list" &&
         verb != "delete" )
        error( verb + ": unknown verb" );

    if ( noun != "user" &&
         noun != "users" &&
         noun != "mailbox" &&
         noun != "password" )
        error( noun + ": unknown noun" );

    // typical mailstore crud
    Configuration::setup( "mailstore.conf" );

    Loop::setup();

    Log l( Log::General );
    global.setLog( &l );
    LogClient::setup();

    OCClient::setup();
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
    else if ( verb == "change" && noun == "password" ) {
        if ( argc == 5 )
            changePassword( argv[3], argv[4] );
        else
            error( "Wrong arguments (need login/address and password)" );
    }
    else if ( verb == "list" && noun == "users" ) {
        if ( argc > 4 )
            error( "Too many arguments (need login glob pattern)" );
        else if ( argc == 4 )
            listUsers( argv[3] );
        else
            listUsers( "*" );
    }
    else if ( ( verb == "create" || verb == "delete" ) &&
              noun == "mailbox" )
    {
        if ( argc < 4 )
            error( "Too few arguments (need a mailbox name)." );
        else if ( argc > 4 )
            error( "Unknown argument following mailbox name." );

        Mailbox *m = new Mailbox( argv[3] );
        addEternal( m, "mailbox" );
        if ( verb == "create" )
            query = m->create( new AdminHelper );
        else if ( verb == "delete" )
            query = m->remove( new AdminHelper );

        if ( !query || query->failed() ) {
            fprintf( stderr, "%s: Internal error. Couldn't create mailbox.\n",
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

    addEternal( query, "query to be run" );
    Loop::start();
    return status;
}
