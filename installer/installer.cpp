// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "configuration.h"
#include "eventloop.h"
#include "database.h"
#include "entropy.h"
#include "query.h"
#include "event.h"
#include "file.h"
#include "md5.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>


class Dispatcher * d;
bool report = false;


void error( String );
bool exists( String );
void oryxGroup();
void oryxUser();
void database();
void configFile();


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;

    StringList args;
    while ( ac-- > 0 )
        args.append( new String( *av++ ) );
    args.shift();
    while ( !args.isEmpty() ) {
        String s( *args.shift() );
        if ( s == "-n" )
            report = true;
        else
            error( "Unrecognised argument: '" + s + "'" );
    }

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    struct passwd * p = getpwnam( PGUSER );
    if ( !p )
        error( "PostgreSQL superuser '" PGUSER "' does not exist." );
    seteuid( p->pw_uid );

    if ( report )
        printf( "Reporting what the installer needs to do.\n" );

    String cf( CONFIGDIR );
    cf.append( "/mailstore.conf" );
    if ( !report && exists( cf ) )
        error( cf + " already exists -- exiting without changes.\n"
               " - Not creating user " ORYXUSER " in group " ORYXGROUP ".\n"
               " - Not creating PostgreSQL user " DBUSER ".\n"
               " - Not creating PostgreSQL database " DBNAME ".\n"
               " - Not creating the Oryx schema.\n"
               " - Not creating stub configuration file." );

    EventLoop::setup();
    oryxGroup();
    oryxUser();
    database();

    if ( d )
        Allocator::addEternal( d, "dispatcher" );
    EventLoop::global()->start();
}


void error( String m )
{
    fprintf( stderr, "%s\n", m.cstr() );
    exit( -1 );
}


bool exists( String f )
{
    struct stat st;
    return stat( f.cstr(), &st ) == 0;
}


void oryxGroup()
{
    struct group * g = getgrnam( ORYXGROUP );
    if ( g )
        return;

    if ( report ) {
        printf( " - Create a group named '" ORYXGROUP "' (e.g. \"groupadd "
                ORYXGROUP "\").\n" );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/groupadd" ) )
        cmd = "/usr/sbin/groupadd " ORYXGROUP;
    else if ( exists( "/sbin/pw" ) )
        cmd = "/sbin/pw groupadd " ORYXGROUP;

    int status = 0;
    if ( !cmd.isEmpty() )
        status = system( cmd.cstr() );

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 )
        error( "Couldn't create group '" ORYXGROUP "'. Please create it by "
               "hand and re-run the installer." );
}


void oryxUser()
{
    struct passwd * p = getpwnam( ORYXUSER );
    if ( p )
        return;

    if ( report ) {
        printf( " - Create a user named '" ORYXUSER "' in the '" ORYXGROUP "' "
                "group (e.g. \"useradd -g " ORYXGROUP " " ORYXUSER "\").\n" );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/useradd" ) )
        cmd = "/usr/sbin/useradd -g " ORYXGROUP " " ORYXUSER;
    else if ( exists( "/sbin/pw" ) )
        cmd = "/sbin/pw useradd " ORYXUSER " -g " ORYXGROUP;

    int status = 0;
    if ( !cmd.isEmpty() )
        status = system( cmd.cstr() );

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 )
        error( "Couldn't create user '" ORYXUSER "'. Please create it by "
               "hand and re-run the installer. The new user does not need "
               "a valid login shell or password." );
}


class Dispatcher
    : public EventHandler
{
public:
    Query * q;
    int state;

    Dispatcher() : state( 0 ) {}
    void execute()
    {
        database();
    }
};


void database()
{
    if ( !d ) {
        Configuration::setup( "" );
        Configuration::add( "db-user = '" PGUSER "'" );
        Configuration::add( "db-name = 'template1'" );
        Database::setup();
        d = new Dispatcher;
        d->q = new Query( "select usename from pg_catalog.pg_user where "
                          "usename=$1", d );
        d->q->bind( 1, DBUSER );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->state == 0 ) {
        Row * r = d->q->nextRow();
        if ( !r ) {
            Entropy::setup();
            String create( "create user " DBUSER " with encrypted password '" );
            String passwd( DBPASS );
            if ( passwd.isEmpty() ) {
                if ( report )
                    passwd = "(password here)";
                else
                    passwd = MD5::hash( Entropy::asString( 16 ) ).hex();
            }
            create.append( passwd );
            create.append( "'" );

            if ( report ) {
                d->state = 2;
                printf( " - Create a PostgreSQL user named '" DBUSER "'.\n"
                        "   As user " PGUSER ", run:\n"
                        "     psql -d template1 -qc \"%s\"\n", create.cstr() );
            }
            else {
                d->state = 1;
                d->q = new Query( create, d );
                d->q->execute();
            }
        }
        else {
            d->state = 2;
        }
    }

    if ( d->state == 1 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create PostgreSQL user '" DBUSER "'. "
                     "Please create it by hand and re-run the installer.\n" );
            EventLoop::shutdown();
        }
        d->state = 2;
    }

    if ( d->state == 2 ) {
        d->state = 3;
        d->q = new Query( "select datname from pg_catalog.pg_database where "
                          "datname=$1", d );
        d->q->bind( 1, DBNAME );
        d->q->execute();
    }

    if ( d->state == 3 ) {
        if ( !d->q->done() )
            return;
        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create database " DBNAME " with owner " DBUSER " "
                           "encoding 'UNICODE'" );
            if ( report ) {
                d->state = 8;
                printf( " - Create a database named '" DBNAME "'.\n"
                        "   As user " PGUSER ", run:\n"
                        "     psql -d template1 -qc \"%s\"\n", create.cstr() );
                printf( " - Load the Oryx schema.\n" );
            }
            else {
                d->state = 4;
                d->q = new Query( create, d );
                d->q->execute();
            }
        }
        else {
            d->state = 5;
        }
    }

    if ( d->state == 4 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create database '" DBUSER "'. "
                     "Please create it by hand and re-run the installer.\n" );
            EventLoop::global()->shutdown();
        }
        d->state = 5;
    }

    if ( d->state == 5 ) {
        // How utterly, utterly disgusting.
        Database::disconnect();
        Configuration::setup( "" );
        Configuration::add( "db-user = '" PGUSER "'" );
        Configuration::add( "db-name = '" DBNAME "'" );
        Database::setup();
        d->state = 6;
        d->q = new Query( "select tablename from pg_catalog.pg_tables where "
                          "tablename='mailstore'", d );
        d->q->execute();
    }

    if ( d->state == 6 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't connect to database '" DBNAME "' to "
                     "load the Oryx schema.\n" );
            EventLoop::shutdown();
        }
        d->state = 7;
    }

    if ( d->state == 7 ) {
        Row * r = d->q->nextRow();
        if ( !r ) {
            if ( report ) {
                d->state = 8;
                printf( " - Load the Oryx schema.\n" );
            }
            else {
                d->state = 8;
                printf( "<create schema>\n" );
            }
        }
        else {
            d->state = 8;
        }
    }

    if ( d->state == 8 ) {
        configFile();
    }
}


void configFile()
{
    if ( report ) {
        printf( " - Generate a default configuration file.\n" );
    }

    EventLoop::global()->shutdown();
}
