// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "stringlist.h"
#include "eventloop.h"
#include "file.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>


StringList * args;
bool report = false;


void error( String );
bool exists( String );
void oryxGroup();
void oryxUser();
void dbUser();
void database();
void configFile();


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;

    args = new StringList;
    while ( ac-- > 0 )
        args->append( new String( *av++ ) );
    args->shift();

    while ( !args->isEmpty() ) {
        String s( *args->shift() );
        if ( s == "-n" )
            report = true;
        else
            error( "Unrecognised argument: '" + s + "'" );
    }

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

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

    oryxGroup();
    oryxUser();
    dbUser();
    database();
    configFile();

    EventLoop::setup();
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


void dbUser()
{
    if ( report ) {
        printf( " - Create a PostgreSQL user named '" DBUSER "' "
                "(e.g. \"create user " DBUSER "\" in psql).\n" );
        return;
    }
}


void database()
{
    if ( report ) {
        printf( " - Create a database named '" DBNAME "' owned by '" DBUSER
                "'\n   (e.g. \"create database " DBNAME " with owner " DBUSER
                "\" in psql).\n" );
        return;
    }
}


void configFile()
{
    if ( report ) {
        printf( " - Generate a default configuration file.\n" );
        return;
    }
}
