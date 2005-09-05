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
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>


uid_t postgres;
class Dispatcher * d;
bool report = false;
bool silent = false;
String * dbpass;


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
        else if ( s == "-q" )
            silent = true;
        else
            error( "Unrecognised argument: '" + s + "'" );
    }

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    struct passwd * p = getpwnam( PGUSER );
    if ( !p )
        error( "PostgreSQL superuser '" PGUSER "' does not exist." );
    seteuid( postgres = p->pw_uid );

    if ( report )
        printf( "Reporting what the installer needs to do.\n" );

    String cf( Configuration::configFile() );
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
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '" ORYXGROUP "' group,\n" );
        status = system( cmd.cstr() );
    }

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
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '" ORYXUSER "' user,\n" );
        status = system( cmd.cstr() );
    }

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
        dbpass = new String;
        Allocator::addEternal( dbpass, "DBPASS" );
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
            dbpass->append( passwd );
            create.append( passwd );
            create.append( "'" );

            if ( report ) {
                d->state = 2;
                printf( " - Create a PostgreSQL user named '" DBUSER "'.\n"
                        "   As user " PGUSER ", run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n", create.cstr() );
            }
            else {
                d->state = 1;
                if ( !silent )
                    printf( "Creating the '" DBUSER "' PostgreSQL user.\n" );
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
                d->state = 7;
                printf( " - Create a database named '" DBNAME "'.\n"
                        "   As user " PGUSER ", run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n", create.cstr() );
                // We let state 7 think the mailstore query returned 0
                // rows, so that it prints an appropriate message.
            }
            else {
                d->state = 4;
                if ( !silent )
                    printf( "Creating the '" DBNAME "' database.\n" );
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
            EventLoop::shutdown();
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
        d->q = new Query( "select relname from pg_catalog.pg_class where "
                          "relname='mailstore'", d );
        d->q->execute();
    }

    if ( d->state == 6 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            if ( report ) {
                d->state = 8;
                printf( " - May need to load the Oryx database schema.\n   "
                        "(Couldn't query database '" DBNAME "' to make sure "
                        "it's needed.)\n" );
            }
            else {
                fprintf( stderr, "Couldn't query database '" DBNAME "' to "
                         "see if the schema needs to be loaded (%s).\n",
                         d->q->error().cstr() );
                EventLoop::shutdown();
            }
        }
        d->state = 7;
    }

    if ( d->state == 7 ) {
        Row * r = d->q->nextRow();
        if ( !r ) {
            String cmd( "\\set ON_ERROR_STOP\n"
                        "SET SESSION AUTHORIZATION " DBUSER ";\n"
                        "SET client_min_messages TO 'ERROR';\n"
                        "\\i " LIBDIR "/schema.pg\n"
                        "\\i " LIBDIR "/field-names\n"
                        "\\i " LIBDIR "/flag-names\n" );
            if ( report ) {
                d->state = 8;
                printf( " - Load the Oryx database schema.\n   "
                        "As user " PGUSER ", run:\n\n"
                        "psql " DBNAME " -f - <<PSQL;\n%sPSQL\n\n",
                        cmd.cstr() );
            }
            else {
                d->state = 8;

                int n;
                int fd[2];
                pid_t pid = -1;

                n = pipe( fd );
                if ( n == 0 )
                    pid = fork();
                if ( n == 0 && pid == 0 ) {
                    if ( setreuid( postgres, postgres ) < 0 ||
                         dup2( fd[0], 0 ) < 0 ||
                         close( fd[1] ) < 0 ||
                         close( fd[0] ) < 0 )
                        exit( -1 );
                    if ( silent )
                        if ( close( 1 ) < 0 || open( "/dev/null", 0 ) != 1 )
                            exit( -1 );
                    execlp( PSQL, "psql", DBNAME, "-f", "-", 0 );
                }
                else {
                    int status = 0;
                    if ( pid > 0 ) {
                        if ( !silent )
                            printf( "Loading Oryx database schema:\n" );
                        write( fd[1], cmd.cstr(), cmd.length() );
                        close( fd[1] );
                        waitpid( pid, &status, 0 );
                    }
                    if ( pid < 0 || ( WIFEXITED( status ) &&
                                      WEXITSTATUS( status ) != 0 ) )
                    {
                        fprintf( stderr, "Couldn't install the Oryx schema.\n"
                                 "Please re-run the installer after doing the "
                                 "following as user " PGUSER ":\n\n"
                                 "psql " DBNAME " -f - <<PSQL;\n%sPSQL\n",
                                 cmd.cstr() );
                        EventLoop::shutdown();
                    }
                }
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
    String p( *dbpass );
    if ( p.isEmpty() )
        p = "'(database password here)'";

    String cf( Configuration::configFile() );
    String v( Configuration::compiledIn( Configuration::Version ) );
    String intro(
        "# Mailstore configuration. See mailstore.conf(5) for details.\n"
        "# Automatically generated while installing Mailstore " + v + ".\n\n"
        "# Specify the hostname if mailstore gets it wrong. We suggest not\n"
        "# using the name \"localhost\".\n#\n"
        "# hostname = fully.qualified.hostname\n\n"
    );
    String cfg(
        "logfile      = " LOGFILE "\n"
        "logfile-mode = " LOGFILEMODE "\n"
        "db-address   = " DBADDRESS "\n"
        "db-name      = " DBNAME "\n"
        "db-user      = " DBUSER "\n\n"
        "# Security note: Anyone who can read this password can do\n"
        "# anything to the database, including delete all mail.\n"
        "db-password  = " + p + "\n"
    );

    if ( !exists( cf ) ) {
        if ( report ) {
            printf( " - Generate a default configuration file.\n"
                    "   %s should contain:\n\n%s", cf.cstr(), cfg.cstr() );
        }
        else {
            setreuid( 0, 0 );
            File f( cf, File::Write, 0600 );
            if ( !f.valid() ) {
                fprintf( stderr, "Could not open %s for writing.\n",
                         cf.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Generating default %s\n", cf.cstr() );
                f.write( intro );
                f.write( cfg );

                struct passwd * p = getpwnam( ORYXUSER );
                struct group * g = getgrnam( ORYXGROUP );
                if ( chown( cf.cstr(), p->pw_uid, g->gr_gid ) < 0 )
                    fprintf( stderr, "Could not chown oryx:oryx on %s\n",
                             cf.cstr() );

                if ( !silent )
                    printf( "Done.\n" );
            }
        }
    }

    EventLoop::shutdown();
}
