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


const char * ORYXGROUP;
const char * ORYXUSER;


void help();
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

    ORYXGROUP = Configuration::compiledIn( Configuration::OryxGroup );
    ORYXUSER = Configuration::compiledIn( Configuration::OryxUser );

    StringList args;
    while ( ac-- > 0 )
        args.append( new String( *av++ ) );
    args.shift();
    while ( !args.isEmpty() ) {
        String s( *args.shift() );
        if ( s == "-?" || s == "-h" || s == "--help" ) {
            help();
        }
        else if ( s == "-q" ) {
            silent = true;
        }
        else if ( s == "-n" ) {
            report = true;
        }
        else if ( s == "-g" || s == "-u" ) {
            if ( args.isEmpty() )
                error( s + " specified with no argument." );
            String p( *args.shift() );
            if ( s == "-g" )
                ORYXGROUP = p.cstr();
            else if ( s == "-u" )
                ORYXUSER = p.cstr();
        }
        else {
            error( "Unrecognised argument: '" + s + "'" );
        }
    }

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    struct passwd * p = getpwnam( PGUSER );
    if ( !p )
        error( "PostgreSQL superuser '" PGUSER "' does not exist." );
    postgres = p->pw_uid;
    seteuid( postgres );

    String dba( DBADDRESS );
    if ( dba[0] == '/' && !exists( dba ) ) {
        fprintf( stderr, "Warning: DBADDRESS is set to '" DBADDRESS "', "
                 "which does not exist.\n" );
        if ( exists( "/etc/debian_version" ) &&
             exists( "/var/run/postgresql/.s.PGSQL.5432" ) )
        {
            fprintf( stderr, "(On Debian, perhaps it should be "
                     "/var/run/postgresql/.s.PGSQL.5432 instead.)\n" );
        }
        exit( -1 );
    }

    if ( report )
        printf( "Reporting what the installer needs to do.\n" );

    String cf( Configuration::configFile() );
    if ( !report && exists( cf ) )
        error( cf + " already exists -- exiting without changes.\n"
               " - Not creating user " + ORYXUSER + " in group " +
               ORYXGROUP + ".\n"
               " - Not creating PostgreSQL user " DBUSER ".\n"
               " - Not creating PostgreSQL database " DBNAME ".\n"
               " - Not creating the Oryx schema.\n"
               " - Not creating stub configuration file." );

    // adding users wants to be root.
    seteuid( 0 );
    oryxGroup();
    oryxUser();

    // doing the rest wants to be postgres
    seteuid( postgres );
    EventLoop::setup();
    database();

    if ( d )
        Allocator::addEternal( d, "dispatcher" );
    EventLoop::global()->start();
}


void help()
{
    fprintf(
        stderr,
        "  Mailstore installer\n\n"
        "  Synopsis:\n\n"
        "    installer [-n] [-q] [-g group] [-u user] [-p postgres] "
        "[-a address]\n\n"
        "  This program does the following:\n\n"
        "    1. Create a Unix group named %s.\n"
        "    2. Create a Unix user named %s.\n"
        "    3. Create a Postgres user named " DBUSER ".\n"
        "    4. Create a Postgres database named " DBNAME ".\n"
        "    5. Load the Oryx database schema.\n"
        "    6. Generate an initial configuration file.\n\n"
        "  Options:\n\n"
        "  The -q flag suppresses all normal output.\n\n"
        "  The -n flag causes the program to report what it would do,\n"
        "  but not actually do anything.\n\n"
        "  The \"-g group\" flag allows you to specify a Unix group\n"
        "  other than the default of '%s'.\n\n"
        "  The \"-u user\" flag allows you to specify a Unix username\n"
        "  other than the default of '%s'.\n\n"
        "  The \"-p postgres\" flag allows you to specify the name of\n"
        "  the PostgreSQL superuser. The default is '" PGUSER "'.\n\n"
        "  The \"-a address\" flag allows you to specify a different\n"
        "  address for the Postgres server. The default is '" DBADDRESS "'.\n",
        ORYXGROUP, ORYXUSER,
        ORYXGROUP, ORYXUSER
    );
    exit( 0 );
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
        printf( " - Create a group named '%s' (e.g. \"groupadd %s\").\n",
                ORYXGROUP, ORYXGROUP );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/groupadd" ) ) {
        cmd.append( "/usr/sbin/groupadd " );
        cmd.append( ORYXGROUP );
    }
    else if ( exists( "/sbin/pw" ) ) {
        cmd.append( "/usr/sbin/pw groupadd " );
        cmd.append( ORYXGROUP );
    }

    int status = 0;
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '%s' group.\n", ORYXGROUP );
        status = system( cmd.cstr() );
    }

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 ) {
        String s;
        if ( cmd.isEmpty() )
            s.append( "Don't know how to create group " );
        else
            s.append( "Couldn't create group " );
        s.append( "'" );
        s.append( ORYXGROUP );
        s.append( "'. " );
        s.append( "Please create it by hand and re-run the installer.\n" );
        if ( !cmd.isEmpty() )
            s.append( "The command which failed was '" + cmd + "'" );
        error( s );
    }
}


void oryxUser()
{
    struct passwd * p = getpwnam( ORYXUSER );
    if ( p )
        return;

    if ( report ) {
        printf( " - Create a user named '%s' in the '%s' group "
                "(e.g. \"useradd -g %s %s\").\n",
                ORYXUSER, ORYXGROUP, ORYXGROUP, ORYXUSER );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/useradd" ) ) {
        cmd.append( "/usr/sbin/useradd -g " );
        cmd.append( ORYXGROUP );
        cmd.append( " " );
        cmd.append( ORYXUSER );
    }
    else if ( exists( "/sbin/pw" ) ) {
        cmd.append( "/usr/sbin/pw useradd " );
        cmd.append( ORYXUSER );
        cmd.append( " -g " );
        cmd.append( ORYXGROUP );
    }

    int status = 0;
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '%s' user.\n", ORYXUSER );
        status = system( cmd.cstr() );
    }

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 ) {
        String s;
        if ( cmd.isEmpty() )
            s.append( "Don't know how to create user " );
        else
            s.append( "Couldn't create user " );
        s.append( "'" );
        s.append( ORYXUSER );
        s.append( "'. " );
        s.append( "Please create it by hand and re-run the installer.\n" );
        s.append( "The new user does not need a valid login shell or "
                  "password.\n" );
        if ( !cmd.isEmpty() )
            s.append( "The command which failed was '" + cmd + "'" );
        error( s );
    }
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
        d->q =
            new Query( "select datname::text,usename::text,"
                       "pg_encoding_to_char(encoding)::text as encoding "
                       "from pg_database d join pg_user u "
                       "on (d.datdba=u.usesysid) where datname=$1", d );
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
            const char * s = 0;
            if ( r->getString( "usename" ) != DBUSER )
                s = "is not owned by user " DBUSER;
            else if ( r->getString( "encoding" ) != "UNICODE" )
                s = "does not have encoding UNICODE";
            if ( s ) {
                fprintf( stderr, " - Database '" DBNAME "' exists, but it %s."
                         "\n   (That will need to be fixed by hand.)\n", s );
                if ( !report )
                    exit( -1 );
            }
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
        "db-user      = " DBUSER "\n"
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
                    fprintf( stderr, "Could not \"chown oryx:oryx %s\".\n",
                             cf.cstr() );

                if ( !silent )
                    printf( "Done.\n" );
            }
        }
    }

    EventLoop::shutdown();
}
