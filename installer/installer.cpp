// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "stderrlogger.h"
#include "configuration.h"
#include "eventloop.h"
#include "database.h"
#include "entropy.h"
#include "schema.h"
#include "query.h"
#include "event.h"
#include "file.h"
#include "md5.h"

#include <errno.h>
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

String * dbname;
String * dbaddress;
String * dbuser;
String * dbpass;
String * dbowner;
String * dbownerpass;

uint dbport = 0;

int todo = 0;
bool generatedPass = false;
bool generatedOwnerPass = false;

const char * PGUSER;
const char * AOXUSER;
const char * AOXGROUP;
const char * DBADDRESS;


void help();
void error( String );
bool exists( const String & );
void configure();
void findPgUser();
void oryxGroup();
void oryxUser();
void database();
void configFile();
void superConfig();
void permissions();
int psql( const String & );


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "log object" );
    global.setLog( l );

    PGUSER = Configuration::compiledIn( Configuration::PgUser );
    AOXUSER = Configuration::compiledIn( Configuration::OryxUser );
    AOXGROUP = Configuration::compiledIn( Configuration::OryxGroup );
    DBADDRESS = Configuration::compiledIn( Configuration::DefaultDbAddress );

    dbname = new String( DBNAME );
    Allocator::addEternal( dbname, "DBNAME" );
    dbaddress = new String( DBADDRESS );
    Allocator::addEternal( dbaddress, "DBADDRESS" );
    dbuser = new String( AOXUSER );
    Allocator::addEternal( dbuser, "AOXUSER" );
    dbpass = new String( DBPASS );
    Allocator::addEternal( dbpass, "DBPASS" );
    dbowner = new String( DBOWNER );
    Allocator::addEternal( dbowner, "DBOWNER" );
    dbownerpass = new String( DBOWNERPASS );
    Allocator::addEternal( dbownerpass, "DBOWNERPASS" );

    uint verbosity = 0;
    av++;
    while ( ac-- > 1 ) {
        String s( *av++ );

        if ( s == "-?" || s == "-h" || s == "--help" ) {
            help();
        }
        else if ( s == "-q" ) {
            silent = true;
            verbosity = 0;
        }
        else if ( s == "-n" ) {
            report = true;
        }
        else if ( s == "-g" || s == "-u" || s == "-p" || s == "-a" ) {
            if ( ac == 1 )
                error( s + " specified with no argument." );
            if ( s == "-g" )
                AOXGROUP = *av++;
            else if ( s == "-u" )
                AOXUSER = *av++;
            else if ( s == "-p" )
                PGUSER = *av++;
            else if ( s == "-a" )
                *dbaddress = *av++;
            ac--;
        }
        else if ( s == "-t" ) {
            if ( ac == 1 )
                error( s + " specified with no argument." );
            String p( *av++ );
            bool ok;
            dbport = p.number( &ok );
            if ( !ok )
                error( "Invalid port number " + p );
            ac--;
        }
        else if ( s == "-v" ) {
            verbosity++;
        }
        else {
            error( "Unrecognised argument: '" + s + "'" );
        }
    }

    Allocator::addEternal( new StderrLogger( "installer", verbosity ),
                           "log object" );

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    findPgUser();

    if ( report )
        printf( "Reporting what the installer needs to do.\n" );

    Configuration::setup( "archiveopteryx.conf" );
    String super( Configuration::compiledIn( Configuration::ConfigDir ) );
    super.append( "/aoxsuper.conf" );
    Configuration::read( super, true );

    configure();

    if ( dbaddress->startsWith( "/" ) && !exists( *dbaddress ) ) {
        fprintf( stderr, "Error: DBADDRESS is set to '%s', "
                 "which does not exist.\n", dbaddress->cstr() );
        if ( exists( "/etc/debian_version" ) &&
             exists( "/var/run/postgresql/.s.PGSQL.5432" ) )
        {
            fprintf( stderr, "(On Debian, perhaps it should be "
                     "/var/run/postgresql/.s.PGSQL.5432 instead.)\n" );
        }
        exit( -1 );
    }

    oryxGroup();
    oryxUser();

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
        "  Archiveopteryx installer\n\n"
        "  Synopsis:\n\n"
        "    installer [-n] [-q] [-g group] [-u user] [-p postgres] "
        "[-a address] [-t port]\n\n"
        "  This program does the following:\n\n"
        "    1. Creates a Unix group named %s.\n"
        "    2. Creates a Unix user named %s.\n"
        "    3. Creates a Postgres user named %s.\n"
        "    4. Creates a Postgres user named %s.\n"
        "    5. Creates a Postgres database named %s owned by %s.\n"
        "    6. Loads the database schema and grants limited privileges "
        "to user %s.\n"
        "    7. Generates an initial configuration file.\n"
        "    8. Adjusts ownership and permissions if necessary.\n\n"
        "  Options:\n\n"
        "  The -q flag suppresses all normal output.\n\n"
        "  The -n flag causes the program to report what it would do,\n"
        "  but not actually do anything.\n\n"
        "  The \"-g group\" flag allows you to specify a Unix group\n"
        "  other than the default of '%s'.\n\n"
        "  The \"-u user\" flag allows you to specify a Unix username\n"
        "  other than the default of '%s'.\n\n"
        "  The \"-p postgres\" flag allows you to specify the name of\n"
        "  the PostgreSQL superuser. The default is to try $PGSQL (if\n"
        "  set), postgres and pgsql in turn.\n\n"
        "  The \"-a address\" flag allows you to specify a different\n"
        "  address for the Postgres server. The default is '%s'.\n\n"
        "  The \"-t port\" flag allows you to specify a different port\n"
        "  for the Postgres server. The default is 5432.\n\n"
        "  The defaults are set at build time in the Jamsettings file.\n\n",
        AOXGROUP, AOXUSER, dbuser->cstr(), dbowner->cstr(), dbname->cstr(),
        dbowner->cstr(), dbuser->cstr(),
        AOXGROUP, AOXUSER, DBADDRESS
    );
    exit( 0 );
}


void error( String m )
{
    fprintf( stderr, "%s\n", m.cstr() );
    exit( -1 );
}


bool exists( const String & f )
{
    struct stat st;
    return stat( f.cstr(), &st ) == 0;
}


void findPgUser()
{
    struct passwd * p = 0;

    if ( *PGUSER ) {
        p = getpwnam( PGUSER );
        if ( !p )
            error( "PostgreSQL superuser '" + String( PGUSER ) +
                   "' does not exist (rerun with -p username)." );
    }

    if ( !p ) {
        PGUSER = "postgres";
        p = getpwnam( PGUSER );
    }
    if ( !p ) {
        PGUSER = "pgsql";
        p = getpwnam( PGUSER );
    }
    if ( !p ) {
        error( "PostgreSQL superuser unknown. Please re-run the "
               "installer with \"-p username\" to specify one." );
    }

    postgres = p->pw_uid;

    String path( getenv( "PATH" ) );
    path.append( ":" + String( p->pw_dir ) + "/bin" );
    path.append( ":/usr/local/pgsql/bin" );
    setenv( "PATH", path.cstr(), 1 );
}


void configure()
{
    Entropy::setup();

    if ( Configuration::present( Configuration::DbName ) )
        *dbname = Configuration::text( Configuration::DbName );

    if ( Configuration::present( Configuration::DbAddress ) )
        *dbaddress = Configuration::text( Configuration::DbAddress );

    if ( Configuration::present( Configuration::DbPort ) )
        dbport = Configuration::scalar( Configuration::DbPort );

    if ( Configuration::present( Configuration::DbUser ) )
        *dbuser = Configuration::text( Configuration::DbUser );

    if ( Configuration::present( Configuration::DbPassword ) ) {
        *dbpass = Configuration::text( Configuration::DbPassword );
    }
    else if ( dbpass->isEmpty() ) {
        String p( "(database user password here)" );
        if ( !report ) {
            p = MD5::hash( Entropy::asString( 16 ) ).hex();
            generatedPass = true;
        }
        dbpass->append( p );
    }

    if ( Configuration::present( Configuration::DbOwner ) )
        *dbowner = Configuration::text( Configuration::DbOwner );

    if ( Configuration::present( Configuration::DbOwnerPassword ) ) {
        *dbownerpass = Configuration::text( Configuration::DbOwnerPassword );
    }
    else if ( dbownerpass->isEmpty() ) {
        String p( "(database owner password here)" );
        if ( !report ) {
            p = MD5::hash( Entropy::asString( 16 ) ).hex();
            generatedOwnerPass = true;
        }
        dbownerpass->append( p );
    }
}


void oryxGroup()
{
    struct group * g = getgrnam( AOXGROUP );
    if ( g )
        return;

    if ( report ) {
        todo++;
        printf( " - Create a group named '%s' (e.g. \"groupadd %s\").\n",
                AOXGROUP, AOXGROUP );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/groupadd" ) ) {
        cmd.append( "/usr/sbin/groupadd " );
        cmd.append( AOXGROUP );
    }
    else if ( exists( "/usr/sbin/pw" ) ) {
        cmd.append( "/usr/sbin/pw groupadd " );
        cmd.append( AOXGROUP );
    }

    int status = 0;
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '%s' group.\n", AOXGROUP );
        status = system( cmd.cstr() );
    }

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 ||
         getgrnam( AOXGROUP ) == 0 )
    {
        String s;
        if ( cmd.isEmpty() )
            s.append( "Don't know how to create group " );
        else
            s.append( "Couldn't create group " );
        s.append( "'" );
        s.append( AOXGROUP );
        s.append( "'. " );
        s.append( "Please create it by hand and re-run the installer.\n" );
        if ( !cmd.isEmpty() )
            s.append( "The command which failed was '" + cmd + "'" );
        error( s );
    }
}


void oryxUser()
{
    struct passwd * p = getpwnam( AOXUSER );
    if ( p )
        return;

    if ( report ) {
        todo++;
        printf( " - Create a user named '%s' in the '%s' group "
                "(e.g. \"useradd -g %s %s\").\n",
                AOXUSER, AOXGROUP, AOXGROUP, AOXUSER );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/useradd" ) ) {
        cmd.append( "/usr/sbin/useradd -g " );
        cmd.append( AOXGROUP );
        cmd.append( " " );
        cmd.append( AOXUSER );
    }
    else if ( exists( "/usr/sbin/pw" ) ) {
        cmd.append( "/usr/sbin/pw useradd " );
        cmd.append( AOXUSER );
        cmd.append( " -g " );
        cmd.append( AOXGROUP );
    }

    int status = 0;
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '%s' user.\n", AOXUSER );
        status = system( cmd.cstr() );
    }

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 ||
         getpwnam( AOXUSER ) == 0 )
    {
        String s;
        if ( cmd.isEmpty() )
            s.append( "Don't know how to create user " );
        else
            s.append( "Couldn't create user " );
        s.append( "'" );
        s.append( AOXUSER );
        s.append( "'. " );
        s.append( "Please create it by hand and re-run the installer.\n" );
        s.append( "The new user does not need a valid login shell or "
                  "password.\n" );
        if ( !cmd.isEmpty() )
            s.append( "The command which failed was '" + cmd + "'" );
        error( s );
    }
}


enum DbState {
    Unused,
    CheckingVersion, CheckDatabase, CheckingDatabase, CheckUser,
    CheckingUser, CreatingUser, CheckSuperuser, CheckingSuperuser,
    CreatingSuperuser, CreateDatabase, CreatingDatabase, CheckSchema,
    CheckingSchema, CreateSchema, CheckingRevision, UpgradingSchema,
    CheckOwnership, AlterOwnership, AlteringOwnership, SelectObjects,
    AlterPrivileges, AlteringPrivileges,
    Done
};


class Dispatcher
    : public EventHandler
{
public:
    Query * q;
    Query * ssa;
    DbState state;
    bool createDatabase;
    String owner;

    Dispatcher()
        : q( 0 ), ssa( 0 ), state( Unused ), createDatabase( false )
    {}

    void execute()
    {
        database();
    }
};


void database()
{
    if ( !d ) {
        Configuration::setup( "" );
        Configuration::add( "db-max-handles = 1" );
        Configuration::add( "db-address = '" + *dbaddress + "'" );
        Configuration::add( "db-user = '" + String( PGUSER ) + "'" );
        Configuration::add( "db-name = 'template1'" );
        if ( dbport != 0 )
            Configuration::add( "db-port = " + fn( dbport ) );

        Database::setup( 1 );

        d = new Dispatcher;
        d->state = CheckingVersion;
        d->q = new Query( "select version() as version", d );
        d->q->execute();
    }

    if ( d->state == CheckingVersion ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r ) {
            fprintf( stderr, "Couldn't check PostgreSQL server version.\n" );
            EventLoop::shutdown();
            return;
        }

        String v = r->getString( "version" ).simplified().section( " ", 2 );
        if ( v.isEmpty() )
            v = r->getString( "version" );
        bool ok = true;
        uint version = 10000 * v.section( ".", 1 ).number( &ok ) +
                       100 * v.section( ".", 2 ).number( &ok ) +
                       v.section( ".", 3 ).number( &ok );
        if ( !ok || version < 70402 ) {
            fprintf( stderr, "Archiveopteryx requires PostgreSQL 7.4.2 "
                     "or higher (found only '%s').\n", v.cstr() );
            EventLoop::shutdown();
            return;
        }
        else if ( version < 80100 ) {
            fprintf( stderr, "Note: Starting May 2007, Archiveopteryx "
                     "will require PostgreSQL 8.1.0 or\nhigher. Please "
                     "upgrade the running server (%s) at your "
                     "convenience.\n", v.cstr() );
        }

        d->state = CheckDatabase;
    }

    if ( d->state == CheckDatabase ) {
        d->state = CheckingDatabase;
        d->owner = *dbowner;
        d->q = new Query( "select datname::text,usename::text,"
                          "pg_encoding_to_char(encoding)::text as encoding "
                          "from pg_database d join pg_user u "
                          "on (d.datdba=u.usesysid) where datname=$1", d );
        d->q->bind( 1, *dbname );
        d->q->execute();
    }

    if ( d->state == CheckingDatabase ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( r ) {
            String s;
            d->owner = r->getString( "usename" );
            String encoding( r->getString( "encoding" ) );

            if ( d->owner != *dbowner && d->owner != *dbuser )
                s = "is not owned by " + *dbowner + " or " + *dbuser;
            else if ( encoding != "UNICODE" && encoding != "UTF8" )
                s = "does not have encoding UNICODE/UTF8";

            if ( !s.isEmpty() ) {
                fprintf( stderr, " - Database '%s' exists, but it %s.\n"
                         "   (That will need to be fixed by hand.)\n",
                         dbname->cstr(), s.cstr() );
                exit( -1 );
            }
        }
        else {
            d->createDatabase = true;
        }
        d->state = CheckUser;
    }

    if ( d->state == CheckUser ) {
        d->state = CheckingUser;
        d->q = new Query( "select usename from pg_catalog.pg_user where "
                          "usename=$1", d );
        d->q->bind( 1, *dbuser );
        d->q->execute();
    }

    if ( d->state == CheckingUser ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create user " + *dbuser + " with encrypted "
                           "password '" + *dbpass + "'" );

            if ( report ) {
                todo++;
                d->state = CheckSuperuser;
                printf( " - Create a PostgreSQL user named '%s'.\n"
                        "   As user %s, run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n",
                        dbuser->cstr(), PGUSER, create.cstr() );
            }
            else {
                d->state = CreatingUser;
                if ( !silent )
                    printf( "Creating the '%s' PostgreSQL user.\n",
                            dbuser->cstr() );
                d->q = new Query( create, d );
                d->q->execute();
            }
        }
        else {
            if ( generatedPass )
                *dbpass = "(database user password here)";
            d->state = CheckSuperuser;
        }
    }

    if ( d->state == CreatingUser ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create PostgreSQL user '%s' (%s).\n"
                     "Please create it by hand and re-run the installer.\n",
                     dbuser->cstr(), d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        d->state = CheckSuperuser;
    }

    if ( d->state == CheckSuperuser ) {
        d->state = CheckingSuperuser;
        d->q = new Query( "select usename from pg_catalog.pg_user where "
                          "usename=$1", d );
        d->q->bind( 1, *dbowner );
        d->q->execute();
    }

    if ( d->state == CheckingSuperuser ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create user " + *dbowner + " with encrypted "
                           "password '" + *dbownerpass + "'" );

            if ( report ) {
                d->state = CreateDatabase;
                printf( " - Create a PostgreSQL user named '%s'.\n"
                        "   As user %s, run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n",
                        dbowner->cstr(), PGUSER, create.cstr() );
            }
            else {
                d->state = CreatingSuperuser;
                if ( !silent )
                    printf( "Creating the '%s' PostgreSQL user.\n",
                            dbowner->cstr() );
                d->q = new Query( create, d );
                d->q->execute();
            }
        }
        else {
            if ( generatedOwnerPass )
                *dbownerpass = "(database owner password here)";
            d->state = CreateDatabase;
        }
    }

    if ( d->state == CreatingSuperuser ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create PostgreSQL user '%s' (%s).\n"
                     "Please create it by hand and re-run the installer.\n",
                     dbowner->cstr(), d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        d->state = CreateDatabase;
    }

    if ( d->state == CreateDatabase ) {
        if ( d->createDatabase ) {
            String create( "create database " + *dbname + " with owner " +
                           *dbowner + " encoding 'UNICODE'" );
            if ( report ) {
                todo++;
                printf( " - Create a database named '%s'.\n"
                        "   As user %s, run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n",
                        dbname->cstr(), PGUSER, create.cstr() );

                // We fool CreateSchema into thinking that the mailstore
                // query returned 0 rows, so that it displays a suitable
                // message.
                d->state = CreateSchema;
            }
            else {
                d->state = CreatingDatabase;
                if ( !silent )
                    printf( "Creating the '%s' database.\n",
                            dbname->cstr() );
                d->q = new Query( create, d );
                d->q->execute();
            }

        }
        else {
            d->state = CheckSchema;
        }
    }

    if ( d->state == CreatingDatabase ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create database '%s' (%s).\n"
                     "Please create it by hand and re-run the installer.\n",
                     dbname->cstr(), d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        d->state = CheckSchema;
    }

    if ( d->state == CheckSchema ) {
        Database::disconnect();

        Configuration::setup( "" );
        Configuration::add( "db-max-handles = 1" );
        Configuration::add( "db-user = '" + String( PGUSER ) + "'" );
        Configuration::add( "db-name = '" + *dbname + "'" );
        Configuration::add( "db-address = '" + *dbaddress + "'" );
        if ( dbport != 0 )
            Configuration::add( "db-port = " + fn( dbport ) );

        Database::setup( 1 );

        d->ssa = new Query( "set session authorization " + d->owner, d );
        d->ssa->execute();

        d->state = CheckingSchema;
        d->q = new Query( "select relname from pg_catalog.pg_class where "
                          "relname='mailstore'", d );
        d->q->execute();
    }

    if ( d->state == CheckingSchema ) {
        if ( !d->ssa->done() || !d->q->done() )
            return;

        if ( d->ssa->failed() ) {
            if ( report ) {
                todo++;
                d->state = Done;
                printf( " - May need to load the database schema.\n   "
                        "(Couldn't authenticate as user '%s' to make sure "
                        "it's needed: %s.)\n", dbname->cstr(),
                        d->ssa->error().cstr() );
            }
            else {
                fprintf( stderr, "Couldn't query database '%s' to "
                         "see if the schema needs to be loaded (%s).\n",
                         dbname->cstr(), d->q->error().cstr() );
                EventLoop::shutdown();
                return;
            }
        }

        if ( d->q->failed() ) {
            if ( report ) {
                todo++;
                d->state = Done;
                printf( " - May need to load the database schema.\n   "
                        "(Couldn't query database '%s' to make sure it's "
                        "needed: %s.)\n", dbname->cstr(),
                        d->q->error().cstr() );
            }
            else {
                fprintf( stderr, "Couldn't query database '%s' to "
                         "see if the schema needs to be loaded (%s).\n",
                         dbname->cstr(), d->q->error().cstr() );
                EventLoop::shutdown();
                return;
            }
        }
        d->state = CreateSchema;
    }

    if ( d->state == CreateSchema ) {
        Row * r = d->q->nextRow();
        if ( !r ) {
            String cmd( "\\set ON_ERROR_STOP\n"
                        "SET SESSION AUTHORIZATION " + *dbowner + ";\n"
                        "SET client_min_messages TO 'ERROR';\n"
                        "\\i " LIBDIR "/schema.pg\n"
                        "\\i " LIBDIR "/flag-names\n"
                        "\\i " LIBDIR "/field-names\n"
                        "\\i " LIBDIR "/grant-privileges\n" );
            d->state = Done;
            if ( report ) {
                todo++;
                printf( " - Load the database schema.\n   "
                        "As user %s, run:\n\n"
                        "psql %s -f - <<PSQL;\n%sPSQL\n\n",
                        PGUSER, dbname->cstr(), cmd.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Loading the database schema:\n" );
                if ( psql( cmd ) < 0 )
                    return;
            }
        }
        else {
            d->state = CheckingRevision;
            d->q = new Query( "select revision from mailstore", d );
            d->q->execute();
        }
    }

    if ( d->state == CheckingRevision ) {
        if ( !d->q->done() )
            return;

        d->state = Done;
        Row * r = d->q->nextRow();
        if ( !r || d->q->failed() ) {
            if ( report ) {
                todo++;
                printf( " - May need to upgrade the database schema.\n   "
                        "(Couldn't query mailstore table to make sure it's "
                        "needed.)\n" );
            }
            else {
                fprintf( stderr, "Couldn't query database '%s' to "
                         "see if the schema needs to be upgraded (%s).\n",
                         dbname->cstr(), d->q->error().cstr() );
                EventLoop::shutdown();
                return;
            }
        }
        else {
            uint revision = r->getInt( "revision" );

            if ( revision > Database::currentRevision() ) {
                String v( Configuration::compiledIn( Configuration::Version ) );
                fprintf( stderr, "The schema in database '%s' (revision #%d) "
                         "is newer than this version of Archiveopteryx (%s) "
                         "recognises (up to #%d).\n", dbname->cstr(), revision,
                         v.cstr(), Database::currentRevision() );
                EventLoop::shutdown();
                return;
            }
            else if ( revision < Database::currentRevision() ) {
                if ( report ) {
                    todo++;
                    printf( " - Upgrade the database schema (\"aox upgrade "
                            "schema -n\" to see what would happen).\n" );
                    d->state = CheckOwnership;
                }
                else {
                    d->state = UpgradingSchema;
                    Schema * s = new Schema( d, true, true );
                    d->q = s->result();
                    s->execute();
                }
            }
            else {
                d->state = CheckOwnership;
            }
        }
    }

    if ( d->state == UpgradingSchema ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't upgrade schema in database '%s' (%s).\n"
                     "Please run \"aox upgrade schema -n\" by hand.\n",
                     dbname->cstr(), d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        d->state = CheckOwnership;
    }

    if ( d->state == CheckOwnership ) {
        if ( d->owner != *dbowner ) {
            d->state = AlterOwnership;
            d->ssa = new Query( "set session authorization default", d );
            d->ssa->execute();
        }
        else {
            // We'll just assume that, if the database is owned by the
            // right user already, the privileges are fine too.
            d->state = Done;
        }
    }

    if ( d->state == AlterOwnership ) {
        if ( !d->ssa->done() )
            return;

        if ( d->ssa->failed() ) {
            if ( !report ) {
                report = true;
                fprintf( stderr,
                         "Couldn't reset session authorisation to alter "
                         "ownership and privileges on database '%s' (%s)."
                         "\nSwitching to reporting mode.\n", dbname->cstr(),
                         d->ssa->error().cstr() );
            }
        }

        String alter( "alter database " + *dbname + " owner to " + *dbowner );

        if ( report ) {
            todo++;
            printf( " - Alter owner of database '%s' from '%s' to '%s'.\n"
                    "   As user %s, run:\n\n"
                    "psql -d template1 -qc \"%s\"\n\n",
                    dbname->cstr(), d->owner.cstr(), dbowner->cstr(),
                    PGUSER, alter.cstr() );
            d->state = SelectObjects;
        }
        else {
            d->state = AlteringOwnership;
            if ( !silent )
                printf( "Altering ownership of database '%s' to '%s'.\n",
                        dbname->cstr(), dbowner->cstr() );
            d->q = new Query( alter, d );
            d->q->execute();
        }
    }

    if ( d->state == AlteringOwnership ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't alter owner of database '%s' to '%s' "
                     "(%s).\n"
                     "Please set the owner by hand and re-run the installer.\n",
                     dbname->cstr(), dbowner->cstr(), d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }

        d->state = SelectObjects;
    }

    if ( d->state == SelectObjects ) {
        d->state = AlterPrivileges;
        d->q = new Query( "select c.relkind::text as type, c.relname::text "
                          "as name from pg_catalog.pg_class c left join "
                          "pg_catalog.pg_namespace n on (n.oid=c.relnamespace) "
                          "where c.relkind in ('r','S') and n.nspname not in "
                          "('pg_catalog','pg_toast') and "
                          "pg_catalog.pg_table_is_visible(c.oid)", d );
        d->q->execute();
    }

    if ( d->state == AlterPrivileges ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            fprintf( stderr,
                     "Couldn't get a list of tables and sequences in database "
                     "'%s' while trying to alter their privileges (%s).\n",
                     dbname->cstr(), d->q->error().cstr() );
            exit( -1 );
        }

        StringList tables;
        StringList sequences;

        Row * r;
        while ( ( r = d->q->nextRow() ) != 0 ) {
            String type( r->getString( "type" ) );
            if ( type == "r" )
                tables.append( r->getString( "name" ) );
            else if ( type == "S" )
                sequences.append( r->getString( "name" ) );
        }

        String ap( Configuration::compiledIn( Configuration::LibDir ) );
        setreuid( 0, 0 );
        ap.append( "/fixup-privileges" );
        File f( ap, File::Write, 0644 );
        if ( !f.valid() ) {
            fprintf( stderr, "Couldn't open '%s' for writing.\n", ap.cstr() );
            exit( -1 );
        }

        StringList::Iterator it( tables );
        while ( it ) {
            String s( "alter table " );
            s.append( *it );
            s.append( " owner to " );
            s.append( *dbowner );
            s.append( ";\n" );
            f.write( s );
            ++it;
        }

        String trevoke( "revoke all privileges on " );
        trevoke.append( tables.join( "," ) );
        trevoke.append( "," );
        trevoke.append( sequences.join( "," ) );
        trevoke.append( " from " );
        trevoke.append( *dbuser );
        trevoke.append( ";\n" );
        f.write( trevoke );

        String tsgrant( "grant select on mailstore, addresses, namespaces, "
                        "users, groups, group_members, mailboxes, aliases, "
                        "permissions, messages, bodyparts, part_numbers, "
                        "field_names, header_fields, address_fields, "
                        "date_fields, flag_names, flags, subscriptions, "
                        "annotation_names, annotations, views, view_messages, "
                        "scripts, deleted_messages to " );
        tsgrant.append( *dbuser );
        tsgrant.append( ";\n" );
        f.write( tsgrant );

        String tigrant( "grant insert on addresses, mailboxes, permissions, "
                        "messages, bodyparts, part_numbers, field_names, "
                        "header_fields, address_fields, date_fields, flags, "
                        "flag_names, subscriptions, views, annotation_names, "
                        "annotations, view_messages, scripts, deleted_messages "
                        "to " );
        tigrant.append( *dbuser );
        tigrant.append( ";\n" );
        f.write( tigrant );

        String tdgrant( "grant delete on permissions, flags, subscriptions, "
                        "annotations, views, view_messages, scripts to " );
        tdgrant.append( *dbuser );
        tdgrant.append( ";\n" );
        f.write( tdgrant );

        String tugrant( "grant update on mailstore, permissions, mailboxes, "
                        "aliases, annotations, views, scripts to " );
        tugrant.append( *dbuser );
        tugrant.append( ";\n" );
        f.write( tugrant );

        String sgrant( "grant select,update on " );
        sgrant.append( sequences.join( "," ) );
        sgrant.append( " to " );
        sgrant.append( *dbuser );
        sgrant.append( ";\n" );
        f.write( sgrant );

        String bigrant( "grant all privileges on bodypart_ids to " );
        bigrant.append( *dbowner );
        bigrant.append( ";\n" );
        f.write( bigrant );

        d->state = AlteringPrivileges;
    }

    if ( d->state == AlteringPrivileges ) {
        d->state = Done;

        String cmd( "SET client_min_messages TO 'ERROR';\n"
                    "\\i " LIBDIR "/fixup-privileges\n" );

        if ( report ) {
            todo++;
            printf( " - Alter privileges on database '%s'.\n"
                    "   As user %s, run:\n\n"
                    "psql %s -f - <<PSQL;\n%sPSQL\n\n",
                    dbname->cstr(), PGUSER, dbname->cstr(), cmd.cstr() );
        }
        else {
            if ( !silent )
                printf( "Altering privileges on database '%s'.\n",
                        dbname->cstr() );
            if ( psql( cmd ) < 0 )
                return;
        }
    }

    if ( d->state == Done ) {
        configFile();
    }
}


void configFile()
{
    setreuid( 0, 0 );

    String p( *dbpass );
    if ( p.contains( " " ) )
        p = "'" + p + "'";

    String cf( Configuration::configFile() );
    String v( Configuration::compiledIn( Configuration::Version ) );
    String intro(
        "# Archiveopteryx configuration. See archiveopteryx.conf(5) "
        "for details.\n"
        "# Automatically generated while installing Archiveopteryx "
        + v + ".\n\n"
    );

    String dbhost( "db-address = " + *dbaddress + "\n" );
    if ( dbport != 0 )
        dbhost.append( "db-port = " + fn( dbport ) + "\n" );

    String cfg(
        dbhost +
        "db-name = " + *dbname + "\n"
        "db-user = " + *dbuser + "\n"
        "db-password = " + p + "\n\n"
        "logfile = " LOGFILE "\n"
        "logfile-mode = " LOGFILEMODE "\n"
    );

    String other(
        "\n"
        "# Specify the hostname if Archiveopteryx gets it wrong at runtime.\n"
        "# (We suggest not using the name \"localhost\".)\n"
        "# hostname = fully.qualified.hostname\n\n"
        "# Uncomment the next line to start the POP3 server.\n"
        "# use-pop = true\n\n"
        "# Change the following to tell smtpd(8) to accept connections on\n"
        "# an address other than the default localhost.\n"
        "# lmtp-address = 192.0.2.1\n"
        "# lmtp-port = 2026\n\n"
        "# Uncomment the following to keep a filesystem copy of all messages\n"
        "# that couldn't be parsed and delivered into the database.\n"
        "# message-copy = errors\n"
        "# message-copy-directory = /usr/local/archiveopteryx/messages\n\n"
        "# Uncomment the following to reject all plaintext authentication.\n"
        "# allow-plaintext-passwords = never\n\n"
        "# Uncomment the next line to use your own TLS certificate.\n"
        "# tls-certificate = /usr/local/archiveopteryx/...\n\n"
        "# Uncomment the next line to log more debugging information.\n"
        "# log-level = debug\n\n"
        "# Uncomment the following ONLY if necessary for debugging.\n"
        "# security = off\n"
        "# use-tls = false\n"
    );

    if ( exists( cf ) && generatedPass ) {
        fprintf( stderr, "Not overwriting existing %s!\n\n"
                 "%s should contain:\n\n%s\n", cf.cstr(), cf.cstr(),
                 cfg.cstr() );
    }
    else if ( !exists( cf ) ) {
        if ( report ) {
            todo++;
            printf( " - Generate a default configuration file.\n"
                    "   %s should contain:\n\n%s\n", cf.cstr(), cfg.cstr() );
        }
        else {
            File f( cf, File::Write, 0600 );
            if ( !f.valid() ) {
                fprintf( stderr, "Could not open %s for writing.\n",
                         cf.cstr() );
                fprintf( stderr, "%s should contain:\n\n%s\n\n",
                         cf.cstr(), cfg.cstr() );
                exit( -1 );
            }
            else {
                if ( !silent )
                    printf( "Generating default %s\n", cf.cstr() );
                f.write( intro );
                f.write( cfg );
                f.write( other );
            }
        }
    }

    superConfig();
}


void superConfig()
{
    String p( *dbownerpass );
    if ( p.contains( " " ) )
        p = "'" + p + "'";

    String cf( Configuration::compiledIn( Configuration::ConfigDir ) );
    cf.append( "/aoxsuper.conf" );

    String v( Configuration::compiledIn( Configuration::Version ) );
    // XXX: Change the manpage reference below if appropriate.
    String intro(
        "# Archiveopteryx configuration. See archiveopteryx.conf(5) "
        "for details.\n"
        "# Automatically generated while installing Archiveopteryx "
        + v + ".\n\n"
    );
    String cfg(
        "# Security note: Anyone who can read this password can do\n"
        "# anything to the database, including delete all mail.\n"
        "db-owner = " + *dbowner + "\n"
        "db-owner-password = " + p + "\n"
    );

    if ( exists( cf ) && generatedOwnerPass ) {
        fprintf( stderr, "Not overwriting existing %s!\n\n"
                 "%s should contain:\n\n%s\n", cf.cstr(), cf.cstr(),
                 cfg.cstr() );
    }
    else if ( !exists( cf ) ) {
        if ( report ) {
            todo++;
            printf( " - Generate the privileged configuration file.\n"
                    "   %s should contain:\n\n%s\n", cf.cstr(), cfg.cstr() );
        }
        else {
            File f( cf, File::Write, 0400 );
            if ( !f.valid() ) {
                fprintf( stderr, "Could not open %s for writing.\n\n",
                         cf.cstr() );
                fprintf( stderr, "%s should contain:\n\n%s\n",
                         cf.cstr(), cfg.cstr() );
                exit( -1 );
            }
            else {
                if ( !silent )
                    printf( "Generating default %s\n", cf.cstr() );
                f.write( intro );
                f.write( cfg );
            }
        }
    }

    permissions();
}


void permissions()
{
    struct stat st;

    struct passwd * p = getpwnam( AOXUSER );
    struct group * g = getgrnam( AOXGROUP );

    // This should never happen, but I'm feeling paranoid.
    if ( !report && !( p && g ) ) {
        fprintf( stderr, "getpwnam(AOXUSER)/getgrnam(AOXGROUP) failed "
                 "in non-reporting mode.\n" );
        exit( -1 );
    }

    String cf( Configuration::configFile() );

    // If archiveopteryx.conf doesn't exist, or has the wrong ownership
    // or permissions:
    if ( stat( cf.cstr(), &st ) != 0 || !p || !g ||
         st.st_uid != p->pw_uid ||
         (gid_t)st.st_gid != (gid_t)g->gr_gid ||
         st.st_mode & S_IRWXU != ( S_IRUSR|S_IWUSR ) )
    {
        if ( report ) {
            todo++;
            printf( " - Set permissions and ownership on %s.\n"
                    "   chmod 0600 %s\n"
                    "   chown %s:%s %s\n",
                    cf.cstr(), cf.cstr(), AOXUSER, AOXGROUP, cf.cstr() );
        }
        else {
            if ( !silent )
                printf( "Setting ownership and permissions on %s\n",
                        cf.cstr() );

            if ( chmod( cf.cstr(), 0600 ) < 0 )
                fprintf( stderr, "Could not \"chmod 0600 %s\" (-%d).\n",
                         cf.cstr(), errno );

            if ( chown( cf.cstr(), p->pw_uid, g->gr_gid ) < 0 )
                fprintf( stderr, "Could not \"chown %s:%s %s\" (-%d).\n",
                         AOXUSER, AOXGROUP, cf.cstr(), errno );
        }
    }

    String scf( Configuration::compiledIn( Configuration::ConfigDir ) );
    scf.append( "/aoxsuper.conf" );

    // If aoxsuper.conf doesn't exist, or has the wrong ownership or
    // permissions:
    if ( stat( scf.cstr(), &st ) != 0 || st.st_uid != 0 ||
         (gid_t)st.st_gid != (gid_t)0 || st.st_mode & S_IRWXU != S_IRUSR )
    {
        if ( report ) {
            todo++;
            printf( " - Set permissions and ownership on %s.\n"
                    "   chmod 0400 %s\n"
                    "   chown root:root %s\n",
                    scf.cstr(), scf.cstr(), scf.cstr() );
        }
        else {
            if ( !silent )
                printf( "Setting ownership and permissions on %s\n",
                        scf.cstr() );

            if ( chmod( scf.cstr(), 0400 ) < 0 )
                fprintf( stderr, "Could not \"chmod 0400 %s\" (-%d).\n",
                         scf.cstr(), errno );

            if ( chown( scf.cstr(), 0, 0 ) < 0 )
                fprintf( stderr, "Could not \"chown root:root %s\" (-%d).\n",
                         scf.cstr(), errno );
        }
    }

    String mcd( Configuration::text( Configuration::MessageCopyDir ) );

    // If the message-copy-directory exists and has the wrong ownership
    // or permissions:
    if ( stat( mcd.cstr(), &st ) == 0 &&
         ( !( p && g ) ||
           ( st.st_uid != p->pw_uid ||
             (gid_t)st.st_gid != (gid_t)g->gr_gid ||
             st.st_mode & S_IRWXU != S_IRWXU ) ) )
    {
        if ( report ) {
            todo++;
            printf( " - Set permissions and ownership on %s.\n"
                    "   chmod 0700 %s\n"
                    "   chown %s:%s %s\n",
                    mcd.cstr(), mcd.cstr(), AOXUSER, AOXGROUP,
                    mcd.cstr() );
        }
        else {
            if ( !silent )
                printf( "Setting ownership and permissions on %s\n",
                        mcd.cstr() );

            if ( chmod( mcd.cstr(), 0700 ) < 0 )
                fprintf( stderr, "Could not \"chmod 0600 %s\" (-%d).\n",
                         mcd.cstr(), errno );

            if ( chown( mcd.cstr(), p->pw_uid, g->gr_gid ) < 0 )
                fprintf( stderr, "Could not \"chown %s:%s %s\" (-%d).\n",
                         AOXUSER, AOXGROUP, mcd.cstr(), errno );
        }
    }

    String jd( Configuration::text( Configuration::JailDir ) );

    // If the jail directory exists and has the wrong ownership or
    // permissions (i.e. we own it or have any rights to it):
    if ( stat( jd.cstr(), &st ) == 0 &&
         ( ( st.st_uid != 0 &&
             !( p && st.st_uid != p->pw_uid ) ) ||
           ( st.st_gid != 0 &&
             !( g && (gid_t)st.st_gid != (gid_t)g->gr_gid ) ) ||
           ( st.st_mode & S_IRWXO ) != 0 ) )
    {
        if ( report ) {
            todo++;
            printf( " - Set permissions and ownership on %s.\n"
                    "   chmod 0700 %s\n"
                    "   chown root:root %s\n",
                    jd.cstr(), jd.cstr(), jd.cstr() );
        }
        else {
            if ( !silent )
                printf( "Setting ownership and permissions on %s\n",
                        jd.cstr() );

            if ( chmod( jd.cstr(), 0700 ) < 0 )
                fprintf( stderr, "Could not \"chmod 0600 %s\" (-%d).\n",
                         jd.cstr(), errno );

            if ( chown( jd.cstr(), 0, 0 ) < 0 )
                fprintf( stderr, "Could not \"chown root:root %s\" (%d).\n",
                         jd.cstr(), errno );
        }
    }

    if ( report && todo == 0 )
        printf( "(Nothing.)\n" );
    else if ( !silent )
        printf( "Done.\n" );

    EventLoop::shutdown();
}


int psql( const String &cmd )
{
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
        execlp( "psql", "psql", dbname->cstr(), "-f", "-",
                (const char *) 0 );
        exit( -1 );
    }
    else {
        int status = 0;
        if ( pid > 0 ) {
            write( fd[1], cmd.cstr(), cmd.length() );
            close( fd[1] );
            waitpid( pid, &status, 0 );
        }
        if ( pid < 0 || ( WIFEXITED( status ) &&
                          WEXITSTATUS( status ) != 0 ) )
        {
            fprintf( stderr, "Couldn't execute psql.\n" );
            if ( WEXITSTATUS( status ) == 255 )
                fprintf( stderr, "(No psql in PATH=%s)\n", getenv( "PATH" ) );
            fprintf( stderr, "Please re-run the installer after "
                     "doing the following as user %s:\n\n"
                     "psql %s -f - <<PSQL;\n%sPSQL\n\n",
                     PGUSER, dbname->cstr(), cmd.cstr() );
            EventLoop::shutdown();
            return -1;
        }
    }

    return 0;
}
