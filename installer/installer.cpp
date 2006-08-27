// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "configuration.h"
#include "eventloop.h"
#include "database.h"
#include "entropy.h"
#include "schema.h"
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

String * dbname;
String * dbaddress;
String * dbuser;
String * dbpass;
String * dbowner;
String * dbownerpass;

int todo = 0;
bool generatedPass = false;
bool generatedOwnerPass = false;

const char * PGUSER;
const char * ORYXUSER;
const char * ORYXGROUP;
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

    PGUSER = Configuration::compiledIn( Configuration::PgUser );
    ORYXUSER = Configuration::compiledIn( Configuration::OryxUser );
    ORYXGROUP = Configuration::compiledIn( Configuration::OryxGroup );
    DBADDRESS = Configuration::compiledIn( Configuration::DefaultDbAddress );

    dbname = new String( DBNAME );
    Allocator::addEternal( dbname, "DBNAME" );
    dbaddress = new String( DBADDRESS );
    Allocator::addEternal( dbaddress, "DBADDRESS" );
    dbuser = new String( DBUSER );
    Allocator::addEternal( dbuser, "DBUSER" );
    dbpass = new String( DBPASS );
    Allocator::addEternal( dbpass, "DBPASS" );
    dbowner = new String( DBOWNER );
    Allocator::addEternal( dbowner, "DBOWNER" );
    dbownerpass = new String( DBOWNERPASS );
    Allocator::addEternal( dbownerpass, "DBOWNERPASS" );

    av++;
    while ( ac-- > 1 ) {
        String s( *av++ );

        if ( s == "-?" || s == "-h" || s == "--help" ) {
            help();
        }
        else if ( s == "-q" ) {
            silent = true;
        }
        else if ( s == "-n" ) {
            report = true;
        }
        else if ( s == "-g" || s == "-u" || s == "-p" || s == "-a" ) {
            if ( ac == 1 )
                error( s + " specified with no argument." );
            if ( s == "-g" )
                ORYXGROUP = *av++;
            else if ( s == "-u" )
                ORYXUSER = *av++;
            else if ( s == "-p" )
                PGUSER = *av++;
            else if ( s == "-a" )
                *dbaddress = *av++;
            ac--;
        }
        else {
            error( "Unrecognised argument: '" + s + "'" );
        }
    }

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    findPgUser();

    if ( dbaddress->startsWith( "/" ) && !exists( *dbaddress ) ) {
        fprintf( stderr, "Warning: DBADDRESS is set to '%s', "
                 "which does not exist.\n", dbaddress->cstr() );
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

    Configuration::setup( "archiveopteryx.conf" );
    String super( Configuration::compiledIn( Configuration::ConfigDir ) );
    super.append( "/aoxsuper.conf" );
    Configuration::read( super, true );

    configure();

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
        "[-a address]\n\n"
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
        "  The defaults are set at build time in the Jamsettings file.\n\n",
        ORYXGROUP, ORYXUSER, dbuser->cstr(), dbowner->cstr(), dbname->cstr(),
        dbowner->cstr(), dbuser->cstr(),
        ORYXGROUP, ORYXUSER,
        DBADDRESS
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
    struct group * g = getgrnam( ORYXGROUP );
    if ( g )
        return;

    if ( report ) {
        todo++;
        printf( " - Create a group named '%s' (e.g. \"groupadd %s\").\n",
                ORYXGROUP, ORYXGROUP );
        return;
    }

    String cmd;
    if ( exists( "/usr/sbin/groupadd" ) ) {
        cmd.append( "/usr/sbin/groupadd " );
        cmd.append( ORYXGROUP );
    }
    else if ( exists( "/usr/sbin/pw" ) ) {
        cmd.append( "/usr/sbin/pw groupadd " );
        cmd.append( ORYXGROUP );
    }

    int status = 0;
    if ( !cmd.isEmpty() ) {
        if ( !silent )
            printf( "Creating the '%s' group.\n", ORYXGROUP );
        status = system( cmd.cstr() );
    }

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 ||
         getgrnam( ORYXGROUP ) == 0 )
    {
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
        todo++;
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
    else if ( exists( "/usr/sbin/pw" ) ) {
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

    if ( cmd.isEmpty() || WEXITSTATUS( status ) != 0 ||
         getpwnam( ORYXUSER ) == 0 )
    {
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


enum DbState {
    Unused, CheckingVersion, CheckUser, CheckingUser, CreatingUser,
    CheckSuperuser, CheckingSuperuser, CreatingSuperuser, CheckDatabase,
    CheckingDatabase, CreatingDatabase, CheckSchema, CheckingSchema,
    CreateSchema, CheckingRevision, UpgradingSchema, CheckPrivileges,
    CheckingPrivileges, AlteringPrivileges, Done
};


class Dispatcher
    : public EventHandler
{
public:
    Query * q;
    DbState state;

    Dispatcher() : state( Unused ) {}
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
                d->state = CheckDatabase;
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
            d->state = CheckDatabase;
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
        d->state = CheckDatabase;
    }

    if ( d->state == CheckDatabase ) {
        d->state = CheckingDatabase;
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
        if ( !r ) {
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
            String s;
            String encoding( r->getString( "encoding" ) );
            if ( r->getString( "usename" ) != *dbowner )
                s = "is not owned by user " + *dbowner;
            else if ( encoding != "UNICODE" && encoding != "UTF8" )
                s = "does not have encoding UNICODE";
            if ( !s.isEmpty() ) {
                todo++;
                fprintf( stderr, " - Database '%s' exists, but it %s.\n"
                         "   (That will need to be fixed by hand.)\n",
                         dbname->cstr(), s.cstr() );
                if ( !report ) {
                    EventLoop::shutdown();
                    return;
                }
            }
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
        // How utterly, utterly disgusting.
        Database::disconnect();

        if ( *dbowner == ORYXUSER ) {
            struct passwd * u = getpwnam( ORYXUSER );
            if ( u )
                seteuid( u->pw_uid );
        } else if ( exists( "/etc/debian_version" ) &&
                    exists( "/etc/postgresql/pg_hba.conf" ) ) {
            printf( " - Note: On Debian, PostgreSQL supports only IDENT "
                    "authentication by default.\n"
                    "         This program runs as root, so it may not have "
                    "permission to\n"
                    "         access the %s database as user %s.\n"
                    "         To fix this, enable password authentication in "
                    "/etc/postgresql/pg_hva.conf\n",
                    dbname->cstr(), dbowner->cstr() );
        }

        Configuration::setup( "" );
        Configuration::add( "db-user = '" + *dbowner + "'" );
        Configuration::add( "db-name = '" + *dbname + "'" );
        Database::setup( 1 );

        d->state = CheckingSchema;
        d->q = new Query( "select relname from pg_catalog.pg_class where "
                          "relname='mailstore'", d );
        d->q->execute();
    }

    if ( d->state == CheckingSchema ) {
        if ( !d->q->done() )
            return;
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
                    printf( "Loading database schema:\n" );
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
            int revision = r->getInt( "revision" );

            if ( revision > Schema::currentRevision() ) {
                String v( Configuration::compiledIn( Configuration::Version ) );
                fprintf( stderr, "The schema in database '%s' (revision #%d) "
                         "is newer than this version of Archiveopteryx (%s) "
                         "recognises (up to #%d).\n", dbname->cstr(), revision,
                         v.cstr(), Schema::currentRevision() );
                EventLoop::shutdown();
                return;
            }
            else if ( revision < Schema::currentRevision() ) {
                if ( report ) {
                    todo++;
                    printf( " - Upgrade the database schema (\"aox upgrade "
                            "schema -n\" to see what would happen).\n" );
                    d->state = CheckPrivileges;
                }
                else {
                    d->state = UpgradingSchema;
                    Schema * s = new Schema( d, true, true );
                    d->q = s->result();
                    s->execute();
                }
            }
            else {
                d->state = CheckPrivileges;
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
        d->state = CheckPrivileges;
    }

    if ( d->state == CheckPrivileges ) {
        d->state = CheckingPrivileges;
        d->q = new Query( "select * from information_schema.table_privileges "
                          "where privilege_type='DELETE' and "
                          "table_name='messages' and grantee=$1", d );
        d->q->bind( 1, *dbuser );
        d->q->execute();
    }

    if ( d->state == CheckingPrivileges ) {
        if ( !d->q->done() )
            return;

        d->state = Done;
        Row * r = d->q->nextRow();
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't check privileges for user '%s' in "
                     "database '%s' (%s).\n", dbuser->cstr(), dbname->cstr(),
                     d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        else if ( r ) {
            String cmd( "\\set ON_ERROR_STOP\n"
                        "SET client_min_messages TO 'ERROR';\n"
                        "\\i " LIBDIR "/revoke-privileges\n"
                        "\\i " LIBDIR "/grant-privileges\n" );
            if ( report ) {
                todo++;
                printf( " - Revoke privileges on database '%s' from user '%s'."
                        "\n   As user %s, run:\n\n"
                        "psql %s -f - <<PSQL;\n%sPSQL\n\n",
                        dbname->cstr(), dbuser->cstr(), PGUSER, dbname->cstr(),
                        cmd.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Revoking privileges on database '%s' from user "
                            "'%s'.\n", dbname->cstr(), dbuser->cstr() );
                if ( psql( cmd ) < 0 )
                    return;
            }
        }
    }

    if ( d->state == Done ) {
        configFile();
    }
}


void configFile()
{
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
    String cfg(
        "db-address = " + *dbaddress + "\n"
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
            setreuid( 0, 0 );
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
            setreuid( 0, 0 );
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

    struct passwd * p = getpwnam( ORYXUSER );
    struct group * g = getgrnam( ORYXGROUP );

    // This should never happen, but I'm feeling paranoid.
    if ( !report && !( p && g ) ) {
        fprintf( stderr, "getpwnam(ORYXUSER)/getgrnam(ORYXGROUP) failed "
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
                    cf.cstr(), cf.cstr(), ORYXUSER, ORYXGROUP, cf.cstr() );
        }
        else {
            if ( !silent )
                printf( "Setting ownership and permissions on %s\n",
                        cf.cstr() );

            if ( chmod( cf.cstr(), 0600 ) < 0 )
                fprintf( stderr, "Could not \"chmod 0600 %s\".\n",
                         cf.cstr() );

            if ( chown( cf.cstr(), p->pw_uid, g->gr_gid ) < 0 )
                fprintf( stderr, "Could not \"chown %s:%s %s\".\n",
                         ORYXUSER, ORYXGROUP, cf.cstr() );
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
                fprintf( stderr, "Could not \"chmod 0400 %s\".\n",
                         scf.cstr() );

            if ( chown( scf.cstr(), 0, 0 ) < 0 )
                fprintf( stderr, "Could not \"chown root:root %s\".\n",
                         scf.cstr() );
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
                    mcd.cstr(), mcd.cstr(), ORYXUSER, ORYXGROUP,
                    mcd.cstr() );
        }
        else {
            if ( !silent )
                printf( "Setting ownership and permissions on %s\n",
                        mcd.cstr() );

            if ( chmod( mcd.cstr(), 0700 ) < 0 )
                fprintf( stderr, "Could not \"chmod 0600 %s\".\n",
                         mcd.cstr() );

            if ( chown( mcd.cstr(), p->pw_uid, g->gr_gid ) < 0 )
                fprintf( stderr, "Could not \"chown %s:%s %s\".\n",
                         ORYXUSER, ORYXGROUP, mcd.cstr() );
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
                fprintf( stderr, "Could not \"chmod 0600 %s\".\n",
                         jd.cstr() );

            if ( chown( jd.cstr(), 0, 0 ) < 0 )
                fprintf( stderr, "Could not \"chown root:root %s\".\n",
                         jd.cstr() );
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
