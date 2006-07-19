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
String * dbpass;


const char * PGUSER;
const char * ORYXUSER;
const char * ORYXGROUP;
const char * DBADDRESS;


void help();
void error( String );
bool exists( String );
void findPgUser();
void oryxGroup();
void oryxUser();
void database();
void configFile();
void permissions();


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;

    PGUSER = Configuration::compiledIn( Configuration::PgUser );
    ORYXUSER = Configuration::compiledIn( Configuration::OryxUser );
    ORYXGROUP = Configuration::compiledIn( Configuration::OryxGroup );
    DBADDRESS = Configuration::compiledIn( Configuration::DefaultDbAddress );

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
                DBADDRESS = *av++;
            ac--;
        }
        else {
            error( "Unrecognised argument: '" + s + "'" );
        }
    }

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    findPgUser();

    String dba( DBADDRESS );
    if ( dba[0] == '/' && !exists( dba ) ) {
        fprintf( stderr, "Warning: DBADDRESS is set to '%s', "
                 "which does not exist.\n", DBADDRESS );
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
        "  the PostgreSQL superuser. The default is to try $PGSQL (if\n"
        "  set), postgres and pgsql in turn.\n\n"
        "  The \"-a address\" flag allows you to specify a different\n"
        "  address for the Postgres server. The default is '%s'.\n",
        ORYXGROUP, ORYXUSER,
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


bool exists( String f )
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
        Configuration::add( "db-max-handles = 1" );
        Configuration::add( "db-address = '" + String( DBADDRESS ) + "'" );
        Configuration::add( "db-user = '" + String( PGUSER ) + "'" );
        Configuration::add( "db-name = 'template1'" );
        Database::setup();
        d = new Dispatcher;
        dbpass = new String;
        Allocator::addEternal( dbpass, "DBPASS" );

        d->q = new Query( "select version() as version", d );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->state == 0 ) {
        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r ) {
            fprintf( stderr, "Couldn't check PostgreSQL server version.\n" );
            EventLoop::shutdown();
            return;
        }
        else {
            String s( r->getString( "version" ) );
            int n = s.find( ' ', 11 );
            String v( s.mid( 11, n-11 ) );

            if ( !s.startsWith( "PostgreSQL" ) || n < 0 ||
                 ( v.startsWith( "7" ) && !v.startsWith( "7.4" ) ) ||
                 v == "7.4.0" || v == "7.4.1" || !v.startsWith( "8" ) )
            {
                fprintf( stderr, "Archiveopteryx requires PostgreSQL 7.4.2 "
                         "or higher (found only '%s').\n", v.cstr() );
                EventLoop::shutdown();
                return;
            }

            if ( v.startsWith( "7" ) || v.startsWith( "8.0" ) ) {
                fprintf( stderr, "Note: Starting May 2007, Archiveopteryx "
                         "will require PostgreSQL 8.1.0 or higher. Please "
                         "upgrade the running server (%s) at your "
                         "convenience.\n", v.cstr() );
            }

            d->q = new Query( "select usename from pg_catalog.pg_user where "
                              "usename=$1", d );
            d->q->bind( 1, DBUSER );
            d->q->execute();
            d->state = 1;
        }
    }

    if ( d->state == 1 ) {
        if ( !d->q->done() )
            return;

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
                d->state = 3;
                printf( " - Create a PostgreSQL user named '" DBUSER "'.\n"
                        "   As user %s, run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n",
                        PGUSER, create.cstr() );
            }
            else {
                d->state = 2;
                if ( !silent )
                    printf( "Creating the '" DBUSER "' PostgreSQL user.\n" );
                d->q = new Query( create, d );
                d->q->execute();
            }
        }
        else {
            d->state = 3;
        }
    }

    if ( d->state == 2 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create PostgreSQL user '" DBUSER
                     "' (%s).\nPlease create it by hand and re-run the "
                     "installer.\n", d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        d->state = 3;
    }

    if ( d->state == 3 ) {
        d->state = 4;
        d->q =
            new Query( "select datname::text,usename::text,"
                       "pg_encoding_to_char(encoding)::text as encoding "
                       "from pg_database d join pg_user u "
                       "on (d.datdba=u.usesysid) where datname=$1", d );
        d->q->bind( 1, DBNAME );
        d->q->execute();
    }

    if ( d->state == 4 ) {
        if ( !d->q->done() )
            return;
        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create database " DBNAME " with owner " DBUSER " "
                           "encoding 'UNICODE'" );
            if ( report ) {
                d->state = 8;
                printf( " - Create a database named '" DBNAME "'.\n"
                        "   As user %s, run:\n\n"
                        "psql -d template1 -qc \"%s\"\n\n",
                        PGUSER, create.cstr() );
                // We let state 8 think the mailstore query returned 0
                // rows, so that it prints an appropriate message.
            }
            else {
                d->state = 5;
                if ( !silent )
                    printf( "Creating the '" DBNAME "' database.\n" );
                d->q = new Query( create, d );
                d->q->execute();
            }
        }
        else {
            const char * s = 0;
            String encoding( r->getString( "encoding" ) );
            if ( r->getString( "usename" ) != DBUSER )
                s = "is not owned by user " DBUSER;
            else if ( encoding != "UNICODE" && encoding != "UTF8" )
                s = "does not have encoding UNICODE";
            if ( s ) {
                fprintf( stderr, " - Database '" DBNAME "' exists, but it %s."
                         "\n   (That will need to be fixed by hand.)\n", s );
                if ( !report )
                    exit( -1 );
            }
            d->state = 6;
        }
    }

    if ( d->state == 5 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            fprintf( stderr, "Couldn't create database '" DBNAME "' (%s).\n"
                     "Please create it by hand and re-run the installer.\n",
                     d->q->error().cstr() );
            EventLoop::shutdown();
            return;
        }
        d->state = 6;
    }

    if ( d->state == 6 ) {
        // How utterly, utterly disgusting.
        Database::disconnect();

        if ( String( ORYXUSER ) == DBUSER ) {
            struct passwd * u = getpwnam( ORYXUSER );
            if ( u )
                seteuid( u->pw_uid );
        }

        Configuration::setup( "" );
        Configuration::add( "db-user = '" DBUSER "'" );
        Configuration::add( "db-name = '" DBNAME "'" );
        Database::setup();
        d->state = 7;
        d->q = new Query( "select relname from pg_catalog.pg_class where "
                          "relname='mailstore'", d );
        d->q->execute();
    }

    if ( d->state == 7 ) {
        if ( !d->q->done() )
            return;
        if ( d->q->failed() ) {
            if ( report ) {
                d->state = 10;
                printf( " - May need to load the Oryx database schema.\n   "
                        "(Couldn't query database '" DBNAME "' to make sure "
                        "it's needed: %s.)\n", d->q->error().cstr() );
            }
            else {
                fprintf( stderr, "Couldn't query database '" DBNAME "' to "
                         "see if the schema needs to be loaded (%s).\n",
                         d->q->error().cstr() );
                EventLoop::shutdown();
                return;
            }
        }
        d->state = 8;
    }

    if ( d->state == 8 ) {
        Row * r = d->q->nextRow();
        if ( !r ) {
            String cmd( "\\set ON_ERROR_STOP\n"
                        "SET SESSION AUTHORIZATION " DBUSER ";\n"
                        "SET client_min_messages TO 'ERROR';\n"
                        "\\i " LIBDIR "/schema.pg\n"
                        "\\i " LIBDIR "/field-names\n"
                        "\\i " LIBDIR "/flag-names\n" );
            if ( report ) {
                d->state = 10;
                printf( " - Load the Oryx database schema.\n   "
                        "As user %s, run:\n\n"
                        "psql " DBNAME " -f - <<PSQL;\n%sPSQL\n\n",
                        PGUSER, cmd.cstr() );
            }
            else {
                d->state = 10;

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
                    execlp( "psql", "psql", DBNAME, "-f", "-",
                            (const char *) 0 );
                    exit( -1 );
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
                        fprintf( stderr,
                                 "Couldn't install the Oryx schema.\n" );
                        if ( WEXITSTATUS( status ) == 255 )
                            fprintf( stderr, "(No psql in PATH=%s)\n",
                                     getenv( "PATH" ) );
                        fprintf( stderr, "Please re-run the installer after "
                                 "doing the following as user %s:\n\n"
                                 "psql " DBNAME " -f - <<PSQL;\n%sPSQL\n\n",
                                 PGUSER, cmd.cstr() );
                        EventLoop::shutdown();
                        return;
                    }
                }
            }
        }
        else {
            d->state = 9;
            d->q = new Query( "select revision from mailstore", d );
            d->q->execute();
        }
    }

    if ( d->state == 9 ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( !r || d->q->failed() ) {
            if ( report ) {
                d->state = 10;
                printf( " - May need to upgrade the Oryx database schema.\n   "
                        "(Couldn't query mailstore table to make sure it's "
                        "needed.)\n" );
            }
            else {
                fprintf( stderr, "Couldn't query database '" DBNAME "' to "
                         "see if the schema needs to be upgraded (%s).\n",
                         d->q->error().cstr() );
                EventLoop::shutdown();
                return;
            }
        }
        else if ( r->getInt( "revision" ) != Schema::currentRevision() ) {
            d->state = 10;
            printf( " - You need to upgrade the Oryx database schema.\n   "
                    "Please run 'ms upgrade schema' by hand.\n" );
        }
        else {
            d->state = 10;
        }
    }

    if ( d->state == 10 ) {
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
        "# Archiveopteryx configuration. See archiveopteryx.conf(5) "
        "for details.\n"
        "# Automatically generated while installing Archiveopteryx "
        + v + ".\n\n"
    );
    String cfg(
        "db-address = " + String( DBADDRESS ) + "\n"
        "db-name = " DBNAME "\n"
        "db-user = " DBUSER "\n"
        "# Security note: Anyone who can read this password can do\n"
        "# anything to the database, including delete all mail.\n"
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

    if ( !exists( cf ) ) {
        if ( report ) {
            printf( " - Generate a default configuration file.\n"
                    "   %s should contain:\n\n%s\n", cf.cstr(), cfg.cstr() );
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
                f.write( other );
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

    // If the configuration file doesn't exist, or has the wrong
    // ownership or permissions:
    if ( stat( cf.cstr(), &st ) != 0 || !p || !g ||
         st.st_uid != p->pw_uid ||
         (gid_t)st.st_gid != (gid_t)g->gr_gid ||
         st.st_mode & S_IRWXU != ( S_IRUSR|S_IWUSR ) )
    {
        if ( report ) {
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
                fprintf( stderr, "Could not \"chown oryx:oryx %s\".\n",
                         cf.cstr() );
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
                fprintf( stderr, "Could not \"chown oryx:oryx %s\".\n",
                         mcd.cstr() );
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

    if ( !report && !silent )
        printf( "Done.\n" );

    EventLoop::shutdown();
}
