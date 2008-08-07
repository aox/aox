// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "stderrlogger.h"
#include "configuration.h"
#include "transaction.h"
#include "eventloop.h"
#include "database.h"
#include "entropy.h"
#include "schema.h"
#include "granter.h"
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
#include <termios.h>


uid_t postgres;
class Dispatcher * d;
bool report = false;
bool silent = false;
uint verbosity = 0;

String * db;
String * dbname;
String * dbsocket;
String * dbaddress;
String * dbuser;
String * dbpass;
String * dbowner;
String * dbownerpass;
String * dbpgpass;
String * dbschema;

bool privateSchema = false;

uint dbport = 5432;
bool askPass = false;

int todo = 0;
bool generatedPass = false;
bool generatedOwnerPass = false;

const char * PGUSER;
const char * AOXUSER;
const char * AOXGROUP;
const char * DBADDRESS;


void help();
void error( String );
String pgErr( const Query * );
bool exists( const String & );
void configure();
void findPostgres();
void findPgUser();
void badSocket( String * );
bool checkSocket( String * );
void readPassword();
void readPgPass();
void oryxGroup();
void oryxUser();
void database();
void configFile();
void superConfig();
void permissions();
int psql( const String & );

void checkVersion();
void checkEncoding();
void createUser();
void createSuperuser();
void createDatabase();
void createLang();
void createNamespace();
void checkOwnership();
void grantUsage();
void splitPrivileges();
void createSchema();
void upgradeSchema();
void grantPrivileges();


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

    db = 0;
    postgres = 0;
    dbsocket = 0;
    dbpgpass = 0;
    dbaddress = 0;

    dbname = new String( DBNAME );
    dbschema = new String( DBSCHEMA );

    dbuser = new String( AOXUSER );
    Allocator::addEternal( dbuser, "AOXUSER" );
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
            verbosity = 0;
        }
        else if ( s == "-n" ) {
            report = true;
        }
        else if ( s == "-g" || s == "-u" || s == "-p" || s == "-a" ||
                  s == "-s" || s == "-d" || s == "-S" )
        {
            if ( ac == 1 )
                error( s + " specified with no argument." );
            if ( s == "-g" )
                AOXGROUP = *av++;
            else if ( s == "-u" )
                AOXUSER = *av++;
            else if ( s == "-p" )
                PGUSER = *av++;
            else if ( s == "-a" )
                dbaddress = new String( *av++ );
            else if ( s == "-s" )
                dbsocket = new String( *av++ );
            else if ( s == "-d" )
                dbname = new String( *av++ );
            else if ( s == "-S" )
                dbschema = new String( *av++ );
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
        else if ( s == "-P" ) {
            askPass = true;
        }
        else if ( s == "-v" ) {
            verbosity++;
        }
        else {
            error( "Unrecognised argument: " + s.quoted() );
        }
    }

    if ( dbsocket )
        Allocator::addEternal( dbsocket, "DBSOCKET" );
    if ( dbaddress )
        Allocator::addEternal( dbaddress, "DBADDRESS" );

    Allocator::addEternal( dbname, "DBNAME" );
    Allocator::addEternal( dbschema, "DBSCHEMA" );

    Allocator::addEternal( new StderrLogger( "installer", verbosity ),
                           "log object" );

    if ( verbosity )
        printf( "Archiveopteryx installer version %s\n",
                Configuration::compiledIn( Configuration::Version ) );

    if ( getuid() != 0 )
        error( "Please run the installer as root." );

    if ( verbosity ) {
        String d( Configuration::compiledIn( Configuration::ConfigDir ) );
        printf( "Will read these configuration files:\n"
                "    %s/archiveopteryx.conf\n"
                "    %s/aoxsuper.conf\n",
                d.cstr(), d.cstr() );
    }

    Configuration::setup( "archiveopteryx.conf" );
    String super( Configuration::compiledIn( Configuration::ConfigDir ) );
    super.append( "/aoxsuper.conf" );
    Configuration::read( super, true );

    configure();

    if ( *dbschema != "public" )
        ::privateSchema = true;

    findPostgres();

    if ( report )
        printf( "Reporting what the installer needs to do.\n" );

    oryxGroup();
    oryxUser();

    if ( postgres != 0 )
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
        "    installer [-n] [-q]\n"
        "    installer [-g group] [-u user] [-p postgres] [-s socket]\n"
        "              [-a address] [-t port] [-d dbname] [-S schema]\n\n"
        "  This program does the following:\n\n"
        "    - Creates a Unix group named %s, and a user named %s.\n"
        "    - Creates Postgres users named %s and %s.\n"
        "    - Creates a database named %s, owned by %s.\n"
        "    - Loads the database schema and grants limited privileges "
        "to user %s.\n"
        "    - Generates an initial configuration file.\n"
        "    - Adjusts ownership and permissions if necessary.\n\n"
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
        "  The \"-P\" flag instructs the installer to prompt for and\n"
        "  read the Postgres superuser's password, and be prepared to\n"
        "  use that for authentication (if necessary).\n\n"
        "  The \"-s socket\" flag allows you to specify an alternate\n"
        "  location for the Postgres server's named listening socket.\n\n"
        "  The \"-a address\" flag allows you to specify a different\n"
        "  address for the Postgres server. The default is '%s'.\n\n"
        "  The \"-t port\" flag allows you to specify a different port\n"
        "  for the Postgres server. The default is 5432.\n\n"
        "  The \"-d dbname\" flag allows you to specify a database name to\n"
        "  use. The default is '%s'.\n\n"
        "  The \"-S schema\" flag allows you to specify a schema in the\n"
        "  database where objects are installed. The default is to assume\n"
        "  that objects live in the public schema.\n\n"
        "  The defaults are set at build time in the Jamsettings file.\n\n",
        AOXGROUP, AOXUSER, dbuser->cstr(), dbowner->cstr(), dbname->cstr(),
        dbowner->cstr(), dbuser->cstr(),
        AOXGROUP, AOXUSER, DBADDRESS, DBNAME
    );
    exit( 0 );
}


void error( String m )
{
    fprintf( stderr, "%s\n", m.cstr() );
    exit( -1 );
}


String pgErr( const Query * q )
{
    String p( "PostgreSQL error: " );
    p.append( q->error() );
    return p;
}


bool exists( const String & f )
{
    struct stat st;
    return stat( f.cstr(), &st ) == 0;
}


void findPostgres()
{
    String port( fn( dbport ) );

    if ( !dbsocket && *dbaddress == "127.0.0.1" )
        dbsocket = new String( "/tmp/.s.PGSQL." + port );

    if ( dbsocket ) {
        findPgUser();
        if ( checkSocket( dbsocket ) == false )
            badSocket( dbsocket );
        db = dbsocket;
    }
    else {
        if ( !*PGUSER )
            PGUSER = "postgres";
        struct passwd * p = getpwnam( PGUSER );
        if ( p )
            postgres = p->pw_uid;
        db = dbaddress;
    }
    Allocator::addEternal( db, "DB" );

    if ( askPass )
        readPassword();
    else
        readPgPass();

    if ( !silent )
        printf( "Connecting to Postgres server %s as%suser %s.\n",
                db->cstr(), ( postgres != 0 ? " Unix " : " " ),
                PGUSER );
}


void badSocket( String * sock )
{
    fprintf( stderr, "Error: Couldn't find the Postgres listening "
             "socket at '%s'.\n", sock->cstr() );

    if ( exists( "/etc/debian_version" ) &&
         exists( "/var/run/postgresql/.s.PGSQL.5432" ) )
    {
        fprintf( stderr, "(On Debian, perhaps it should be "
                 "/var/run/postgresql/.s.PGSQL.5432 instead.)\n" );
    }

    fprintf( stderr, "Please rerun the installer with "
             "\"-s /path/to/socket.file\".\n" );
    exit( -1 );
}


bool checkSocket( String * sock )
{
    if ( !sock->startsWith( "/" ) )
        return false;

    struct stat st;
    int n = stat( sock->cstr(), &st );

    if ( n < 0 ) {
        return false;
    }
    else if ( S_ISSOCK( st.st_mode ) ) {
        // This is the normal case.
    }
    else if ( S_ISDIR( st.st_mode ) ) {
        // Postgres users are used to specifying a directory and port
        // number, and letting psql turn that into a socket path. We
        // try to cooperate.

        String s( "/.s.PGSQL." + fn( dbport ) );
        sock->append( s );

        if ( !( stat( sock->cstr(), &st ) == 0 &&
                S_ISSOCK( st.st_mode ) ) )
            return false;

        fprintf( stderr, "Using '%s' as the server socket.\n",
                 sock->cstr() );
    }
    else {
        return false;
    }

    // If we were run with "-s /foo/bar/.s.PGSQL.6666", make sure we can
    // translate that into "psql -h /foo/bar -p 6666".

    if ( !sock->endsWith( "/.s.PGSQL." + fn( dbport ) ) ) {
        bool ok = false;
        String s = *sock;

        uint i = sock->length()-1;
        while ( i > 0 && (*sock)[i] != '/' )
            i--;
        if ( i > 0 && (*sock)[i] == '/' ) {
            s = sock->mid( i+1 );
            if ( s.startsWith( ".s.PGSQL." ) ) {
                String port( s.mid( 9 ) );
                dbport = port.number( &ok );
            }
        }

        if ( !ok )
            error( "Malformed socket name: " + s.quoted() );
    }

    return true;
}


void readPassword()
{
    char passwd[128];
    struct termios term;
    struct termios newt;

    if ( tcgetattr( 0, &term ) < 0 )
        error( "Couldn't get terminal attributes (-" +
               fn( errno ) + ")." );
    newt = term;
    newt.c_lflag |= ECHONL;
    newt.c_lflag &= ~(ECHO|ISIG);
    if ( tcsetattr( 0, TCSANOW, &newt ) < 0 )
        error( "Couldn't set terminal attributes (-" +
               fn( errno ) + ")." );
    printf( "Password: " );
    fgets( passwd, 128, stdin );
    tcsetattr( 0, TCSANOW, &term );
    dbpgpass = new String( passwd );
    dbpgpass->truncate( dbpgpass->length()-1 );
    Allocator::addEternal( dbpgpass, "DBPGPASS" );
}


StringList * splitFields( const String & s )
{
    StringList * l = new StringList;

    uint i = 0;
    String word;
    while ( i < s.length() ) {
        char c = s[i++];

        if ( c == ':' || c == '\n' ) {
            l->append( new String( word ) );
            word.truncate( 0 );
        }
        else {
            if ( c == '\\' )
                c = s[i++];
            word.append( c );
        }
    }

    return l;
}


void readPgPass()
{
    const char * pgpass = getenv( "PGPASSFILE" );
    if ( !pgpass )
        return;

    struct stat st;
    if ( stat( pgpass, &st ) < 0 || !S_ISREG( st.st_mode ) ||
         ( st.st_mode & (S_IRWXG|S_IRWXO) ) != 0 )
        return;

    File f( pgpass, File::Read );
    if ( !f.valid() )
        return;

    StringList::Iterator line( f.lines() );
    while ( line ) {
        StringList * fields = splitFields( *line );
        if ( fields->count() != 5 )
            return;

        String host( *fields->shift() );
        String port( *fields->shift() );
        String database( *fields->shift() );
        String username( *fields->shift() );
        String password( *fields->shift() );

        if ( ( host == "*" ||
               host == *db ||
               ( host == "localhost" &&
                 ( *db == "127.0.0.1" || db->startsWith( "/" ) ) ) ) &&
             ( port == "*" || port == fn( dbport ) ) &&
             ( database == "*" || database == "template1" ) &&
             ( username == "*" || username == PGUSER ) )
        {
            dbpgpass = new String( password );
            break;
        }

        ++line;
    }

    if ( dbpgpass ) {
        Allocator::addEternal( dbpgpass, "DBPGPASS" );
        fprintf( stderr, "Using password from PGPASSFILE='%s'\n",
                 pgpass );
    }
}


void findPgUser()
{
    struct passwd * p = 0;

    if ( *PGUSER ) {
        p = getpwnam( PGUSER );
        if ( !p )
            error( "PostgreSQL superuser " + String( PGUSER ).quoted() +
                   " does not exist (rerun with -p username)." );
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
        error( "PostgreSQL superuser unknown (PGUSER not set, and neither "
               "\"postgres\" nor \"pgsql\" worked). Please re-run the "
               "installer with \"-p username\"." );
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

    if ( *dbname == DBNAME ) {
        if ( Configuration::present( Configuration::DbName ) ) {
            *dbname = Configuration::text( Configuration::DbName );
            if ( verbosity )
                printf( "Using db-name from the configuration: %s\n",
                        dbname->cstr() );
        }
    }

    if ( *dbschema == DBSCHEMA ) {
        if ( Configuration::present( Configuration::DbSchema ) ) {
            *dbschema = Configuration::text( Configuration::DbSchema );
            if ( verbosity )
                printf( "Using db-schema from the configuration: %s\n",
                        dbschema->cstr() );
        }
    }

    if ( !dbaddress ) {
        if ( Configuration::present( Configuration::DbAddress ) ) {
            dbaddress =
                new String( Configuration::text( Configuration::DbAddress ) );
            if ( verbosity )
                printf( "Using db-address from the configuration: %s\n",
                        dbaddress->cstr() );
        }
        else {
            dbaddress = new String( DBADDRESS );
        }
        Allocator::addEternal( dbaddress, "DBADDRESS" );
    }

    if ( Configuration::present( Configuration::DbPort ) ) {
        dbport = Configuration::scalar( Configuration::DbPort );
        if ( verbosity )
            printf( "Using db-port from the configuration: %d\n", dbport );
    }

    if ( Configuration::present( Configuration::DbUser ) ) {
        *dbuser = Configuration::text( Configuration::DbUser );
        if ( verbosity )
            printf( "Using db-user from the configuration: %s\n",
                    dbuser->cstr() );
    }

    if ( Configuration::present( Configuration::DbPassword ) ) {
        *dbpass = Configuration::text( Configuration::DbPassword );
        if ( verbosity )
            printf( "Using db-password from the configuration\n" );
    }
    else if ( dbpass->isEmpty() ) {
        String p( "(database user password here)" );
        if ( !report ) {
            p = MD5::hash( Entropy::asString( 16 ) ).hex();
            generatedPass = true;
        }
        dbpass->append( p );
    }

    if ( Configuration::present( Configuration::DbOwner ) ) {
        *dbowner = Configuration::text( Configuration::DbOwner );
        if ( verbosity )
            printf( "Using db-owner from the configuration: %s\n",
                    dbowner->cstr() );
    }

    if ( Configuration::present( Configuration::DbOwnerPassword ) ) {
        *dbownerpass = Configuration::text( Configuration::DbOwnerPassword );
        if ( verbosity )
            printf( "Using db-owner-password from the configuration\n" );
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
            s.append( "The command which failed was " + cmd.quoted() );
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
            s.append( "The command which failed was " + cmd.quoted() );
        error( s );
    }
}


enum DbState {
    CheckVersion, CheckEncoding,
    CreateUser, CreateSuperuser, CreateDatabase, CreateLang,
    CreateNamespace, CheckOwnership, GrantUsage, SplitPrivileges,
    CreateSchema, UpgradeSchema, GrantPrivileges,
    Done
};


class Dispatcher
    : public EventHandler
{
public:
    DbState state;
    Query * q;
    Query * u;
    Query * w;
    Query * ssa;
    Query * ssp;
    Transaction * t;
    bool databaseExists;
    bool namespaceExists;
    bool mailstoreExists;
    bool failed;
    String owner;

    Dispatcher()
        : state( CheckVersion ),
          q( 0 ), u( 0 ), w( 0 ), ssa( 0 ), ssp( 0 ), t( 0 ),
          databaseExists( false ), namespaceExists( false ),
          mailstoreExists( false ), failed( false )
    {}

    void execute()
    {
        database();
    }

    void error( const String &s )
    {
        d->failed = true;
        fprintf( stderr, "%s\n", s.cstr() );
    }

    void nextState()
    {
        d->q = d->u = d->w = 0;
        state = (DbState)(state + 1);
    }
};


void connectToDb( const String & dbname )
{
    Configuration::setup( "" );
    Configuration::add( "db-max-handles = 1" );
    Configuration::add( "db-name = " + dbname.quoted() );
    Configuration::add( "db-schema = " + dbschema->quoted() );
    Configuration::add( "db-user = " + dbuser->quoted() );
    Configuration::add( "db-address = " + db->quoted() );
    if ( !db->startsWith( "/" ) )
        Configuration::add( "db-port = " + fn( dbport ) );

    String pass;
    if ( dbpgpass )
        pass = *dbpgpass;

    Database::setup( 1, PGUSER, pass );
}


void database()
{
    if ( !d ) {
        connectToDb( "template1" );
        d = new Dispatcher;
    }

    DbState last;

    do {
        last = d->state;
        switch ( d->state ) {
        case CheckVersion:
            checkVersion();
            break;

        case CheckEncoding:
            checkEncoding();
            break;

        case CreateUser:
            createUser();
            break;

        case CreateSuperuser:
            createSuperuser();
            break;

        case CreateDatabase:
            createDatabase();
            break;

        case CreateLang:
            createLang();
            break;

        case CreateNamespace:
            createNamespace();
            break;

        case CheckOwnership:
            checkOwnership();
            break;

        case GrantUsage:
            grantUsage();
            break;

        case SplitPrivileges:
            splitPrivileges();
            break;

        case CreateSchema:
            createSchema();
            break;

        case UpgradeSchema:
            upgradeSchema();
            break;

        case GrantPrivileges:
            grantPrivileges();
            break;

        case Done:
            break;
        }

        if ( d->failed ) {
            EventLoop::shutdown();
            return;
        }
    }
    while ( last != d->state && d->state != Done );

    if ( d->state == Done )
        configFile();
}


void checkVersion()
{
    // We could use Postgres::version() instead of issuing a query here,
    // but it's not worth it. We have to check that we can issue queries
    // anyway.

    if ( !d->q ) {
        d->q = new Query( "select version() as version", d );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    Row * r = d->q->nextRow();
    if ( d->q->failed() || !r ) {
        d->error( "Couldn't check Postgres server version. " + pgErr( d->q ) );
        return;
    }

    String v = r->getString( "version" ).simplified().section( " ", 2 );
    if ( v.isEmpty() )
        v = r->getString( "version" );
    bool ok = true;
    uint version = 10000 * v.section( ".", 1 ).number( &ok ) +
                   100 * v.section( ".", 2 ).number( &ok ) +
                   v.section( ".", 3 ).number( &ok );
    if ( !ok || version < 80100 ) {
        d->error( "Archiveopteryx requires PostgreSQL 8.1.0 or higher "
                  "(found only " + v + ")." );
        return;
    }

    d->nextState();
}


void checkEncoding()
{
    if ( !d->q ) {
        d->owner = *dbowner;
        d->q = new Query( "select usename::text, "
                          "pg_encoding_to_char(encoding)::text as encoding "
                          "from pg_database d join pg_user u "
                          "on (d.datdba=u.usesysid) where datname=$1", d );
        d->q->bind( 1, *dbname );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() ) {
        d->error( "Couldn't check encoding for database " +
                  dbname->quoted( '\'' ) + ". " + pgErr( d->q ) );
        return;
    }

    Row * r = d->q->nextRow();
    if ( r ) {
        d->databaseExists = true;

        bool warning = false;
        d->owner = r->getString( "usename" );
        String encoding( r->getString( "encoding" ) );

        if ( encoding != "UNICODE" && encoding != "UTF8" ) {
            // If someone is using SQL_ASCII, it's probably... us.
            if ( encoding == "SQL_ASCII" )
                warning = true;

            fprintf( stderr,
                     " - Database %s exists, but it has encoding "
                     "%s instead of UTF8/UNICODE.\n"
                     "   (That will need to be fixed by hand.)\n",
                     dbname->quoted().cstr(), encoding.cstr() );

            if ( !warning ) {
                d->failed = true;
                return;
            }
        }
    }

    d->nextState();
}


void createUser()
{
    if ( !d->q ) {
        d->q = new Query( "select usename::text from pg_catalog.pg_user "
                          "where usename=$1", d );
        d->q->bind( 1, *dbuser );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->error( "Couldn't check user " + *dbuser + ". " + pgErr( d->q ) );
            return;
        }

        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create user " + *dbuser + " with encrypted "
                           "password " + dbpass->quoted( '\'' ) );

            if ( report ) {
                todo++;
                printf( " - Create a PostgreSQL user named '%s'.\n"
                        "   As user %s, run:\n\n"
                        "%s -d template1 -qc \"%s\"\n\n",
                        dbuser->cstr(), PGUSER, PSQL, create.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Creating the '%s' PostgreSQL user.\n",
                            dbuser->cstr() );
                d->u = new Query( create, d );
                d->u->execute();
            }
        }
        else {
            if ( generatedPass )
                *dbpass = "(database user password here)";
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't create database user " + dbuser->quoted() +
                      " (" + pgErr( d->u ) + ").\nPlease create it by hand "
                      "and re-run the installer." );
            return;
        }
    }

    d->nextState();
}


void createSuperuser()
{
    if ( !d->q ) {
        d->q = new Query( "select usename::text from pg_catalog.pg_user "
                          "where usename=$1", d );
        d->q->bind( 1, *dbowner );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->error( "Couldn't check user " + *dbowner + ". " +
                      pgErr( d->q ) );
            return;
        }

        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create user " + *dbowner + " with encrypted "
                           "password " + dbownerpass->quoted( '\'' ) );

            if ( report ) {
                todo++;
                printf( " - Create a PostgreSQL user named '%s'.\n"
                        "   As user %s, run:\n\n"
                        "%s -d template1 -qc \"%s\"\n\n",
                        dbowner->cstr(), PGUSER, PSQL, create.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Creating the '%s' PostgreSQL user.\n",
                            dbowner->cstr() );
                d->u = new Query( create, d );
                d->u->execute();
            }
        }
        else {
            if ( generatedOwnerPass )
                *dbownerpass = "(database owner password here)";
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't create database user " + dbuser->quoted() +
                      " (" + pgErr( d->u ) + ").\nPlease create it by hand "
                      "and re-run the installer." );
            return;
        }
    }

    d->nextState();
}


// If the database does not exist (the common case), we create it, add
// plpgsql, create a namespace (if one is specified), create database
// objects and grant privileges. If the database DOES exist, we don't
// need to create it, but we check everything else.

void createDatabase()
{
    if ( d->databaseExists ) {
        d->nextState();
        return;
    }

    if ( !d->u ) {
        String create( "create database " + *dbname + " with owner " +
                       *dbowner + " encoding 'UNICODE'" );
        if ( report ) {
            todo++;
            printf( " - Create a database named '%s'.\n"
                    "   As user %s, run:\n\n"
                    "%s -d template1 -qc \"%s\"\n\n",
                    dbname->cstr(), PGUSER, PSQL, create.cstr() );
        }
        else {
            if ( !silent )
                printf( "Creating the '%s' database.\n", dbname->cstr() );
            d->u = new Query( create, d );
            d->u->execute();
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't create database " + dbname->quoted() +
                      "(" + pgErr( d->u ) + ").\nPlease create it by "
                      "hand and re-run the installer." );
            return;
        }
    }

    d->nextState();
}


// We must connect to the database for the next few tests, but we can do
// so only if it existed before, or we just created it. Otherwise we'll
// just report what we would have done and carry on.

void createLang()
{
    if ( !d->databaseExists && report ) {
        todo++;
        printf( " - Add PL/PgSQL to the '%s' database.\n"
                "   As user %s, run:\n\n"
                "createlang plpgsql %s\n\n",
                dbname->cstr(), PGUSER, dbname->cstr() );
        d->nextState();
        return;
    }

    if ( !d->q ) {
        Database::disconnect();
        connectToDb( *dbname );

        d->q = new Query( "select lanname::text from pg_catalog.pg_language "
                          "where lanname='plpgsql'", d );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->error( "Couldn't check for plpgsql. " + pgErr( d->q ) );
            return;
        }

        Row * r = d->q->nextRow();
        if ( !r ) {
            String create( "create language plpgsql" );

            if ( report ) {
                todo++;
                printf( " - Add PL/PgSQL to the '%s' database.\n"
                        "   As user %s, run:\n\n"
                        "createlang plpgsql %s\n\n",
                        dbname->cstr(), PGUSER, dbname->cstr() );
            }
            else {
                if ( !silent )
                    printf( "Adding PL/PgSQL to the '%s' database.\n",
                            dbname->cstr() );
                d->u = new Query( create, d );
                d->u->execute();
            }
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't add PL/PgSQL to the " + dbname->quoted() +
                      "database (" + pgErr( d->u ) + ").\nPlease do it by "
                      "hand and re-run the installer." );
            return;
        }
    }

    d->nextState();
}


// If the user specified a schema with -S, we need to check if it
// exists and create it if it doesn't.
//
// We call our arrangement of database objects a schema (cf. schema.pg),
// but now we're adding support for Postgres schemata; so there's some
// confusion between the two terms here. I try to refer to the latter
// as namespaces in the code, but commands still refer to "schema".

void createNamespace()
{
    if ( !privateSchema ) {
        d->namespaceExists = true;
        d->nextState();
        return;
    }

    String create( "create schema " + *dbschema +
                   " authorization " + *dbowner );

    if ( !d->databaseExists && report ) {
        todo++;
        printf( " - Create a schema named '%s'.\n"
                "   As user %s, run:\n\n"
                "%s -d %s -qc \"%s\"\n\n",
                dbschema->cstr(), PGUSER, PSQL, dbname->cstr(), create.cstr() );
        d->nextState();
        return;
    }

    if ( !d->q ) {
        d->q = new Query( "select nspname::text from pg_catalog.pg_namespace "
                          "where nspname=$1", d );
        d->q->bind( 1, *dbschema );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->error( "Couldn't check schema " + *dbschema + ". " +
                      pgErr( d->q ) );
            return;
        }

        Row * r = d->q->nextRow();
        if ( !r ) {
            if ( report ) {
                todo++;
                printf( " - Create a schema named '%s'.\n"
                        "   As user %s, run:\n\n"
                        "%s -d template1 -qc \"%s\"\n\n",
                        dbschema->cstr(), PGUSER, PSQL, create.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Creating the '%s' schema.\n", dbschema->cstr() );
                d->u = new Query( create, d );
                d->u->execute();
            }
        }
        else {
            d->namespaceExists = true;
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't create schema " + dbschema->quoted() + " "
                      "in database " + dbname->quoted() + "(" +
                      pgErr( d->u ) + ").\nPlease create it by hand and "
                      "re-run the installer." );
            return;
        }
    }

    d->nextState();
}


// Before we create database objects, we check ownership: if a schema
// was specified, the dbowner should be its owner; if not, it should
// own the database we're installing into.

void checkOwnership()
{
    // If we just created either database or schema, the owner is
    // already set correctly, and we don't need to do anything.

    if ( !( d->databaseExists && d->namespaceExists ) ) {
        d->nextState();
        return;
    }

    // If a schema is specified, check its owner and decide what to do.
    // We could do the same for the database if a schema is not given,
    // but checkEncoding() already set d->owner, which we can use.

    if ( !d->q && !d->u ) {
        if ( privateSchema ) {
            d->q = new Query( "select usename::text "
                              "from pg_namespace n join pg_user u on "
                              "(n.nspowner=u.usesysid) where nspname=$1", d );
            d->q->bind( 1, *dbschema );
            d->q->execute();
        }
        else if ( d->owner != *dbowner ) {
            String alter( "alter database " + *dbname +
                          " owner to " + *dbowner );

            if ( report ) {
                todo++;
                printf( " - Alter owner of database '%s' from '%s' to '%s'.\n"
                        "   As user %s, run:\n\n"
                        "%s -d template1 -qc \"%s\"\n\n",
                        dbname->cstr(), d->owner.cstr(), dbowner->cstr(),
                        PGUSER, PSQL, alter.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Altering ownership of database '%s' to '%s'.\n",
                            dbname->cstr(), dbowner->cstr() );
                d->u = new Query( alter, d );
                d->u->execute();
            }
        }
    }

    if ( d->q && !d->u ) {
        if ( !d->q->done() )
            return;

        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r ) {
            d->error( "Couldn't check ownership of schema " + *dbschema + ". " +
                      pgErr( d->q ) );
            return;
        }

        String owner( r->getString( "usename" ) );
        if ( owner != *dbowner ) {
            String alter( "alter schema " + *dbschema +
                          " owner to " + *dbowner );

            if ( report ) {
                todo++;
                printf( " - Alter owner of schema '%s' from '%s' to '%s'.\n"
                        "   As user %s, run:\n\n"
                        "%s -d %s -qc \"%s\"\n\n",
                        dbschema->cstr(), owner.cstr(), dbowner->cstr(),
                        PGUSER, PSQL, dbname->cstr(), alter.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Altering ownership of schema '%s' to '%s'.\n",
                            dbschema->cstr(), dbowner->cstr() );
                d->u = new Query( alter, d );
                d->u->execute();
            }
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            String s( "Couldn't alter owner of " );
            if ( privateSchema )
                s.append( "schema " + dbschema->quoted( '\'' ) );
            else
                s.append( "database " + dbname->quoted( '\'' ) );
            s.append( " to " + dbowner->quoted( '\'' ) );
            s.append( " (" );
            s.append( pgErr( d->u ) );
            s.append( ").\n" );
            d->error( s + "Please set the owner by hand and re-run the "
                      "installer." );
            return;
        }
    }

    d->nextState();
}


void grantUsage()
{
    if ( !privateSchema ) {
        d->nextState();
        return;
    }

    String grant( "grant usage on schema " + *dbschema + " to " + *dbuser );

    if ( !d->q ) {
        d->q = new Query(
            "select has_schema_privilege($1,nspname,'usage') as has_usage "
            "from pg_catalog.pg_namespace where nspname=$2", d
        );
        d->q->bind( 1, *dbuser );
        d->q->bind( 2, *dbschema );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->error( "Couldn't check usage privileges for schema " +
                      dbschema->quoted( '\'' ) + ". " + pgErr( d->q ) );
            return;
        }

        Row * r = d->q->nextRow();
        if ( !r || !r->getBoolean( "has_usage" ) ) {
            if ( report ) {
                todo++;
                printf( " - Grant usage on schema '%s' to user '%s'.\n"
                        "   As user %s, run:\n\n"
                        "%s -d %s -qc \"%s\"\n\n",
                        dbschema->cstr(), dbuser->cstr(), PGUSER, PSQL,
                        dbname->cstr(), grant.cstr() );
            }
            else {
                d->u = new Query( grant, d );
                d->u->execute();
            }
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't grant usage on schema " +
                      dbschema->quoted( '\'' ) + " to user " +
                      dbuser->quoted( '\'' ) + " (" + pgErr( d->u ) +
                      ").\nPlease grant it by hand and re-run the "
                      "installer." );
            return;
        }
    }

    d->nextState();
}


// Archiveopteryx 2.10 introduced the privilege-separation scheme still
// in use, where aoxsuper owns the database objects and has all rights,
// while servers connects as user aox, which has only selected rights.
// In earlier versions, the oryx user owned everything. This function
// is responsible for doing the one-time conversion to the new scheme.

void splitPrivileges()
{
    if ( !( d->databaseExists && d->namespaceExists ) ) {
        d->nextState();
        return;
    }

    if ( !d->q ) {
        d->q = new Query( "select tableowner::text from pg_catalog.pg_tables "
                          "where tablename=$1 and schemaname=$2", d );
        d->q->bind( 1, "messages" );
        d->q->bind( 2, *dbschema );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        if ( d->q->failed() ) {
            d->error( "Couldn't check ownership of messages table. " +
                      pgErr( d->q ) );
            return;
        }

        String owner( *dbowner );
        Row * r = d->q->nextRow();
        if ( r )
            owner = r->getString( "tableowner" );

        // If the messages table is owned by the user that the servers
        // connect as, that's bad. But we have to be careful, because
        // people may have dbuser and dbowner set to the same user.

        if ( owner == *dbuser && *dbuser != *dbowner ) {
            if ( report ) {
                todo++;
                printf( " - Alter the owner of all database objects "
                        "to '%s'.\n\n", dbowner->cstr() );
            }
            else {
                d->q = new Query(
                    "create function exec(text) returns int "
                    "language 'plpgsql' as "
                    "$$begin execute $1;return 0;end;$$", d
                );
                d->q->execute();

                d->u = new Query(
                    "select "
                    "exec('ALTER TABLE '||c.relname||' OWNER TO '||$1) "
                    "from pg_catalog.pg_class c join "
                    "pg_catalog.pg_namespace n on (n.oid=c.relnamespace) "
                    "where n.nspname='public' and c.relkind='r' and "
                    "pg_catalog.pg_table_is_visible(c.oid)", d
                );
                d->u->bind( 1, *dbowner );
                d->u->execute();

                // We have at least one unlinked sequence (bodypart_ids)
                // whose ownership would not have been altered by the
                // query above.

                d->w = new Query(
                    "select "
                    "exec('ALTER TABLE '||c.relname||' OWNER TO '||$1) "
                    "from pg_catalog.pg_class c join "
                    "pg_catalog.pg_namespace n on (n.oid=c.relnamespace) "
                    "where n.nspname='public' and c.relkind='S' and "
                    "pg_catalog.pg_table_is_visible(c.oid)", d
                );
                d->w->bind( 1, *dbowner );
                d->w->execute();

                d->q = new Query( "drop function exec(text)", d );
                d->q->execute();
            }
        }
        else if ( owner != *dbowner ) {
            d->error( "The messages table is not owned by user " +
                      dbuser->quoted( '\'' ) + " or by user " +
                      dbowner->quoted( '\'' ) + ".\n"
                      "This configuration is unsupported. Please contact "
                      "info@oryx.com for help." );
            return;
        }
    }

    if ( d->u ) {
        if ( !d->u->done() || !d->w->done() || !d->q->done() )
            return;

        Query * q = 0;
        if ( d->u->failed() )
            q = d->u;
        else if ( d->w->failed() )
            q = d->w;
        else if ( d->q->failed() )
            q = d->q;

        if ( q ) {
            d->error( "Couldn't alter ownership of objects in the database " +
                      dbname->quoted( '\'' ) + ". " + pgErr( q ) );
            return;
        }
    }

    d->nextState();
}


// At this point, we know that the aox/aoxsuper users exist, that the
// aox database exists, that any given schema exists, that PL/PgSQL is
// available, and that the database/schema have the right ownership.

void createSchema()
{
    // This is what we need to feed to psql to create the schema.

    String cmd( "\\set ON_ERROR_STOP\n"
                "SET SESSION AUTHORIZATION " + *dbowner + ";\n"
                "SET client_min_messages TO 'ERROR';\n" );

    if ( privateSchema )
        cmd.append( "SET search_path TO " +
                    dbschema->quoted( '\'' ) + ";\n" );

    cmd.append( "\\i " LIBDIR "/schema.pg\n"
                "\\i " LIBDIR "/flag-names\n"
                "\\i " LIBDIR "/field-names\n" );

    // And this function decides whether we need to invoke psql at all,
    // based on whether we can find the "mailstore" table.

    if ( report && !( d->databaseExists && d->namespaceExists ) ) {
        todo++;
        printf( " - Load the database schema.\n   "
                "As user %s, run:\n\n"
                "%s %s -f - <<PSQL;\n%sPSQL\n\n",
                PGUSER, PSQL, dbname->cstr(), cmd.cstr() );
        d->nextState();
        return;
    }

    if ( !d->q ) {
        d->ssa = new Query( "set session authorization " + *dbowner, d );
        d->ssa->execute();

        if ( privateSchema ) {
            d->ssp = new Query( "set search_path to " +
                                dbschema->quoted( '\'' ), d );
            d->ssp->execute();
        }

        d->q = new Query( "select tablename::text from pg_catalog.pg_tables "
                          "where tablename=$1 and schemaname=$2", d );
        d->q->bind( 1, "mailstore" );
        d->q->bind( 2, *dbschema );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->ssa->done() || ( d->ssp && !d->ssp->done() ) ||
             !d->q->done() )
            return;

        String s;
        Query * q = 0;

        if ( d->ssa->failed() ) {
            q = d->ssa;
            s.append( "authenticate as user " );
            s.append( dbowner->quoted( '\'' ) );
        }
        else if ( d->ssp && d->ssp->failed() ) {
            q = d->ssp;
            s.append( "set search_path to " );
            s.append( dbschema->quoted( '\'' ) );
        }
        else if ( d->q->failed() ) {
            q = d->q;
            s.append( "query database " );
            s.append( dbname->quoted( '\'' ) );
        }

        if ( q ) {
            if ( report ) {
                todo++;
                printf( " - May need to load the database schema.\n"
                        "   (Couldn't %s to make sure it's needed. %s.)\n\n",
                        s.cstr(), pgErr( q ).cstr() );
            }
            else {
                d->error( "Couldn't " + s + " to see if the schema needs "
                          "to be loaded. " + pgErr( q ) );
            }
            d->state = Done;
            return;
        }

        Row * r = d->q->nextRow();
        if ( !r ) {
            if ( report ) {
                todo++;
                printf( " - Load the database schema.\n   "
                        "As user %s, run:\n\n"
                        "%s %s -f - <<PSQL;\n%sPSQL\n\n",
                        PGUSER, PSQL, dbname->cstr(), cmd.cstr() );
            }
            else {
                if ( !silent )
                    printf( "Loading the database schema.\n" );
                if ( psql( cmd ) < 0 )
                    d->failed = true;
            }
        }
        else {
            d->mailstoreExists = true;
        }
    }

    d->nextState();
}


// If the schema already exists, we might need to upgrade it to the
// latest version.

void upgradeSchema()
{
    if ( !d->mailstoreExists ) {
        d->nextState();
        return;
    }

    if ( !d->q ) {
        d->q = new Query( "select revision from mailstore", d );
        d->q->execute();
    }

    if ( !d->u ) {
        if ( !d->q->done() )
            return;

        // This query may fail even if the pg_class query for mailstore
        // above succeeded, because we (aoxsuper) may not have rights to
        // the schema or the mailstore table.

        Row * r = d->q->nextRow();
        if ( d->q->failed() || !r ) {
            if ( report ) {
                todo++;
                printf( " - May need to upgrade the database schema.\n"
                        "   (Couldn't query mailstore table to make sure "
                        "it's needed.)\n\n" );
            }
            else {
                String s( "Couldn't query database " );
                s.append( dbname->quoted( '\'' ) );
                s.append( " to see if the schema needs to be upgraded." );
                if ( d->q->failed() ) {
                    s.append( " " );
                    s.append( pgErr( d->q ) );
                }
                d->error( s );
            }
            d->state = Done;
            return;
        }

        uint revision = r->getInt( "revision" );

        if ( revision > Database::currentRevision() ) {
            String v( Configuration::compiledIn( Configuration::Version ) );
            fprintf( stderr, "The schema in database '%s' (revision #%d) "
                     "is newer than this version of Archiveopteryx (%s) "
                     "recognises (up to #%d).\n", dbname->cstr(), revision,
                     v.cstr(), Database::currentRevision() );
            d->failed = true;
            return;
        }
        else if ( revision < Database::currentRevision() ) {
            if ( report ) {
                todo++;
                printf( " - Upgrade the database schema.\n   "
                        "(Try \"aox upgrade schema -n\" to see "
                        "what would happen).\n\n" );
            }
            else {
                if ( !silent )
                    printf( "Upgrading the database schema.\n" );
                Schema * s = new Schema( d, true, true );
                d->u = s->result();
                s->execute();
            }
        }
    }

    if ( d->u ) {
        if ( !d->u->done() )
            return;

        if ( d->u->failed() ) {
            d->error( "Couldn't upgrade Archiveopteryx schema in database " +
                      dbname->quoted( '\'' ) + " (" + pgErr( d->u ) + ").\n"
                      "Please run \"aox upgrade schema -n\" by hand.\n" );
            return;
        }
    }

    d->nextState();
}


// Make sure the aox user has exactly those privileges it needs.

void grantPrivileges()
{
    if ( report ) {
        todo++;
        printf( " - Grant privileges to user '%s'.\n   "
                "(Run \"aox grant privileges -n %s\" to see "
                "what would happen).\n\n",
                dbuser->cstr(), dbuser->cstr() );
        d->nextState();
        return;
    }

    if ( !d->t ) {
        if ( !silent )
            printf( "Granting database privileges.\n" );
        d->t = new Transaction( d );
        Granter * s = new Granter( *dbuser, d->t, d );
        d->q = s->result();
        s->execute();
    }

    if ( d->q ) {
        if ( !d->q->done() )
            return;

        d->q = 0;
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        d->error( "Couldn't grant privileges to user " +
                  dbuser->quoted( '\'' ) + " (PostgreSQL error: " +
                  d->t->error() + ").\nPlease run \"aox grant "
                  "privileges -n\" by hand.\n" );
        return;
    }

    d->nextState();
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
    if ( dbaddress->startsWith( "/" ) )
        dbhost.append( "# " );
    dbhost.append( "db-port = " + fn( dbport ) + "\n" );

    String name( "db-name = " + *dbname + "\n" );

    String schema;
    if ( privateSchema ) {
        schema.append( "db-schema = " );
        schema.append( *dbschema );
        schema.append( "\n" );
    }

    String cfg(
        dbhost + name + schema +
        "db-user = " + *dbuser + "\n"
        "db-password = " + p + "\n\n"
        "logfile = " LOGFILE "\n"
        "logfile-mode = " LOGFILEMODE "\n"
    );

    String other(
        "# Uncomment the next line to log more (or set it to debug for even more).\n"
        "# log-level = info\n"
        "\n"
        "# Specify the hostname if Archiveopteryx gets it wrong at runtime.\n"
        "# (We suggest not using the name \"localhost\".)\n"
        "# hostname = fully.qualified.hostname\n"
        "\n"
        "# If soft-bounce is set, configuration problems will not cause mail\n"
        "# loss. Instead, the mail will be queued by the MTA. Uncomment the\n"
        "# following when you are confident that mail delivery works.\n"
        "# soft-bounce = disabled\n"
        "\n"
        "# Change the following to accept LMTP connections on an address\n"
        "# other than the default localhost.\n"
        "# lmtp-address = 192.0.2.1\n"
        "# lmtp-port = 2026\n"
        "\n"
        "# Uncomment the following to support subaddressing: foo+bar@example.org\n"
        "# use-subaddressing = true\n"
        "\n"
        "# Uncomment the following to keep a filesystem copy of all messages\n"
        "# that couldn't be parsed and delivered into the database.\n"
        "# message-copy = errors\n"
        "# message-copy-directory = /usr/local/archiveopteryx/messages\n"
        "\n"
        "# Uncomment the following ONLY if necessary for debugging.\n"
        "# security = off\n"
        "# use-tls = false\n"
        "\n"
        "# Uncomment the next line to use your own TLS certificate.\n"
        "# tls-certificate = /usr/local/archiveopteryx/...\n"
        "\n"
        "# Uncomment the following to reject all plaintext passwords and\n"
        "# require TLS.\n"
        "# allow-plaintext-passwords = never\n"
        "# allow-plaintext-access = never\n"
        "\n"
        "# Uncomment the next line to start the POP3 server.\n"
        "# use-pop = true\n"
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
    String intro(
        "# Archiveopteryx configuration. See aoxsuper.conf(5) "
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
    int n = 0;
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

    n = stat( cf.cstr(), &st );
    if ( n != 0 || !p || !g || st.st_uid != p->pw_uid ||
         (gid_t)st.st_gid != (gid_t)g->gr_gid ||
         ( st.st_mode & 0777 ) != 0600 )
    {
        if ( report ) {
            todo++;
            printf( " - Set permissions and ownership on %s.\n\n"
                    "chmod 0600 %s\n"
                    "chown %s:%s %s\n\n",
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

    n = stat( scf.cstr(), &st );
    if ( n != 0 || st.st_uid != 0 || (gid_t)st.st_gid != (gid_t)0 ||
         ( st.st_mode & 0777 ) != 0400 )
    {
        if ( report ) {
            todo++;
            printf( " - Set permissions and ownership on %s.\n\n"
                    "chmod 0400 %s\n"
                    "chown root:root %s\n\n",
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
            printf( " - Set permissions and ownership on %s.\n\n"
                    "chmod 0700 %s\n"
                    "chown %s:%s %s\n\n",
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
            printf( " - Set permissions and ownership on %s.\n\n"
                    "chmod 0700 %s\n"
                    "chown root:root %s\n\n",
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

    String host( *dbaddress );
    String port( fn( dbport ) );

    if ( dbsocket ) {
        String s( ".s.PGSQL." + port );
        uint l = dbsocket->length() - s.length();
        host = dbsocket->mid( 0, l-1 );
    }

    n = pipe( fd );
    if ( n == 0 )
        pid = fork();
    if ( n == 0 && pid == 0 ) {
        if ( ( postgres != 0 && setreuid( postgres, postgres ) < 0 ) ||
             dup2( fd[0], 0 ) < 0 ||
             close( fd[1] ) < 0 ||
             close( fd[0] ) < 0 )
            exit( -1 );
        if ( silent )
            if ( close( 1 ) < 0 || open( "/dev/null", 0 ) != 1 )
                exit( -1 );
        execlp( PSQL, PSQL, "-h", host.cstr(), "-p", port.cstr(),
                "-U", PGUSER, dbname->cstr(), "-f", "-",
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
                     "%s -h %s -p %s %s -f - <<PSQL;\n%sPSQL\n\n",
                     PGUSER, PSQL, host.cstr(), port.cstr(),
                     dbname->cstr(), cmd.cstr() );
            return -1;
        }
    }

    return 0;
}
