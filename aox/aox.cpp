// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "cache.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "configuration.h"
#include "stderrlogger.h"
#include "addresscache.h"
#include "transaction.h"
#include "fieldcache.h"
#include "eventloop.h"
#include "injector.h"
#include "database.h"
#include "occlient.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "schema.h"
#include "logger.h"
#include "query.h"
#include "dict.h"
#include "file.h"
#include "list.h"
#include "user.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>


char * aox;
StringList * args;
int options[256];
int status;
class LwAddressCache;
class HeaderFieldRow;
class Dispatcher * d;

static PreparedStatement * fetchValues;
static PreparedStatement * fetchAddresses;
static PreparedStatement * updateAddressField;
static PreparedStatement * insertAddressField;
static PreparedStatement * deleteHeaderFields;

char * servers[] = {
    "logd", "ocd", "tlsproxy", "archiveopteryx"
};
const int nservers = sizeof( servers ) / sizeof( servers[0] );


char * buildinfo[] = {
#include "buildinfo.inc"
    ""
};


String next();
int opt( char );
void bad( const String &, const String &, const String & = "" );
void error( String );
void parseOptions();
void end();

void start();
void stop();
void restart();
void showStatus();
void showBuildconf();
void showConfiguration();
void showSchema();
void showCounts();
void upgradeSchema();
void updateDatabase();
void listMailboxes();
void listUsers();
void listAliases();
void createUser();
void deleteUser();
void createMailbox();
void deleteMailbox();
void changePassword();
void changeUsername();
void changeAddress();
void createAlias();
void deleteAlias();
void vacuum();
void anonymise( const String & );
void help();
void checkFilePermissions();
void checkConfigConsistency();
void reparse();


/*! \nodoc */


int main( int ac, char *av[] )
{
    Scope global;

    args = new StringList;
    aox = *av++;
    ac--;

    uint verbosity = 0;
    int i = 0;
    while ( i < ac ) {
        if ( String( av[i] ) == "-v" )
            verbosity++;
        else if ( String( av[i] ) == "-q" )
            verbosity = 0;
        else
            args->append( new String( av[i] ) );
        i++;
    }
    if ( verbosity )
        options[(int)'v'] = true;

    EventLoop::setup();

    Configuration::setup( "archiveopteryx.conf" );
    Configuration::read( String( "" ) +
                         Configuration::compiledIn( Configuration::ConfigDir) +
                         "/aoxsuper.conf", true );
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "log object" );
    global.setLog( l );
    Allocator::addEternal( new StderrLogger( "aox", verbosity ),
                           "log object" );

    Configuration::report();

    if ( Scope::current()->log()->disastersYet() )
        exit( -1 );

    String verb = next().lower();

    if ( verb == "add" || verb == "new" )
        verb = "create";
    else if ( verb == "del" || verb == "remove" )
        verb = "delete";

    if ( verb == "start" ) {
        start();
    }
    else if ( verb == "stop" ) {
        stop();
    }
    else if ( verb == "restart" ) {
        restart();
    }
    else if ( verb == "show" ) {
        String noun = next().lower();
        if ( noun == "status" )
            showStatus();
        else if ( noun == "build" )
            showBuildconf();
        else if ( noun == "cf" || noun == "configuration" )
            showConfiguration();
        else if ( noun == "schema" )
            showSchema();
        else if ( noun == "counts" )
            showCounts();
        else
            bad( verb, noun, "status, build, cf, schema, counts" );
    }
    else if ( verb == "upgrade" ) {
        String noun = next().lower();
        if ( noun == "schema" )
            upgradeSchema();
        else
            bad( verb, noun, "schema" );
    }
    else if ( verb == "update" ) {
        String noun = next().lower();
        if ( noun == "database" )
            updateDatabase();
        else
            bad( verb, noun, "database" );
    }
    else if ( verb == "list" || verb == "ls" ) {
        String noun = next().lower();
        if ( noun == "users" )
            listUsers();
        else if ( noun == "mailboxes" )
            listMailboxes();
        else if ( noun == "aliases" )
            listAliases();
        else
            bad( verb, noun, "users, mailboxes, aliases" );
    }
    else if ( verb == "create" || verb == "delete" ) {
        String noun = next().lower();

        Database::setup( 1, Configuration::DbOwner );

        if ( verb == "create" && noun == "user" )
            createUser();
        else if ( verb == "delete" && noun == "user" )
            deleteUser();
        else if ( verb == "create" && noun == "mailbox" )
            createMailbox();
        else if ( verb == "delete" && noun == "mailbox" )
            deleteMailbox();
        else if ( verb == "create" && noun == "alias" )
            createAlias();
        else if ( verb == "delete" && noun == "alias" )
            deleteAlias();
        else
            bad( verb, noun, "user, mailbox, alias" );
    }
    else if ( verb == "change" ) {
        String noun = next().lower();
        if ( noun == "password" )
            changePassword();
        else if ( noun == "username" )
            changeUsername();
        else if ( noun == "address" )
            changeAddress();
        else
            bad( verb, noun, "password, username, address" );
    }
    else if ( verb == "vacuum" ) {
        vacuum();
    }
    else if ( verb == "anonymise" ) {
        anonymise( next() );
    }
    else if ( verb == "check" ) {
        checkConfigConsistency();
    }
    else if ( verb == "reparse" ) {
        reparse();
    }
    else {
        if ( verb != "help" )
            args->prepend( new String( verb ) );
        help();
    }

    if ( d ) {
        EventLoop::global()->start();
    }
    return status;
}


String next()
{
    if ( args->isEmpty() )
        return "";
    return *args->shift();
}


int opt( char c )
{
    return options[(int)c];
}


void bad( const String &verb, const String &noun, const String &ok )
{
    if ( noun.isEmpty() )
        fprintf( stderr, "aox %s: No argument supplied.\n",
                 verb.cstr() );
    else if ( !ok.isEmpty() )
        fprintf( stderr, "aox %s: Unknown argument: %s (try %s).\n",
                 verb.cstr(), noun.cstr(), ok.cstr() );
    else
        fprintf( stderr, "aox %s: Unknown argument: %s.\n",
                 verb.cstr(), noun.cstr() );
    exit( -1 );
}


void error( String m )
{
    fprintf( stderr, "aox: %s\n", m.cstr() );
    exit( -1 );
}


void parseOptions()
{
    StringList::Iterator it( args );
    while ( it ) {
        String s = *it;
        if ( s[0] != '-' )
            break;
        if ( s.length() == 2 &&
             ( ( s[1] >= '0' && s[1] <= '9' ) ||
               ( s[1] >= 'A' && s[1] <= 'Z' ) ||
               ( s[1] >= 'a' && s[1] <= 'z' ) ) )
            options[(int)s[1]]++;
        else
            error( "Bad option name: '" + s + "'" );
        args->take( it );
    }
}


void end()
{
    if ( args->isEmpty() )
        return;
    error( "Unexpected argument: " + next() );
}


struct Id
    : public Garbage
{
    Id( uint n, String s )
        : id( n ), name( s )
    {}

    uint id;
    String name;
};


struct AddressMap
    : public Garbage
{
    AddressMap() : bad( 0 ), good( 0 ) {}

    Address * bad;
    Address * good;
};


class Dispatcher
    : public EventHandler
{
public:
    enum Command {
        Start, ShowCounts, ShowSchema, UpgradeSchema, UpdateDatabase,
        ListMailboxes, ListUsers, ListAliases, CreateUser, DeleteUser,
        ChangePassword, ChangeUsername, ChangeAddress, CreateMailbox,
        DeleteMailbox, CreateAlias, DeleteAlias, Vacuum,
        CheckConfigConsistency, Reparse
    };

    List< Query > * chores;
    Command command;
    Query * query;
    User * user;
    uint conversions;
    Transaction * t;
    Address * address;
    Mailbox * m;
    String s;
    Schema * schema;
    int state;
    List< Id > * ids;
    LwAddressCache * addressCache;
    Dict<AddressParser> * parsers;
    List<Address> * unknownAddresses;
    List<HeaderFieldRow> * headerFieldRows;
    CacheLookup * cacheLookup;
    Dict<void> * uniq;
    List<AddressMap> * addressMap;
    Injector * injector;
    Row * row;

    Dispatcher( Command cmd )
        : chores( new List< Query > ),
          command( cmd ), query( 0 ),
          user( 0 ), conversions( 0 ), t( 0 ), address( 0 ), m( 0 ),
          schema( 0 ), state( 0 ), ids( 0 ), addressCache( 0 ),
          parsers( 0 ), unknownAddresses( 0 ), headerFieldRows( 0 ),
          cacheLookup( 0 ), uniq( new Dict<void>( 1000 ) ),
          addressMap( new List<AddressMap> ), injector( 0 ),
          row( 0 )
    {
        Allocator::addEternal( this, "an aox dispatcher" );
    }

    void waitFor( Query * q )
    {
        chores->append( q );
    }

    void execute()
    {
        static bool failures = false;

        if ( !chores->isEmpty() ) {
            List< Query >::Iterator it( chores );
            while ( it ) {
                Query * q = it;

                if ( q->done() ) {
                    if ( q->failed() )
                        failures = true;
                    chores->take( it );
                }
                else {
                    ++it;
                }
            }

            if ( failures || Scope::current()->log()->disastersYet() ) {
                EventLoop::shutdown();
                exit( -1 );
            }

            if ( !chores->isEmpty() )
                return;
        }

        switch ( command ) {
        case Start:
            start();
            break;

        case ShowCounts:
            showCounts();
            break;

        case ShowSchema:
            showSchema();
            break;

        case UpgradeSchema:
            upgradeSchema();
            break;

        case UpdateDatabase:
            updateDatabase();
            break;

        case ListMailboxes:
            listMailboxes();
            break;

        case ListUsers:
            listUsers();
            break;

        case ListAliases:
            listAliases();
            break;

        case CreateUser:
            createUser();
            break;

        case DeleteUser:
            deleteUser();
            break;

        case ChangePassword:
            changePassword();
            break;

        case ChangeUsername:
            changeUsername();
            break;

        case ChangeAddress:
            changeAddress();
            break;

        case CreateMailbox:
            createMailbox();
            break;

        case DeleteMailbox:
            deleteMailbox();
            break;

        case CreateAlias:
            createAlias();
            break;

        case DeleteAlias:
            deleteAlias();
            break;

        case Vacuum:
            vacuum();
            break;

        case CheckConfigConsistency:
            checkConfigConsistency();
            break;

        case Reparse:
            reparse();
            break;
        }

        if ( ( query && !query->done() ) || ( t && !t->done() ) ||
             ( d->user && d->user->state() == User::Unverified ) )
            return;

        if ( query && query->failed() ) {
            if ( !Scope::current()->log()->disastersYet() )
                error( "Error: " + query->error() );
            status = -1;
        }

        EventLoop::shutdown();
    }
};


String pidFile( const char * s )
{
    String pf( Configuration::compiledIn( Configuration::PidFileDir ) );
    pf.append( "/" );
    pf.append( s );
    pf.append( ".pid" );
    return pf;
}


int serverPid( const char * s )
{
    String pf = pidFile( s );
    File f( pf, File::Read );
    if ( !f.valid() )
        return -1;

    bool ok;
    int pid = f.contents().stripCRLF().number( &ok );
    if ( !ok ) {
        fprintf( stderr, "aox: Bad pid file: %s\n", pf.cstr() );
        return -1;
    }

    return pid;
}


bool startServer( const char * s )
{
    String srv( Configuration::compiledIn( Configuration::SbinDir ) );
    srv.append( "/" );
    srv.append( s );

    bool use = true;

    String t( s );
    if ( t == "tlsproxy" )
        use = Configuration::toggle( Configuration::UseTls );
    else if ( t == "imapd" )
        use = Configuration::toggle( Configuration::UseImap ) ||
              Configuration::toggle( Configuration::UseImaps );
    else if ( t == "smtpd" )
        use = Configuration::toggle( Configuration::UseSmtp ) ||
              Configuration::toggle( Configuration::UseLmtp );
    else if ( t == "httpd" )
        use = Configuration::toggle( Configuration::UseHttp );
    else if ( t == "pop3d" )
        use = Configuration::toggle( Configuration::UsePop );

    if ( !use ) {
        if ( opt( 'v' ) > 0 )
            printf( "Don't need to start %s\n", srv.cstr() );
        return false;
    }

    int p = serverPid( s );
    if ( p != -1 ) {
        if ( kill( p, 0 ) != 0 && errno == ESRCH ) {
            File::unlink( pidFile( s ) );
        }
        else {
            if ( opt( 'v' ) > 0 )
                printf( "%s(%d) is already running\n", s, p );
            return false;
        }
    }

    if ( opt( 'v' ) > 0 )
        printf( "Starting %s\n", srv.cstr() );

    pid_t pid = fork();
    if ( pid < 0 ) {
        error( "Couldn't fork to exec(" + srv + ")" );
    }
    else if ( pid == 0 ) {
        execl( srv.cstr(), srv.cstr(), "-f", NULL );
        exit( -1 );
    }
    else {
        int status = 0;
        if ( waitpid( pid, &status, 0 ) < 0 ||
             WIFEXITED( status ) && WEXITSTATUS( status ) != 0 )
            error( "Couldn't exec(" + srv + ")" );
    }

    return true;
}


void start()
{
    if ( !d ) {
        parseOptions();
        checkFilePermissions();
        end();

        String sbin( Configuration::compiledIn( Configuration::SbinDir ) );
        if ( chdir( sbin.cstr() ) < 0 )
            error( "Couldn't chdir to SBINDIR (" + sbin + ")" );

        Database::setup( 1 );

        d = new Dispatcher( Dispatcher::Start );
        d->query = new Query( "select 42 as test", d );
        d->query->execute();
    }

    if ( d && !d->query->done() )
        return;

    Row * r = d->query->nextRow();
    if ( d->query->failed() || !r || r->getInt( "test" ) != 42 )
        error( "Couldn't execute a simple Postgres query: " +
               d->query->error() );

    int i = 0;
    bool started = false;
    while ( i < nservers )
        if ( startServer( servers[i++] ) )
            started = true;

    if ( !started )
        printf( "No processes need to be started.\n" );
}


void stop()
{
    parseOptions();
    end();

    if ( opt( 'v' ) > 0 )
        printf( "Stopping servers: " );

    int i = 0;
    int n = 0;
    int pids[nservers];
    while ( i < nservers ) {
        pids[i] = serverPid( servers[nservers-i-1] );
        if ( opt( 'v' ) > 0 && pids[i] != -1 )
            printf( "%s%s", servers[nservers-i-1],
                    i == nservers-1 ? "" : " " );
        i++;
    }

    if ( opt( 'v' ) > 0 )
        printf( ".\n" );

    i = 0;
    while ( i < nservers ) {
        if ( pids[i] != -1 ) {
            if ( opt( 'v' ) > 1 )
                printf( "Sending SIGTERM to %d\n", pids[i] );
            File::unlink( pidFile( servers[nservers-i-1] ) );
            kill( pids[i], SIGTERM );
            n++;
        }
        i++;
    }

    if ( n > 0 ) {
        sleep( 1 );

        i = 0;
        while ( i < nservers ) {
            if ( pids[i] != -1 && kill( pids[i], 0 ) == 0 ) {
                if ( opt( 'v' ) > 1 )
                    printf( "Sending SIGKILL to %d\n", pids[i] );
                kill( pids[i], SIGKILL );
            }
            i++;
        }
    }
}


void restart()
{
    parseOptions();
    checkFilePermissions();
    end();

    stop();
    sleep( 1 );
    start();
}


void showStatus()
{
    parseOptions();
    checkFilePermissions();
    end();

    printf( "Servers: " );
    if ( opt( 'v' ) > 0 )
        printf( "\n  " );

    int i = 0;
    while ( i < nservers ) {
        int pid = serverPid( servers[i] );
        printf( "%s", servers[i] );

        bool started = false;
        String t( servers[i] );
        if ( t == "tlsproxy" )
            started = Configuration::toggle( Configuration::UseTls );
        else if ( t == "imapd" )
            started = Configuration::toggle( Configuration::UseImap ) ||
                      Configuration::toggle( Configuration::UseImaps );
        else if ( t == "smtpd" )
            started = Configuration::toggle( Configuration::UseSmtp ) ||
                      Configuration::toggle( Configuration::UseLmtp );
        else if ( t == "httpd" )
            started = Configuration::toggle( Configuration::UseHttp );
        else if ( t == "pop3d" )
            started = Configuration::toggle( Configuration::UsePop );

        const char * noState = started ? "not running" : "not started";

        if ( pid < 0 )
            printf( " (%s)", noState );
        else if ( kill( pid, 0 ) != 0 && errno == ESRCH )
            if ( opt( 'v' ) > 0 )
                printf( " (%s, stale pidfile)", noState );
            else
                printf( " (%s)", noState );
        else if ( opt( 'v' ) > 0 )
            printf( " (%d)", pid );

        if ( i != nservers-1 )
            if ( opt( 'v' ) > 0 )
                printf( "\n  " );
            else
                printf( ", " );
        i++;
    }

    if ( opt( 'v' ) == 0 )
        printf( "." );
    printf( "\n" );
}


void showBuildconf()
{
    end();

    printf( "Archiveopteryx version %s, "
            "http://www.archiveopteryx.org/%s.html\n",
            Configuration::compiledIn( Configuration::Version ),
            Configuration::compiledIn( Configuration::Version ) );

    printf( "Built on " __DATE__ " " __TIME__ "\n" );

    int i = 0;
    while ( buildinfo[i] && *buildinfo[i] )
        printf( "%s\n", buildinfo[i++] );

    printf( "Jamsettings:\n" );
    printf( "CONFIGDIR = %s\n",
            Configuration::compiledIn( Configuration::ConfigDir ) );
    printf( "PIDFILEDIR = %s\n",
            Configuration::compiledIn( Configuration::PidFileDir ) );
    printf( "BINDIR = %s\n",
            Configuration::compiledIn( Configuration::BinDir ) );
    printf( "MANDIR = %s\n",
            Configuration::compiledIn( Configuration::ManDir ) );
    printf( "LIBDIR = %s\n",
            Configuration::compiledIn( Configuration::LibDir ) );
    printf( "INITDIR = %s\n",
            Configuration::compiledIn( Configuration::InitDir ) );
    printf( "AOXUSER = %s\n",
            Configuration::compiledIn( Configuration::OryxUser ) );
    printf( "AOXGROUP = %s\n",
            Configuration::compiledIn( Configuration::OryxGroup ) );
    printf( "VERSION = %s\n",
            Configuration::compiledIn( Configuration::Version ) );
}


void addVariable( SortedList< String > * l, String n, String v,
                  String pat, bool p )
{
    int np = opt( 'p' );
    int nv = opt( 'v' );

    if ( ( pat.isEmpty() || n == pat ) &&
         ( np == 0 || p ) )
    {
        String * s = new String;

        if ( nv == 0 ) {
            s->append( n );
            s->append( " = " );
        }
        s->append( v );
        l->insert( s );
    }
}


void showConfiguration()
{
    SortedList<String> output;

    parseOptions();
    String pat = next();
    end();

    uint i = 0;
    while ( i < Configuration::NumScalars ) {
        Configuration::Scalar j = (Configuration::Scalar)i++;

        String n( Configuration::name( j ) );
        String v( fn( Configuration::scalar( j ) ) );
        addVariable( &output, n, v, pat, Configuration::present( j ) );
    }

    i = 0;
    while ( i < Configuration::NumToggles ) {
        Configuration::Toggle j = (Configuration::Toggle)i++;

        String n( Configuration::name( j ) );
        String v( Configuration::toggle( j ) ? "on" : "off" );
        addVariable( &output, n, v, pat, Configuration::present( j ) );
    }

    i = 0;
    while ( i < Configuration::NumTexts ) {
        Configuration::Text j = (Configuration::Text)i++;

        String n( Configuration::name( j ) );
        String v( Configuration::text( j ) );
        if ( j != Configuration::DbPassword &&
             j != Configuration::DbOwnerPassword ) {
            if ( v.isEmpty() )
                v = "\"\"";
            addVariable( &output, n, v, pat, Configuration::present( j ) );
        }
    }

    StringList::Iterator it( output );
    while ( it ) {
        printf( "%s\n", it->cstr() );
        ++it;
    }
}


void showCounts()
{
    if ( !d ) {
        parseOptions();
        end();

        Database::setup( 1 );

        d = new Dispatcher( Dispatcher::ShowCounts );
        d->state = 1;
        d->query =
            new Query( "select "
                       "(select count(*) from users)::int as users,"
                       "(select count(*) from mailboxes where"
                       " deleted='f')::int as mailboxes,"
                       "(select reltuples from pg_class where"
                       " relname='messages')::int as messages,"
                       "(select reltuples from pg_class where"
                       " relname='deleted_messages')::int as dm,"
                       "(select reltuples from pg_class where"
                       " relname='bodyparts')::int as bodyparts,"
                       "(select reltuples from pg_class where"
                       " relname='addresses')::int as addresses", d );
        d->query->execute();
    }

    if ( d->state == 1 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch estimates." );

        printf( "Users: %d\n", r->getInt( "users" ) );
        printf( "Mailboxes: %d\n", r->getInt( "mailboxes" ) );

        if ( opt( 'f' ) == 0 ) {
            printf( "Messages: %d", r->getInt( "messages" ) );
            if ( r->getInt( "dm" ) != 0 )
                printf( " (%d marked for deletion)", r->getInt( "dm" ) );
            printf( " (estimated)\n" );
            printf( "Bodyparts: %d (estimated)\n",
                    r->getInt( "bodyparts" ) );
            printf( "Addresses: %d (estimated)\n",
                    r->getInt( "addresses" ) );
            d->state = 666;
            return;
        }

        d->query =
            new Query( "select count(*)::int as messages, "
                       "sum(rfc822size)::bigint as totalsize, "
                       "(select count(*) from deleted_messages)::int "
                       "as dm from messages", d );
        d->query->execute();
        d->state = 2;
    }

    if ( d->state == 2 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch messages/deleted_messages counts." );

        int m = r->getInt( "messages" );
        int dm = r->getInt( "dm" );

        printf( "Messages: %d", m-dm );
        if ( dm != 0 )
            printf( " (%d marked for deletion)", dm );
        printf( " (total size: %s)\n",
                String::humanNumber( r->getBigint( "totalsize" ) ).cstr() );

        d->query =
            new Query( "select count(*)::int as bodyparts,"
                       "sum(length(text))::bigint as textsize,"
                       "sum(length(data))::bigint as datasize "
                       "from bodyparts", d );
        d->query->execute();
        d->state = 3;
    }

    if ( d->state == 3 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch bodyparts counts." );

        printf( "Bodyparts: %d (text size: %s, data size: %s)\n",
                r->getInt( "bodyparts" ),
                String::humanNumber( r->getBigint( "textsize" ) ).cstr(),
                String::humanNumber( r->getBigint( "datasize" ) ).cstr() );

        d->query =
            new Query( "select count(*)::int as addresses "
                       "from addresses", d );
        d->query->execute();
        d->state = 4;
    }

    if ( d->state == 4 ) {
        if ( !d->query->done() )
            return;

        Row * r = d->query->nextRow();
        if ( d->query->failed() || !r )
            error( "Couldn't fetch addresses counts." );

        printf( "Addresses: %d\n", r->getInt( "addresses" ) );
        d->state = 666;
    }
}


void showSchema()
{
    const char * versions[] = {
        "", "", "0.91", "0.92", "0.92", "0.92 to 0.93", "0.93",
        "0.93", "0.94 to 0.95", "0.96 to 0.97", "0.97", "0.97",
        "0.98", "0.99", "1.0", "1.01", "1.05", "1.05", "1.06",
        "1.07", "1.08", "1.09", "1.10", "1.10", "1.11", "1.11",
        "1.11", "1.11", "1.12", "1.12", "1.12", "1.12", "1.13",
        "1.13", "1.15", "1.15", "1.16", "1.16", "1.16", "1.17",
        "1.17", "1.17"
    };
    int nv = sizeof( versions ) / sizeof( versions[0] );

    if ( !d ) {
        end();

        Database::setup( 1 );

        d = new Dispatcher( Dispatcher::ShowSchema );
        d->query = new Query( "select revision from mailstore", d );
        d->query->execute();
    }

    if ( d && !d->query->done() )
        return;

    Row * r = d->query->nextRow();
    if ( r ) {
        int rev = r->getInt( "revision" );

        String s;
        if ( rev >= nv ) {
            s = "too new for ";
            s.append( Configuration::compiledIn( Configuration::Version ) );
        }
        else {
            s = versions[rev];
            if ( rev == nv-1 )
                s.append( " - latest known version" );
        }

        if ( !s.isEmpty() )
            s = " (" + s + ")";
        printf( "%d%s\n", rev, s.cstr() );
    }
}


void upgradeSchema()
{
    if ( !d ) {
        parseOptions();
        end();

        Database::setup( 1, Configuration::DbOwner );

        bool commit = true;
        if ( opt( 'n' ) > 0 )
            commit = false;

        d = new Dispatcher( Dispatcher::UpgradeSchema );
        d->schema = new Schema( d, true, commit );
        d->query = d->schema->result();
        d->schema->execute();
    }

    if ( !d->query->done() )
        return;

    String v( d->schema->serverVersion() );
    if ( v.startsWith( "7" ) || v.startsWith( "8.0" ) )
        fprintf( stderr,
                 "Note: Starting May, 2007, "
                 "Archiveopteryx will require PostgreSQL 8.1.0 or\nhigher. "
                 "Please upgrade the running server (%s) at your "
                 "convenience.\n", v.cstr() );
}


class HeaderFieldRow
    : public Garbage
{
public:
    HeaderFieldRow()
        : mailbox( 0 ), uid( 0 ), position( 0 ), field( 0 )
    {}

    uint mailbox;
    uint uid;
    String part;
    uint position;
    uint field;
    String value;
};


class LwAddressCache
    : public EventHandler
{
public:
    Query * q;
    Dict<uint> * names;
    EventHandler * owner;

    LwAddressCache( EventHandler * ev )
        : q( 0 ), names( new Dict<uint>( 16384 ) ), owner( ev )
    {}

    void execute()
    {
        while ( q->hasResults() ) {
            Row * r = q->nextRow();

            uint * id = (uint *)Allocator::alloc( sizeof(uint), 0 );
            *id = r->getInt( "id" );
            Address * a =
                new Address( r->getString( "name" ),
                             r->getString( "localpart" ),
                             r->getString( "domain" ) );

            names->insert( a->toString(), id );
        }

        if ( q->done() ) {
            printf( "  Loaded %d addresses into cache.\n", q->rows() );
            owner->execute();
        }
    }

    uint lookup( const Address * a )
    {
        uint * id = names->find( a->toString() );
        if ( id )
            return *id;
        return 0;
    }
};


bool convertField( uint mailbox, uint uid, const String &part,
                   uint position, uint field, const String & value )
{
    Query * q;
    AddressParser * p;
    p = d->parsers->find( value );
    if ( !p ) {
        p = new AddressParser( value );
        d->parsers->insert( value, p );
    }

    bool unknown = false;
    List<Address>::Iterator it( p->addresses() );
    while ( it ) {
        Address * a = it;
        uint address = d->addressCache->lookup( a );
        if ( address == 0 ) {
            if ( !d->uniq->contains( a->toString() ) ) {
                d->unknownAddresses->append( a );
                d->uniq->insert( a->toString(), (void *)1 );
            }
            unknown = true;
        }
        a->setId( address );
        ++it;
    }

    if ( unknown )
        return false;

    uint number = 0;
    it = p->addresses();
    while ( it ) {
        Address * a = it;

        if ( part.isEmpty() )
            q = new Query( *updateAddressField, d );
        else
            q = new Query( *insertAddressField, d );

        q->bind( 1, mailbox );
        q->bind( 2, uid );
        q->bind( 3, part );
        q->bind( 4, position );
        q->bind( 5, field );
        q->bind( 6, a->id() );
        q->bind( 7, number );

        d->t->enqueue( q );

        number++;
        ++it;
    }

    d->conversions++;
    return true;
}


void updateDatabase()
{
    if ( !d ) {
        end();

        fetchValues =
            new PreparedStatement(
                "select uid,part,position,field,value from header_fields "
                "where mailbox=$1 and ((part<>'' and field<=12) or "
                "(mailbox,uid,part,position,field) in "
                "(select mailbox,uid,part,position,field from address_fields"
                " where mailbox=$1 group by mailbox,uid,part,position,field"
                " having count(*)<>count(number)))"
            );
        Allocator::addEternal( fetchValues, "fetchValues" );

        fetchAddresses =
            new PreparedStatement(
                "select id,name,localpart,domain from address_fields af "
                "join addresses a on (af.address=a.id) where mailbox=$1 "
                "and uid in (select uid from address_fields where "
                "mailbox=$1 group by uid having count(*)<>count(number))"
            );
        Allocator::addEternal( fetchAddresses, "fetchAddresses" );

        updateAddressField =
            new PreparedStatement(
                "update address_fields set number=$7 where mailbox=$1 and "
                "uid=$2 and part=$3 and position=$4 and field=$5 and "
                "address=$6"
            );
        Allocator::addEternal( updateAddressField, "updateAddressField" );

        insertAddressField =
            new PreparedStatement(
                "insert into address_fields "
                "(mailbox,uid,part,position,field,address,number) values "
                "($1,$2,$3,$4,$5,$6,$7)"
            );
        Allocator::addEternal( insertAddressField, "insertAddressField" );

        deleteHeaderFields =
            new PreparedStatement(
                "delete from header_fields where mailbox=$1 and field<=12 "
                "and uid not in (select uid from address_fields where "
                "mailbox=$1 group by uid having count(*)<>count(number))"
            );
        Allocator::addEternal( deleteHeaderFields, "deleteHeaderFields" );

        AddressCache::setup();
        Database::setup( 1, Configuration::DbOwner );
        d = new Dispatcher( Dispatcher::UpdateDatabase );
        d->state = 0;
    }

    while ( d->state != 670 ) {
        if ( d->state == 0 ) {
            printf( "- Checking for unconverted address fields in "
                    "header_fields.\n" );
            d->state = 1;
            d->query =
                new Query( "select id,name from mailboxes where id in "
                           "(select distinct mailbox from address_fields"
                           " where number is null) order by name", d );
            d->query->execute();
        }

        if ( d->state == 1 ) {
            if ( !d->query->done() )
                return;

            d->ids = new List<Id>;

            Row * r;
            while ( ( r = d->query->nextRow() ) != 0 ) {
                Id * id = new Id( r->getInt( "id" ),
                                  r->getString( "name" ) );
                d->ids->append( id );
            }

            uint n = d->ids->count();
            if ( n == 0 ) {
                d->state = 666;
            }
            else {
                printf( "  %d mailboxes to process:\n", n );
                d->state = 2;
            }
        }

        if ( d->state <= 7 && d->state >= 2 ) {
            List<Id>::Iterator it( d->ids );
            while ( it ) {
                Id * m = it;

                if ( d->state == 2 ) {
                    printf( "- Processing %s\n", m->name.cstr() );
                    d->state = 3;
                    d->t = new Transaction( d );
                    d->parsers = new Dict<AddressParser>( 1000 );
                    d->unknownAddresses = new List<Address>;
                    d->headerFieldRows = new List<HeaderFieldRow>;
                    d->addressCache = new LwAddressCache( d );
                    d->query = new Query( *fetchAddresses, d->addressCache );
                    d->addressCache->q = d->query;
                    d->query->bind( 1, m->id );
                    d->query->execute();
                }

                if ( d->state == 3 ) {
                    if ( !d->query->done() )
                        return;

                    d->state = 4;
                    d->query = new Query( *fetchValues, d );
                    d->query->bind( 1, m->id );
                    d->query->execute();
                }

                if ( d->state == 4 ) {
                    uint updates = 0;

                    while ( d->query->hasResults() ) {
                        Row * r = d->query->nextRow();

                        uint mailbox( m->id );
                        uint uid( r->getInt( "uid" ) );
                        String part( r->getString( "part" ) );
                        uint position = r->getInt( "position" );
                        uint field( r->getInt( "field" ) );
                        String value( r->getString( "value" ) );

                        bool p = convertField( mailbox, uid, part, position,
                                               field, value );
                        if ( p ) {
                            updates++;
                        }
                        else {
                            HeaderFieldRow * hf = new HeaderFieldRow;
                            hf->mailbox = mailbox;
                            hf->uid = uid;
                            hf->part = part;
                            hf->position = position;
                            hf->field = field;
                            hf->value = value;
                            d->headerFieldRows->append( hf );
                        }
                    }

                    if ( updates )
                        d->t->execute();

                    if ( !d->query->done() )
                        return;

                    if ( d->unknownAddresses->isEmpty() ) {
                        d->state = 6;
                    }
                    else {
                        d->state = 5;
                        if ( d->conversions )
                            printf( "  Converted %d address fields.\n",
                                    d->conversions );
                        d->conversions = 0;
                        if ( !d->unknownAddresses->isEmpty() )
                            printf( "  Looking up %d more addresses.\n",
                                    d->unknownAddresses->count() );
                        d->cacheLookup =
                            AddressCache::lookup( d->t, d->unknownAddresses,
                                                  d );
                    }
                }

                if ( d->state == 5 ) {
                    if ( !d->cacheLookup->done() )
                        return;

                    List<Address>::Iterator ad( d->unknownAddresses );
                    while ( ad ) {
                        Address * a = ad;
                        uint * n = (uint *)Allocator::alloc( sizeof(uint), 0 );
                        *n = a->id();
                        d->addressCache->names->insert( a->toString(), n );
                        ++ad;
                    }

                    List<HeaderFieldRow>::Iterator it( d->headerFieldRows );
                    while ( it ) {
                        bool p;
                        HeaderFieldRow * hf = it;
                        p = convertField( hf->mailbox, hf->uid, hf->part,
                                          hf->position, hf->field, hf->value );
                        if ( p )
                            d->headerFieldRows->take( it );
                        else
                            ++it;
                    }

                    if ( d->conversions )
                        printf( "  Converted %d address fields on the "
                                "second attempt.\n", d->conversions );
                    d->conversions = 0;
                    d->state = 6;
                }

                if ( d->state == 6 ) {
                    d->state = 7;
                    d->query = new Query( *deleteHeaderFields, d );
                    d->query->bind( 1, m->id );
                    d->t->enqueue( d->query );
                    d->t->commit();
                }

                if ( d->state == 7 ) {
                    if ( !d->t->done() )
                        return;

                    if ( d->t->failed() ) {
                        fprintf( stderr, "Database error: %s\n",
                                 d->t->error().cstr() );
                        exit( -1 );
                    }

                    d->state = 2;
                    d->ids->take( it );
                }
            }

            if ( it )
                return;

            d->state = 666;
        }

        if ( d->state == 666 ) {
            d->state = 667;
            printf( "- Checking for misparsed addresses.\n" );
            d->t = new Transaction( d );
            d->query =
                new Query( "select distinct id,name,localpart,domain "
                           "from address_fields af join addresses a "
                           "on (af.address=a.id) where number is null ", d );
            d->t->enqueue( d->query );
            d->t->execute();
        }

        if ( d->state == 667 ) {
            if ( !d->query->done() )
                return;

            List<Address> * addresses = new List<Address>;
            while ( d->query->hasResults() ) {
                Row * r = d->query->nextRow();

                AddressMap * m = new AddressMap;
                m->bad = new Address( r->getString( "name" ),
                                      r->getString( "localpart" ),
                                      r->getString( "domain" ) );
                m->bad->setId( r->getInt( "id" ) );

                AddressParser ap( m->bad->toString() );
                if ( ap.addresses() )
                    m->good = ap.addresses()->first();

                if ( m->good ) {
                    d->addressMap->append( m );
                    addresses->append( m->good );
                }
            }

            printf( "  Reparsing %d addresses.\n", addresses->count() );

            d->state = 668;
            d->cacheLookup = AddressCache::lookup( d->t, addresses, d );
        }

        if ( d->state == 668 ) {
            if ( !d->cacheLookup->done() )
                return;

            String s( "update address_fields set address=CASE address " );
            String w( "" );

            d->conversions = 0;
            List<AddressMap>::Iterator it( d->addressMap );
            while ( it ) {
                if ( it->good->id() != 0 &&
                     it->good->id() != it->bad->id() )
                {
                    s.append( "WHEN " );
                    s.append( fn( it->bad->id() ) );
                    s.append( " THEN " );
                    s.append( fn( it->good->id() ) );
                    s.append( " " );
                    d->conversions++;
                    if ( w.isEmpty() )
                        w.append( "WHERE " );
                    else
                        w.append( "or " );
                    w.append( "address=" );
                    w.append( fn( it->bad->id() ) );
                    w.append( " " );
                }
                ++it;
            }

            s.append( "END " );
            s.append( w );

            d->state = 669;

            if ( d->conversions != 0 ) {
                printf( "  Updating %d reparsed addresses.\n",
                        d->conversions );
                d->query = new Query( s, d );
                d->t->enqueue( d->query );
            }

            d->t->commit();
        }

        if ( d->state == 669 ) {
            if ( !d->t->done() )
                return;

            if ( d->t->failed() ) {
                fprintf( stderr, "Database error: %s\n",
                         d->t->error().cstr() );
                exit( -1 );
            }
            else {
                if ( d->conversions != 0 ) {
                    printf( "- Rerunning update database.\n" );
                    d->addressMap->clear();
                    d->state = 0;
                }
                else {
                    d->state = 670;
                }
            }
        }
    }

    printf( "Done.\n" );
}


String sqlPattern( String s )
{
    String p;

    uint i = 0;
    while ( s[i] ) {
        if ( s[i] == '*' )
            p.append( '%' );
        else if ( s[i] == '?' )
            p.append( '_' );
        else
            p.append( s[i] );
        i++;
    }

    return p;
}


void listMailboxes()
{
    if ( d ) {
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();

            String s( r->getString( "name" ) );
            if ( opt( 's' ) > 0 ) {
                int messages = r->getInt( "messages" );
                int size = r->getInt( "size" );
                s.append( " (" );
                s.append( fn( messages ) );
                if ( messages == 1 )
                    s.append( " message, " );
                else
                    s.append( " messages, " );
                s.append( String::humanNumber( size ) );
                s.append( " bytes" );
                s.append( ")" );
            }

            printf( "%s\n", s.cstr() );
        }
        return;
    }

    String owner;
    StringList::Iterator it( args );
    while ( it ) {
        String s = *it;

        if ( s == "-d" ) {
            options[(int)'d']++;
        }
        else if ( s == "-s" ) {
            options[(int)'s']++;
        }
        else if ( s == "-o" ) {
            args->take( it );
            if ( args->isEmpty() )
                error( "No username specified with -o." );
            options[(int)'o']++;
            owner = *it;
        }
        else {
            break;
        }

        args->take( it );
    }

    String pattern = next();
    end();

    Database::setup( 1 );

    d = new Dispatcher( Dispatcher::ListMailboxes );

    String s( "select name,login as owner" );

    if ( opt( 's' ) > 0 )
        s.append( ",(select count(*) from messages where mailbox=m.id)::int "
                  "as messages,(select sum(rfc822size) from messages "
                  "where mailbox=m.id)::int as size" );

    s.append( " from mailboxes m left join users u on (m.owner=u.id)" );

    int n = 1;
    StringList where;
    if ( opt( 'd' ) == 0 )
        where.append( "not deleted" );
    if ( !pattern.isEmpty() )
        where.append( "name like $" + fn( n++ ) );
    if ( opt( 'o' ) > 0 )
        where.append( "login like $" + fn( n ) );

    if ( !where.isEmpty() ) {
        s.append( " where " );
        s.append( where.join( " and " ) );
    }

    d->query = new Query( s, d );
    if ( !pattern.isEmpty() )
        d->query->bind( 1, sqlPattern( pattern ) );
    if ( !owner.isEmpty() )
        d->query->bind( n, owner );
    d->query->execute();
}


bool validUsername( String s )
{
    uint i = 0;
    while ( i < s.length() &&
            ( ( s[i] >= '0' && s[i] <= '9' ) ||
              ( s[i] >= 'a' && s[i] <= 'z' ) ||
              ( s[i] >= 'Z' && s[i] <= 'Z' ) ||
              ( s[i] == '@' || s[i] == '.' ||
                s[i] == '-' || s[i] == '_' ) ) )
        i++;
    if ( i < s.length() ||
         s == "anyone" ||
         s == "group" ||
         s == "user" )
    {
        return false;
    }
    return true;
}


void listUsers()
{
    if ( d ) {
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();
            printf( "%-16s %s\n",
                    r->getString( "login" ).cstr(),
                    r->getString( "address" ).cstr() );
        }
        return;
    }

    String pattern = next();
    end();

    Database::setup( 1 );

    d = new Dispatcher( Dispatcher::ListUsers );

    String s( "select login, localpart||'@'||domain as address "
              "from users u join aliases al on (u.alias=al.id) "
              "join addresses a on (al.address=a.id)" );
    if ( !pattern.isEmpty() )
        s.append( " where login like $1" );
    d->query = new Query( s, d );
    if ( !pattern.isEmpty() )
        d->query->bind( 1, sqlPattern( pattern ) );
    d->query->execute();
}


void listAliases()
{
    if ( d ) {
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();
            printf( "%s: %s\n",
                    r->getString( "address" ).cstr(),
                    r->getString( "name" ).cstr() );
        }
        return;
    }

    String pattern = next();
    end();

    Database::setup( 1 );

    d = new Dispatcher( Dispatcher::ListAliases );

    String s( "select localpart||'@'||domain as address, m.name "
              "from aliases join addresses a on (address=a.id) "
              "join mailboxes m on (mailbox=m.id)" );
    if ( !pattern.isEmpty() )
        s.append( " where localpart||'@'||domain like $1 or "
                  "m.name like $1" );
    d->query = new Query( s, d );
    if ( !pattern.isEmpty() )
        d->query->bind( 1, sqlPattern( pattern ) );
    d->query->execute();
}


void createUser()
{
    if ( !d ) {
        parseOptions();
        String login = next();
        String passwd = next();
        String address = next();
        end();

        if ( login.isEmpty() || passwd.isEmpty() || address.isEmpty() )
            error( "Username, password, and address must be non-empty." );
        if ( !validUsername( login ) )
            error( "Invalid username: " + login );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        OCClient::setup();
        AddressCache::setup();

        d = new Dispatcher( Dispatcher::CreateUser );

        d->user = new User;
        d->user->setLogin( login );
        d->user->setSecret( passwd );
        d->user->setAddress( p.addresses()->first() );

        Mailbox::setup( d );
        d->user->refresh( d );
    }

    if ( !d->query ) {
        if ( d->user->state() == User::Unverified )
            return;

        if ( d->user->state() != User::Nonexistent )
            error( "User " + d->user->login() + " already exists." );

        d->query = d->user->create( d );
        d->user->execute();
    }

    if ( d->query->failed() )
        error( d->query->error() );
}


void deleteUser()
{
    if ( !d ) {
        parseOptions();
        String login = next();
        end();

        if ( login.isEmpty() )
            error( "No username supplied." );
        if ( !validUsername( login ) )
            error( "Invalid username: " + login );

        OCClient::setup();
        AddressCache::setup();

        d = new Dispatcher( Dispatcher::DeleteUser );
        Mailbox::setup( d );

        d->user = new User;
        d->user->setLogin( login );
        d->user->refresh( d );

        d->query =
            new Query( "select m.id,m.name from mailboxes m join users u "
                       "on (m.owner=u.id) where u.login=$1", d );
        d->query->bind( 1, login );
        d->query->execute();
    }

    if ( d->user->state() == User::Unverified )
        return;

    if ( !d->query->done() )
        return;

    if ( !d->t ) {
        if ( d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login() );

        if ( !opt( 'f' ) && d->query->hasResults() ) {
            fprintf( stderr, "User %s still owns the following mailboxes:\n",
                     d->user->login().cstr() );
            while ( d->query->hasResults() ) {
                Row * r = d->query->nextRow();
                String s = r->getString( "name" );
                fprintf( stderr, "%s\n", s.cstr() );
            }
            fprintf( stderr, "(Use 'aox delete user -f %s' to delete the "
                     "mailboxes too.)\n", d->user->login().cstr() );
            exit( -1 );
        }

        List<Query> aliases;
        d->t = new Transaction( d );
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();
            String s = r->getString( "name" );
            Mailbox * m = Mailbox::obtain( s, false );
            if ( !m || m->remove( d->t ) == 0 )
                error( "Couldn't delete mailbox " + s );
            Query * q = new Query( "delete from aliases where mailbox=$1", 0 );
            q->bind( 1, r->getInt( "id" ) );
            aliases.append( q );
        }
        d->query = d->user->remove( d->t );
        List<Query>::Iterator it( aliases );
        while ( it ) {
            d->t->enqueue( it );
            ++it;
        }
        d->t->commit();
    }

    if ( d->t && !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't delete user: " + d->t->error() );
}


void changePassword()
{
    if ( d )
        return;

    parseOptions();
    String login = next();
    String passwd = next();
    end();

    Database::setup( 1, Configuration::DbOwner );

    if ( login.isEmpty() || passwd.isEmpty() )
        error( "No username and password supplied." );
    if ( !validUsername( login ) )
        error( "Invalid username: " + login );

    User * u = new User;
    u->setLogin( login );
    u->setSecret( passwd );

    d = new Dispatcher( Dispatcher::ChangePassword );
    Mailbox::setup( d );
    d->query = u->changeSecret( d );
    if ( d->query->failed() )
        error( d->query->error() );
    u->execute();
}


void changeUsername()
{
    if ( !d ) {
        parseOptions();
        String name = next();
        String newname = next();
        end();

        Database::setup( 1, Configuration::DbOwner );
        AddressCache::setup();

        if ( name.isEmpty() || newname.isEmpty() )
            error( "Old and new usernames not supplied." );
        if ( !validUsername( name ) )
            error( "Invalid username: " + name );
        if ( !validUsername( newname ) )
            error( "Invalid username: " + newname );

        d = new Dispatcher( Dispatcher::ChangeUsername );

        d->user = new User;
        d->user->setLogin( name );
        d->s = newname;

        Mailbox::setup( d );
        d->user->refresh( d );
    }

    if ( !d->t ) {
        if ( d->user->state() == User::Unverified )
            return;

        if ( d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login() );

        d->t = new Transaction( d );

        Query * q =
            new Query( "update users set login=$2 where id=$1", d );
        q->bind( 1, d->user->id() );
        q->bind( 2, d->s );
        d->t->enqueue( q );

        d->query =
            new Query( "select name from mailboxes where deleted='f' and "
                       "name like '/users/'||$1||'/%'", d );
        d->query->bind( 1, d->user->login() );
        d->t->enqueue( d->query );

        d->t->execute();
    }

    if ( d->query && d->query->done() ) {
        while ( d->query->hasResults() ) {
            Row * r = d->query->nextRow();

            String name = r->getString( "name" );
            String newname( "/users/" + d->s );
            newname.append( name.mid( 7+d->user->login().length() ) );

            Query * q;

            Mailbox * from = Mailbox::obtain( name );
            uint uidvalidity = from->uidvalidity();

            Mailbox * to = Mailbox::obtain( newname );
            if ( to->deleted() ) {
                if ( to->uidvalidity() > uidvalidity ||
                     to->uidnext() > 1 )
                    uidvalidity = to->uidvalidity() + 1;
                q = new Query( "delete from mailboxes where id=$1", d );
                q->bind( 1, to->id() );
                d->t->enqueue( q );
            }

            q = new Query( "update mailboxes set name=$2,uidvalidity=$3 "
                           "where id=$1", d );
            q->bind( 1, from->id() );
            q->bind( 2, newname );
            q->bind( 3, uidvalidity );

            d->t->enqueue( q );
        }

        d->t->commit();
        d->query = 0;
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't change username: " + d->t->error() );
}


void changeAddress()
{
    if ( !d ) {
        parseOptions();
        String name = next();
        String address = next();
        end();

        if ( name.isEmpty() || address.isEmpty() )
            error( "Username and address must be non-empty." );
        if ( !validUsername( name ) )
            error( "Invalid username: " + name );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        Database::setup( 1, Configuration::DbOwner );
        AddressCache::setup();

        d = new Dispatcher( Dispatcher::ChangeAddress );
        d->address = p.addresses()->first();
        d->user = new User;
        d->user->setLogin( name );

        Mailbox::setup( d );
        d->user->refresh( d );
    }

    if ( !d->t ) {
        if ( d->user->state() == User::Unverified )
            return;

        if ( d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login() );

        d->t = new Transaction( d );
        List< Address > l;
        l.append( d->address );
        AddressCache::lookup( d->t, &l, d );
        d->t->execute();
    }

    if ( d->address->id() == 0 )
        return;

    if ( !d->query ) {
        d->query =
            new Query( "update aliases set address=$2 where id="
                       "(select alias from users where id=$1)", d );
        d->query->bind( 1, d->user->id() );
        d->query->bind( 2, d->address->id() );
        d->t->enqueue( d->query );
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't change address: " + d->t->error() );
}


void createMailbox()
{
    if ( !d ) {
        parseOptions();
        String name = next();
        String owner = next();
        end();

        if ( name.isEmpty() )
            error( "No mailbox name supplied." );

        OCClient::setup();
        AddressCache::setup();

        d = new Dispatcher( Dispatcher::CreateMailbox );
        d->s = name;
        Mailbox::setup( d );
        if ( !owner.isEmpty() ) {
            d->user = new User;
            d->user->setLogin( owner );
            d->user->refresh( d );
        }
        return;
    }

    if ( d && ( d->user && d->user->state() == User::Unverified ) )
        return;

    if ( !d->t ) {
        if ( d->user && d->user->state() == User::Nonexistent )
            error( "No user named " + d->user->login() );

        if ( d->user && !d->s.startsWith( "/" ) )
            d->s = d->user->home()->name() + "/" + d->s;

        d->m = Mailbox::obtain( d->s );
        if ( !d->m )
            error( "Can't create mailbox named " + d->s );

        d->t = new Transaction( d );
        if ( d->m->create( d->t, d->user ) == 0 )
            error( "Couldn't create mailbox " + d->s );
        d->t->commit();
    }

    if ( d->t && !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't create mailbox: " + d->t->error() );

    OCClient::send( "mailbox " + d->m->name().quoted() + " new" );
}


void deleteMailbox()
{
    if ( !d ) {
        parseOptions();
        String name = next();
        end();

        if ( name.isEmpty() )
            error( "No mailbox name supplied." );

        OCClient::setup();
        AddressCache::setup();

        d = new Dispatcher( Dispatcher::DeleteMailbox );
        d->s = name;
        Mailbox::setup( d );
        return;
    }

    if ( !d->t ) {
        d->m = Mailbox::obtain( d->s, false );
        if ( !d->m )
            error( "No mailbox named " + d->s );
        d->t = new Transaction( d );
        if ( d->m->remove( d->t ) == 0 )
            error( "Couldn't delete mailbox " + d->s );
        d->t->commit();
    }

    if ( d->t && !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't delete mailbox: " + d->t->error() );

    OCClient::send( "mailbox " + d->m->name().quoted() + " deleted" );
}


void createAlias()
{
    if ( !d ) {
        parseOptions();
        String address = next();
        String mailbox = next();
        end();

        if ( address.isEmpty() )
            error( "No address specified." );

        if ( mailbox.isEmpty() )
            error( "No mailbox specified." );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        AddressCache::setup();

        d = new Dispatcher( Dispatcher::CreateAlias );

        d->s = mailbox;
        d->address = p.addresses()->first();

        d->t = new Transaction( d );
        List< Address > l;
        l.append( d->address );
        AddressCache::lookup( d->t, &l, d );
        d->t->commit();

        Mailbox::setup( d );
        return;
    }

    if ( !d->t->done() )
        return;

    if ( !d->query ) {
        Mailbox * m = Mailbox::obtain( d->s, false );
        if ( !m )
            error( "Invalid mailbox specified: '" + d->s + "'" );

        d->query =
            new Query( "insert into aliases (address, mailbox) "
                       "values ($1, $2)", d );
        d->query->bind( 1, d->address->id() );
        d->query->bind( 2, m->id() );
        d->query->execute();
    }

    if ( !d->query->done() )
        return;

    if ( d->query->failed() )
        error( "Couldn't create alias: " + d->query->error() );
}


void deleteAlias()
{
    if ( !d ) {
        parseOptions();
        String address = next();
        end();

        if ( address.isEmpty() )
            error( "No address specified." );

        AddressParser p( address );
        if ( !p.error().isEmpty() )
            error( "Invalid address: " + p.error() );
        if ( p.addresses()->count() != 1 )
            error( "At most one address may be present" );

        Address * a = p.addresses()->first();

        d = new Dispatcher( Dispatcher::DeleteAlias );

        d->query =
            new Query( "delete from aliases where address=(select id "
                       "from addresses where lower(localpart)=$1 and "
                       "lower(domain)=$2 and name='')", d );
        d->query->bind( 1, a->localpart().lower() );
        d->query->bind( 2, a->domain().lower() );
        d->query->execute();
    }

    if ( !d->query->done() )
        return;

    if ( d->query->failed() )
        error( "Couldn't delete alias: " + d->query->error() );
}


void vacuum()
{
    if ( !d ) {
        parseOptions();
        end();

        Database::setup( 1, Configuration::DbOwner );
        // it doesn't really matter, but the 1 above ensures that the
        // two queries below are sent sequentially
        d = new Dispatcher( Dispatcher::Vacuum );
        String to = fn( Configuration::scalar( Configuration::UndeleteTime ) );
        // this needs to become lots more advanced in the coming
        // versions... sanity-checking on the number of messages is
        // one thing, retention policies is another.
        d->query
            = new Query( "delete from messages "
                         "where (mailbox,uid) in "
                         "(select mailbox,uid from deleted_messages "
                         "where deleted_at<current_timestamp-'" +
                         to + " days'::interval)", d );
        d->query->execute();
    }

    if ( !d->t && !d->query->done() )
        return;

    if ( !d->t ) {
        d->t = new Transaction( d );
        d->query =
            new Query( "lock mailboxes in exclusive mode", d );
        d->t->enqueue( d->query );
        d->query =
            new Query( "delete from bodyparts where id in (select id "
                       "from bodyparts b left join part_numbers p on "
                       "(b.id=p.bodypart) where bodypart is null)", d );
        d->t->enqueue( d->query );
        d->t->commit();
    }
}


void anonymise( const String & s )
{
    File f( s );
    if ( f.valid() )
        fprintf( stdout, "%s\n", f.contents().anonymised().cstr() );
    else
        error( "Couldn't open file: " + s );
}


void help()
{
    String a = next().lower();
    String b = next().lower();

    if ( a == "add" || a == "new" )
        a = "create";
    else if ( a == "del" || a == "remove" )
        a = "delete";

    // We really need a better way of constructing help texts.
    // (And better help text, now that I think about it.)

    if ( a == "start" ) {
        fprintf(
            stderr,
            "  start -- Start the servers.\n\n"
            "    Synopsis: aox start [-v]\n\n"
            "    Starts the Oryx servers in the correct order.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "stop" ) {
        fprintf(
            stderr,
            "  stop -- Stop the running servers.\n\n"
            "    Synopsis: aox stop [-v]\n\n"
            "    Stops the running Oryx servers in the correct order.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "restart" ) {
        fprintf(
            stderr,
            "  restart -- Restart the servers.\n\n"
            "    Synopsis: aox restart [-v]\n\n"
            "    Restarts the Oryx servers in the correct order.\n"
            "    (Currently equivalent to start && stop.)\n\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "show" && b == "status" ) {
        fprintf(
            stderr,
            "  show status -- Display a summary of the running servers.\n\n"
            "    Synopsis: aox show status [-v]\n\n"
            "    Displays a summary of the running Oryx servers.\n"
            "    The -v flag enables (slightly) verbose diagnostic output.\n"
        );
    }
    else if ( a == "show" && ( b == "cf" || b.startsWith( "conf" ) ) ) {
        fprintf(
            stderr,
            "  show configuration -- Display configuration variables.\n\n"
            "    Synopsis: aox show conf [ -p -v ] [variable-name]\n\n"
            "    Displays variables configured in archiveopteryx.conf.\n\n"
            "    If a variable-name is specified, only that variable\n"
            "    is displayed.\n\n"
            "    The -v flag displays only the value of the variable.\n"
            "    The -p flag restricts the results to variables whose\n"
            "    value has been changed from the default.\n\n"
            "    configuration may be abbreviated as cf.\n\n"
            "    Examples:\n\n"
            "      aox show configuration\n"
            "      aox show cf -p\n"
            "      aox show cf -v imap-address\n"
        );
    }
    else if ( a == "show" && b.startsWith( "build" ) ) {
        fprintf(
            stderr,
            "  show build -- Display build settings.\n\n"
            "    Synopsis: aox show build\n\n"
            "    Displays the build settings used for this installation.\n"
            "    (As configured in Jamsettings.)\n"
        );
    }
    else if ( a == "show" && b.startsWith( "count" ) ) {
        fprintf(
            stderr,
            "  show counts -- Show number of users, messages etc..\n\n"
            "    Synopsis: aox show counts [-f]\n\n"
            "    Displays the number of rows in the most important tables,\n"
            "    as well as the total size of the mail stored.\n"
            "\n"
            "    The -f flag makes aox collect slow-but-accurate counts.\n"
            "    Without it, by default, you get quick estimates.\n"
        );
    }
    else if ( a == "show" && b == "schema" ) {
        fprintf(
            stderr,
            "  show schema -- Display schema revision.\n\n"
            "    Synopsis: aox show schema\n\n"
            "    Displays the revision of the existing database schema.\n"
        );
    }
    else if ( a == "upgrade" && b == "schema" ) {
        fprintf(
            stderr,
            "  upgrade schema -- Upgrade the database schema.\n\n"
            "    Synopsis: aox upgrade schema [-n]\n\n"
            "    Checks that the database schema is one that this version of\n"
            "    Archiveopteryx is compatible with, and updates it if needed.\n"
            "\n"
            "    The -n flag causes aox to perform the SQL statements for the\n"
            "    schema upgrade and report on their status without COMMITting\n"
            "    the transaction (i.e. see what the upgrade would do, without\n"
            "    changing anything).\n"
        );
    }
    else if ( a == "update" && b == "database" ) {
        fprintf(
            stderr,
            "  update database -- Update the database contents.\n\n"
            "    Synopsis: aox update database\n\n"
            "    Performs any updates to the database contents which are too\n"
            "    slow for inclusion in \"aox upgrade schema\". This command is\n"
            "    meant to be used while the server is running. It does its\n"
            "    work in small chunks, so it can be restarted at any time,\n"
            "    and is tolerant of interruptions.\n"
        );
    }
    else if ( a == "list" && b == "mailboxes" ) {
        fprintf(
            stderr,
            "  list mailboxes -- Display existing mailboxes.\n\n"
            "    Synopsis: aox list mailboxes [-d] [-o user] [pattern]\n\n"
            "    Displays a list of mailboxes matching the specified shell\n"
            "    glob pattern. Without a pattern, all mailboxes are listed.\n\n"
            "    The -d flag includes deleted mailboxes in the list.\n\n"
            "    The \"-o username\" flag restricts the list to mailboxes\n"
            "    owned by the specified user.\n\n"
            "    The -s flag shows a count of messages and the total size\n"
            "    of messages in each mailbox.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list mailboxes\n"
            "      aox ls mailboxes /users/ab?cd*\n"
        );
    }
    else if ( a == "list" && b == "users" ) {
        fprintf(
            stderr,
            "  list users -- Display existing users.\n\n"
            "    Synopsis: aox list users [pattern]\n\n"
            "    Displays a list of users matching the specified shell\n"
            "    glob pattern. Without a pattern, all users are listed.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list users\n"
            "      aox ls users ab?cd*\n"
        );
    }
    else if ( a == "list" && b == "aliases" ) {
        fprintf(
            stderr,
            "  list aliases -- Display delivery aliases.\n\n"
            "    Synopsis: aox list aliases [pattern]\n\n"
            "    Displays a list of aliases where either the address or the\n"
            "    target mailbox matches the specified shell glob pattern.\n"
            "    Without a pattern, all aliases are listed.\n\n"
            "    ls is an acceptable abbreviation for list.\n\n"
            "    Examples:\n\n"
            "      aox list aliases\n"
            "      aox ls aliases /users/\\*\n"
        );
    }
    else if ( a == "create" && b == "user" ) {
        fprintf(
            stderr,
            "  create user -- Create a new user.\n\n"
            "    Synopsis: aox create user <username> <password> <e@ma.il>\n\n"
            "    Creates a new Archiveopteryx user with the given username,\n"
            "    password, and email address.\n"
        );
    }
    else if ( a == "delete" && b == "user" ) {
        fprintf(
            stderr,
            "  delete user -- Delete a user.\n\n"
            "    Synopsis: aox create user [-f] <username>\n\n"
            "    Deletes the Archiveopteryx user with the specified name.\n\n"
            "    The -f flag causes any mailboxes owned by the user to be "
            "deleted too.\n"
        );
    }
    else if ( a == "change" && b == "password" ) {
        fprintf(
            stderr,
            "  change password -- Change a user's password.\n\n"
            "    Synopsis: aox change password <username> <new-password>\n\n"
            "    Changes the specified user's password.\n"
        );
    }
    else if ( a == "change" && b == "username" ) {
        fprintf(
            stderr,
            "  change username -- Change a user's name.\n\n"
            "    Synopsis: aox change username <username> <new-username>\n\n"
            "    Changes the specified user's username.\n"
        );
    }
    else if ( a == "change" && b == "address" ) {
        fprintf(
            stderr,
            "  change address -- Change a user's email address.\n\n"
            "    Synopsis: aox change address <username> <new-address>\n\n"
            "    Changes the specified user's email address.\n"
        );
    }
    else if ( a == "create" && b == "mailbox" ) {
        fprintf(
            stderr,
            "  create mailbox -- Create a new mailbox.\n\n"
            "    Synopsis: aox create mailbox <name> [username]\n\n"
            "    Creates a new mailbox with the specified name and,\n"
            "    if a username is specified, owned by that user.\n\n"
            "    The mailbox name must be fully-qualified (begin with /),\n"
            "    unless a username is specified, in which case unqualified\n"
            "    names are assumed to be under the user's home directory.\n"
        );
    }
    else if ( a == "delete" && b == "mailbox" ) {
        fprintf(
            stderr,
            "  delete mailbox -- Delete a mailbox.\n\n"
            "    Synopsis: aox delete mailbox <name>\n\n"
            "    Deletes the specified mailbox.\n"
        );
    }
    else if ( a == "create" && b == "alias" ) {
        fprintf(
            stderr,
            "  create alias -- Create a delivery alias.\n\n"
            "    Synopsis: aox create alias <address> <mailbox>\n\n"
            "    Creates an alias that instructs the L/SMTP server to accept\n"
            "    mail to a given address, and deliver it to a given mailbox.\n"
            "    (Ordinarily, mail is accepted only to a user's main address,\n"
            "    and stored in their INBOX. Aliases take precedence over this\n"
            "    mechanism.)\n"
        );
    }
    else if ( a == "delete" && b == "alias" ) {
        fprintf(
            stderr,
            "  delete alias -- Delete a delivery alias.\n\n"
            "    Synopsis: aox delete alias <address>\n\n"
            "    Deletes the alias that associated the specified address\n"
            "    with a mailbox.\n"
        );
    }
    else if ( a == "vacuum" ) {
        fprintf(
            stderr,
            "  vacuum -- Perform routine maintenance.\n\n"
            "    Synopsis: aox vacuum\n\n"
            "    Permanently deletes messages that were marked for deletion\n"
            "    more than a certain number of days ago (cf. undelete-time)\n"
            "    and removes any bodyparts that are no longer used.\n\n"
            "    This process holds an exclusive lock on the mailboxes table\n"
            "    (i.e. new messages cannot be injected until it's done) while\n"
            "    removing orphaned bodyparts.\n\n"
            "    This is not a replacement for running VACUUM ANALYSE on the\n"
            "    database (either with vaccumdb or via autovacuum).\n\n"
            "    This command should be run (we suggest daily) via crontab.\n"
        );
    }
    else if ( a == "anonymise" ) {
        fprintf(
            stderr,
            "  anonymise -- Anonymise a named mail message.\n\n"
            "    Synopsis: aox anonymise filename\n\n"
            "    Reads a mail message from the named file, obscures most or\n"
            "    all content and prints the result on stdout. The output\n"
            "    resembles the original closely enough to be used in a bug\n"
            "    report.\n"
        );
    }
    else if ( a == "check" ) {
        fprintf(
            stderr,
            "  check - Check that the configuration is sane.\n\n"
            "    Synopsis: aox check\n\n"
            "    Reads the configuration, looks for self-contradictions and reports\n"
            "    any problems it finds.\n"
        );
    }
    else if ( a == "commands" ) {
        fprintf(
            stderr,
            "  Available aox commands:\n\n"
            "    start              -- Server management.\n"
            "    stop\n"
            "    restart\n\n"
            "    check              -- Check that the configuration is sane.\n"
            "    show status        -- Are the servers running?\n"
            "    show counts        -- Shows number of users, messages etc.\n"
            "    show configuration -- Displays runtime configuration.\n"
            "    show build         -- Displays compile-time configuration.\n"
            "\n"
            "    show schema        -- Displays the existing schema revision.\n"
            "    upgrade schema     -- Upgrades an older schema to work with\n"
            "                          the current server.\n"
            "\n"
            "                       -- User and mailbox management.\n"
            "    list <users|mailboxes|aliases>\n"
            "    create <user|mailbox|alias>\n"
            "    delete <user|mailbox|alias>\n"
            "    change <username|password|address>\n"
            "\n"
            "    vacuum             -- VACUUM the database.\n"
            "    anonymise          -- Anonymise a message for a bug report.\n"
            "\n"
            "  Use \"aox help command name\" for more specific help.\n"
        );
    }
    else {
        fprintf(
            stderr,
            "  aox -- A command-line interface to Archiveopteryx.\n\n"
            "    Synopsis: %s <verb> <noun> [options] [arguments]\n\n"
            "    Use \"aox help commands\" for a list of commands.\n"
            "    Use \"aox help start\" for help with \"start\".\n",
            aox
        );
    }
}


class Path
    : public Garbage
{
public:
    enum Type {
        Readable,
        ReadableFile,
        ReadableDir,
        WritableFile,
        WritableDir,
        CreatableFile,
        JailDir
    };

    Path( const String &, Type );
    bool checked;
    bool ok;
    void check();
    static bool allOk;

    Path * parent;
    const char * message;
    Dict<Path> variables;
    String name;
    Type type;

    static uint uid;
    static uint gid;
};


uint Path::uid;
uint Path::gid;
bool Path::allOk;
static Dict<Path> paths;


static void addPath( Path::Type type,
                     Configuration::Text variable )
{
    String name = Configuration::text( variable );
    Path * p = paths.find( name );
    if ( name.startsWith( "/" ) ) {
        if ( !p ) {
            p = new Path( name, type );
            paths.insert( name, p );
        }
    }

    while ( p ) {
        if ( p->type != type )
            // this isn't 100% good enough, is it... let's write the
            // huge code to produce the right message if it ever bites
            // anyone.
            p->message = "has conflicting permission requirements";
        p->variables.insert( Configuration::name( variable ), p );
        p = p->parent;
    }
}


static String parentOf( const String & name )
{
    uint i = name.length();
    while ( i > 0 && name[i] != '/' )
        i--;
    String pn = name.mid( 0, i );
    if ( i == 0 )
        pn = "/";
    return pn;
}


Path::Path( const String & s, Type t )
    : Garbage(),
      checked( false ), ok( true ),
      parent( 0 ), message( 0 ),
      name( s ), type( t )
{
    String pn = parentOf( name );
    if ( pn.length() < name.length() ) {
        Path * p = paths.find( pn );
        if ( !p ) {
            if ( t == CreatableFile || t == WritableFile )
                p = new Path( pn, WritableDir );
            else
                p = new Path( pn, ReadableDir );
            paths.insert( pn, p );
        }
    }
}


void Path::check()
{
    if ( checked )
        return;
    if ( parent && !parent->checked )
        parent->check();

    checked = true;
    if ( parent && !parent->ok ) {
        ok = false;
        return;
    }

    struct stat st;
    uint rights = 0;
    bool isdir = false;
    bool isfile = false;
    const char * message = 0;
    bool exist = false;
    if ( stat( name.cstr(), &st ) >= 0 ) {
        exist = true;
        if ( st.st_uid == uid )
            rights = st.st_mode >> 6;
        else if ( st.st_gid == gid )
            rights = st.st_mode >> 3;
        else
            rights = st.st_mode;
        rights &= 7;
        isdir = S_ISDIR(st.st_mode);
        isfile = S_ISREG(st.st_mode);
    }

    switch( type ) {
    case Readable:
        if ( !exist )
            message = "does not exist";
        else if ( isdir )
            message = "is not a normal file";
        else if ( (rights & 4) != 4 )
            message = "is not readable";
        break;
    case ReadableFile:
        if ( !exist )
            message = "does not exist";
        else if ( !isfile )
            message = "is not a normal file";
        else if ( (rights & 4) != 4 )
            message = "is not readable";
        break;
    case ReadableDir:
        if ( !exist )
            message = "does not exist";
        else if ( !isdir )
            message = "is not a directory";
        else if ( (rights & 5) != 5 )
            message = "is not readable and searchable";
        break;
    case WritableFile:
        if ( exist && !isfile )
            message = "is not a normal file";
        else if ( (rights & 2) != 2 )
            message = "is not writable";
        break;
    case WritableDir:
        if ( !exist )
            message = "does not exist";
        else if ( !isdir )
            message = "is not a directory";
        else if ( (rights & 3) != 3 )
            message = "is not writable and searchable";
        break;
    case CreatableFile:
        if ( exist && !isfile )
            message = "is not a normal file";
        break;
    case JailDir:
        if ( !isdir )
            message = "is not a directory";
        if ( rights )
            message = "is accessible and should not be";
        break;
    }

    if ( !message )
        return;
    fprintf( stderr, "%s %s.\n", name.cstr(), message );
    StringList::Iterator i( variables.keys() );
    while ( i ) {
        fprintf( stderr, " - affected variable: %s\n", i->cstr() );
        ++i;
    }
    ok = false;
    allOk = false;
}


void checkFilePermissions()
{
    String user( Configuration::text( Configuration::JailUser ) );
    struct passwd * pw = getpwnam( user.cstr() );
    if ( !pw ) {
        fprintf( stderr,
                 "%s (jail-user) is not a valid username.\n", user.cstr() );
        exit( 1 );
    }
    if ( pw->pw_uid == 0 ) {
        fprintf( stderr,
                 "%s (jail-user) has UID 0.\n", user.cstr() );
        exit( 1 );
    }

    String group( Configuration::text( Configuration::JailGroup ) );
    struct group * gr = getgrnam( group.cstr() );
    if ( !gr ) {
        fprintf( stderr,
                 "%s (jail-group) is not a valid group.\n", group.cstr() );
        exit( 1 );
    }
    Path::uid = pw->pw_uid;
    Path::gid = gr->gr_gid;
    Path::allOk = true;

    if ( Configuration::text( Configuration::MessageCopy ).lower() != "none" )
        addPath( Path::WritableDir, Configuration::MessageCopyDir );
    addPath( Path::JailDir, Configuration::JailDir );
    addPath( Path::ReadableFile, Configuration::TlsCertFile );
    addPath( Path::Readable, Configuration::EntropySource );
    addPath( Path::CreatableFile, Configuration::LogFile );

    // should also do all the *-address ones, if they're AF_UNIX. but
    // not now.

    StringList::Iterator i( paths.keys() );
    while ( i ) {
        paths.find( *i )->check();
        ++i;
    }
    if ( !Path::allOk ) {
        fprintf( stderr,
                 "Checking as user %s (uid %d), group %s (gid %d)\n",
                 user.cstr(), Path::uid, group.cstr(), Path::gid );
        exit( 1 );
    }
}

void checkConfigConsistency()
{
    // for the moment, this does only one thing. how should we
    // organise this function if we want to check several things?

    // and wouldn't it be neat to run this before start/stop/restart?
    if ( !d ) {
        Database::setup( 1 );

        d = new Dispatcher( Dispatcher::CheckConfigConsistency );
        d->query =
            new Query( "select login from users where "
                       "lower(login)='anonymous'", d );
        d->query->execute();
    }

    if ( d && !d->query->done() )
        return;

    Row * r = d->query->nextRow();
    if ( d->query->failed() ) {
        error( "Could not check configuration consistency." );
        return;
    }

    if ( r ) {
        if ( !Configuration::toggle( Configuration::AuthAnonymous ) )
            fprintf( stderr, "Note: auth-anonymous is disabled, "
                     "but there is an anonymous user.\n"
                     "The anonymous user will not be used. "
                     "You may wish to delete it using\n"
                     "  aox delete user anonymous.\n" );
    }
    else {
        if ( Configuration::toggle( Configuration::AuthAnonymous ) )
            fprintf( stderr, "Note: auth-anonymous is enabled, "
                     "but there is no anonymous user,\n"
                     "so anonymous authentication will not work. "
                     "You may wish to run\n"
                     "  aox add user anonymous '' email@address.here.\n" );
    }
}


void reparse()
{
    if ( !d ) {
        end();

        Database::setup( 1, Configuration::DbOwner );

        d = new Dispatcher( Dispatcher::Reparse );

        AddressCache::setup();
        FieldNameCache::setup();
        Mailbox::setup( d );

        d->query = new Query( "select p.mailbox,p.uid,b.id as bodypart,"
                              "b.text,b.data "
                              "from unparsed_messages u "
                              "join bodyparts b on (u.bodypart=b.id) "
                              "join part_numbers p on (p.bodypart=b.id) "
                              "left join deleted_messages dm on "
                              " (p.mailbox=dm.mailbox and p.uid=dm.uid) "
                              "where dm.mailbox is null", d );
        d->query->execute();
    }

    if ( d->injector ) {
        if ( !d->injector->done() )
            return;
        if ( !d->injector->failed() ) {
            d->injector->announce();
            Query * q =
                new Query( "insert into deleted_messages "
                           "(mailbox,uid,deleted_by,reason) "
                           "values ($1,$2,$3,$4)", d );
            q->bind( 1, d->row->getInt( "mailbox" ) );
            q->bind( 2, d->row->getInt( "uid" ) );
            q->bindNull( 3 );
            q->bind( 4,
                     String( "reparsed as uid " ) +
                     fn(d->injector->uid(d->injector->mailboxes()->first())) +
                     " by aox " +
                     Configuration::compiledIn( Configuration::Version ) );
            q->execute();
        }
    }

    while ( d->query->hasResults() ) {
        Row * r = d->query->nextRow();

        String text;
        if ( r->isNull( "data" ) )
            text = r->getString( "text" );
        else
            text = r->getString( "data" );
        Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
        Message * msg = new Message( text );
        if ( m && msg->valid() ) {
            d->row = r;
            d->injector = new Injector( msg, d );
            SortedList<Mailbox> * l = new SortedList<Mailbox>;
            l->append( m );
            d->injector->setMailboxes( l );
            d->injector->execute();
            printf( "- reparsed %s:%d (at least %d more messages)\n",
                    m->name().cstr(), r->getInt( "uid" ), d->query->rows() );
            return;
        }
        else {
            printf( "- parsing %s:%d still fails: %s\n",
                    m->name().cstr(), r->getInt( "uid" ),
                    msg->error().simplified().cstr() );
        }
    }
}
