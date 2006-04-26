// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "string.h"
#include "allocator.h"
#include "stringlist.h"
#include "configuration.h"
#include "addresscache.h"
#include "transaction.h"
#include "eventloop.h"
#include "database.h"
#include "occlient.h"
#include "address.h"
#include "mailbox.h"
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
class Dispatcher * d;


char * servers[] = {
    "logd", "ocd", "tlsproxy", "archiveopteryx"
};
const int nservers = sizeof( servers ) / sizeof( servers[0] );


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
void listMailboxes();
void listUsers();
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


/*! \nodoc */


class StderrLog
    : public Logger
{
public:
    StderrLog();
    void send( const String &,
               Log::Facility, Log::Severity,
               const String & );
    void commit( const String &, Log::Severity ) {}
    virtual String name() const;
};


StderrLog::StderrLog()
    : Logger()
{
    // nothing?
}


void StderrLog::send( const String &,
                      Log::Facility, Log::Severity s,
                      const String & m )
{
    // Log already does this
    if ( s == Log::Error )
        fprintf( stderr, "%s: %s\n", name().cstr(), m.cstr() );

    // Debug we ignore, Info we ignore for now.

    // and in case of a disaster, we quit. the hard way.
    if ( s == Log::Disaster ) {
        fprintf( stderr, "%s: Fatal error. Exiting.\n", name().cstr() );
        exit( 1 );
    }
}


String StderrLog::name() const
{
    return "aox";
}


int main( int ac, char *av[] )
{
    Scope global;

    args = new StringList;
    aox = *av++;
    ac--;

    int i = 0;
    while ( i < ac )
        args->append( new String( av[i++] ) );

    EventLoop::setup();

    Configuration::setup( "archiveopteryx.conf" );
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "log object" );
    global.setLog( l );
    Allocator::addEternal( new StderrLog, "log object" );

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
    else if ( verb == "list" || verb == "ls" ) {
        String noun = next().lower();
        if ( noun == "users" )
            listUsers();
        else if ( noun == "mailboxes" )
            listMailboxes();
        else
            bad( verb, noun, "users, mailboxes" );
    }
    else if ( verb == "create" || verb == "delete" ) {
        String noun = next().lower();

        Database::setup();

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
    else {
        if ( verb != "help" )
            args->prepend( new String( verb ) );
        help();
    }

    if ( d ) {
        Allocator::addEternal( d, "Event dispatcher" );
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


class Dispatcher
    : public EventHandler
{
public:
    enum Command {
        Start, ShowCounts, ShowSchema, UpgradeSchema,
        ListMailboxes, ListUsers, CreateUser, DeleteUser,
        ChangePassword, ChangeUsername, ChangeAddress,
        CreateMailbox, DeleteMailbox, CreateAlias, DeleteAlias,
        Vacuum
    };

    List< Query > * chores;
    Command command;
    Query * query;
    User * user;
    Transaction * t;
    Address * address;
    String s;

    Dispatcher( Command cmd )
        : chores( new List< Query > ),
          command( cmd ), query( 0 ),
          user( 0 ), t( 0 ), address( 0 )
    {
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

        case ListMailboxes:
            listMailboxes();
            break;

        case ListUsers:
            listUsers();
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


void startServer( const char * s )
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
        return;
    }

    int p = serverPid( s );
    if ( p != -1 ) {
        if ( kill( p, 0 ) != 0 && errno == ESRCH ) {
            File::unlink( pidFile( s ) );
        }
        else {
            if ( opt( 'v' ) > 0 )
                printf( "%s(%d) is already running\n", s, p );
            return;
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

        Database::setup();

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
    while ( i < nservers )
        startServer( servers[i++] );
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
    printf( "ORYXUSER = %s\n",
            Configuration::compiledIn( Configuration::OryxUser ) );
    printf( "ORYXGROUP = %s\n",
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
        if ( j != Configuration::DbPassword ) {
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
        end();

        Database::setup();

        d = new Dispatcher( Dispatcher::ShowCounts );
        d->query =
            new Query( "select "
                       "(select count(*) from mailboxes"
                       " where deleted='f')::int as mailboxes,"
                       "(select count(*) from messages)::int as messages,"
                       "(select count(*) from bodyparts)::int as bodyparts,"
                       "(select sum(length(text)) from bodyparts)::int as textsize,"
                       "(select sum(length(data)) from bodyparts)::int as datasize,"
                       "(select count(*) from addresses)::int as addresses,"
                       "(select sum(rfc822size) from messages)::int as size,"
                       "(select count(*) from users)::int as users", d );
        d->query->execute();
    }

    if ( d && !d->query->done() )
        return;

    Row * r = d->query->nextRow();
    if ( r ) {
        uint mailboxes = 0;
        if ( !r->isNull( "mailboxes" ) )
            mailboxes = r->getInt( "mailboxes" );
        uint messages = 0;
        if ( !r->isNull( "messages" ) )
            messages = r->getInt( "messages" );
        uint bodyparts = 0;
        if ( !r->isNull( "bodyparts" ) )
            bodyparts = r->getInt( "bodyparts" );
        uint addresses = 0;
        if ( !r->isNull( "addresses" ) )
            addresses = r->getInt( "addresses" );
        uint textSize = 0;
        if ( !r->isNull( "textsize" ) )
            textSize = r->getInt( "textsize" );
        uint dataSize = 0;
        if ( !r->isNull( "datasize" ) )
            dataSize = r->getInt( "datasize" );
        uint size = 0;
        if ( !r->isNull( "size" ) )
            size = r->getInt( "size" );
        uint users = 0;
        if ( !r->isNull( "users" ) )
            users = r->getInt( "users" );

        printf( "Users: %d\n"
                "Mailboxes: %d\n"
                "Messages: %d (%s total size)\n"
                "Bodyparts: %d (%s text, %s data)\n"
                "Addresses: %d\n",
                users,
                mailboxes,
                messages, String::humanNumber( size ).cstr(),
                bodyparts,
                String::humanNumber( textSize ).cstr(),
                String::humanNumber( dataSize ).cstr(),
                addresses );
    }
}




void showSchema()
{
    const char * versions[] = {
        "", "", "0.91", "0.92", "0.92", "0.92 to 0.93", "0.93",
        "0.93", "0.94 to 0.95", "0.96 to 0.97", "0.97", "0.97",
        "0.98", "0.99", "1.0", "1.01", "1.05", "1.05", "1.06"
    };
    int nv = sizeof( versions ) / sizeof( versions[0] );

    if ( !d ) {
        end();

        Database::setup();

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
                s.append( ", and perhaps later versions" );
        }

        if ( !s.isEmpty() )
            s = " (" + s + ")";
        printf( "%d%s\n", rev, s.cstr() );
    }
}


void upgradeSchema()
{
    if ( d )
        return;

    end();

    Database::setup();

    d = new Dispatcher( Dispatcher::UpgradeSchema );
    Schema * s = new Schema( d, true );
    d->waitFor( s->result() );
    s->execute();
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

    Database::setup();

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
              ( s[i] == '@' || s[i] == '.' || s[i] == '-' ) ) )
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

    Database::setup();

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

    Database::setup();

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

        Database::setup();
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

        Database::setup();
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

        Mailbox * m = Mailbox::obtain( d->s );
        if ( !m )
            error( "Can't create mailbox named " + d->s );

        d->t = new Transaction( d );
        if ( m->create( d->t, d->user ) == 0 )
            error( "Couldn't create mailbox " + d->s );
        d->t->commit();
    }

    if ( d->t && !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't create mailbox: " + d->t->error() );
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
        Mailbox * m = Mailbox::obtain( d->s, false );
        if ( !m )
            error( "No mailbox named " + d->s );
        d->t = new Transaction( d );
        if ( m->remove( d->t ) == 0 )
            error( "Couldn't delete mailbox " + d->s );
        d->t->commit();
    }

    if ( d->t && !d->t->done() )
        return;

    if ( d->t->failed() )
        error( "Couldn't delete mailbox: " + d->t->error() );
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

        Database::setup();
        d = new Dispatcher( Dispatcher::Vacuum );
        d->query = new Query( "vacuum analyze", d );
        d->query->execute();
    }

    if ( !d->t && !d->query->done() )
        return;

    if ( !d->t ) {
        if ( opt( 'b' ) != 0 ) {
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
            "    Synopsis: aox show counts\n\n"
            "    Displays the number of rows in the most important tables,\n"
            "    as well as the total size of the mail stored.\n"
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
            "    Synopsis: aox upgrade schema\n\n"
            "    Checks that the database schema is one that this version of\n"
            "    Archiveopteryx is compatible with, and updates it if needed.\n"
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
            "    Synopsis: aox vacuum [-b]\n\n"
            "    VACUUMs the database and (optionally) cleans up bodyparts\n"
            "    that are no longer in use by any message (as a result of\n"
            "    messages being deleted).\n\n"
            "    The -b flag causes orphaned bodyparts to be cleaned up,\n"
            "    which requires an exclusive lock on the mailboxes table\n"
            "    (i.e., messages cannot be injected until it is done).\n\n"
            "    This command should be run via crontab.\n"
        );
    }
    else if ( a == "anonymise" ) {
        fprintf(
            stderr,
            "  anonymise -- Anonymise a named mail message.\n\n"
            "    Synopsis: aox anonymise filename\n\n"
            "    Reads a mail message from the named file, obscures most or all\n"
            "    content and prints the result on stdout. The output resembles the\n"
            "    original closely enough to be used in a bug report.\n"
        );
    }
    else if ( a == "commands" ) {
        fprintf(
            stderr,
            "  Available aox commands:\n\n"
            "    start              -- Server management.\n"
            "    stop\n"
            "    restart\n\n"
            "    show status        -- Are the servers running?\n"
            "    show counts        -- Shows number of users, messages etc.\n"
            "    show configuration -- Displays runtime configuration.\n"
            "    show build         -- Displays compile-time configuration.\n"
            "\n"
            "    show schema        -- Displays the existing schema revision.\n"
            "    upgrade schema     -- Upgrades an older schema to work with\n"
            "                          the current server.\n"
            "\n"
            "    list users         -- User and mailbox management.\n"
            "    create user\n"
            "    delete user\n"
            "    change password\n"
            "    create mailbox\n"
            "    delete mailbox\n\n"
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
