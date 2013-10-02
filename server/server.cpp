// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

// getpwnam
#include <pwd.h>
// getgrnam
#include <grp.h>
// write, getpid, getdtablesize, close, dup, getuid, geteuid, chroot,
// chdir, setregid, setreuid, fork
#include <unistd.h>
// open, O_RDWR
#include <sys/stat.h>
#include <fcntl.h>
// opendir
#include <dirent.h>
// exit
#include <stdlib.h>
// errno
#include <errno.h>
// fork
#include <sys/types.h>
// fprintf, stderr
#include <stdio.h>
// sigaction, sigemptyset
#include <signal.h>
// waitpid()
#include <sys/types.h>
#include <sys/wait.h>
// time()
#include <time.h>
// trunc()
#include <math.h>

// our own includes, _after_ the system header files. lots of system
// header files break if we've already defined UINT_MAX, etc.

#include "server.h"

#include "log.h"
#include "file.h"
#include "scope.h"
#include "estring.h"
#include "logclient.h"
#include "eventloop.h"
#include "connection.h"
#include "configuration.h"
#include "eventloop.h"
#include "allocator.h"
#include "resolver.h"
#include "entropy.h"
#include "query.h"


class ServerData
    : public Garbage
{
public:
    ServerData( const char * n )
        : name( n ), stage( Server::Configuration ),
          secured( false ), fork( false ), useCache( USECACHE ),
          chrootMode( Server::JailDir ),
          queries( new List< Query > ),
          children( 0 ),
          mainProcess( false )
    {}

    EString name;
    Server::Stage stage;
    EString configFile;
    bool secured;
    bool fork;
    bool useCache;
    Server::ChrootMode chrootMode;
    List< Query > *queries;
    List<pid_t> * children;
    bool mainProcess;
};


ServerData * Server::d;


/*! \class Server server.h

    The Server class performs the server startup functions that are
    common to most/all Archiveopteryx servers. The functions are
    performed in a fixed order - you call setup( x ) to continue up to
    stage x, then return.
*/


/*! Constructs a Server for \a name. \a name will be used for the pid
    file, etc. \a argc and \a argv are parsed to find command-line
    options.
*/

Server::Server( const char * name, int argc, char * argv[] )
{
    d = new ServerData( name );
    Allocator::addEternal( d, "Server data" );

    bool uc = false;
    int c;
    while ( (c=getopt( argc, argv, "fc:C" )) != -1 ) {
        switch ( c ) {
        case 'f':
            if ( d->fork ) {
                fprintf( stderr, "%s: -f specified twice\n", name );
                exit( 1 );
            }
            d->fork = true;
            break;
        case 'c':
            if ( !d->configFile.isEmpty() ) {
                fprintf( stderr, "%s: -c specified twice\n", name );
                exit( 1 );
            }
            else {
                d->configFile = optarg;
                File tmp( d->configFile );
                if ( !tmp.valid() ) {
                    fprintf( stderr,
                             "%s: Config file %s not accessible/readable\n",
                             name, tmp.name().cstr() );
                    exit( 1 );
                }
            }
            break;
        case 'C':
            // -C is undocumented on purpose. it should not change
            // anything except performance, and exists only for
            // testing.
            d->useCache = !d->useCache;
            uc = true;
            break;
        default:
            exit( 1 );
            break;
        }
    }
    if ( argc > optind ) {
        fprintf( stderr, "%s: Parse error for argument %d (%s)\n",
                 name, optind, argv[optind] );
        exit( 1 );
    }
    if ( uc || !d->useCache )
        fprintf( stdout, "%s: Will%s use caches\n",
                 name, d->useCache ? "" : " not" );
}


/*! Notifies the Server that it is to chroot according to \a mode. If
    \a mode is JailDir, secure() will chroot into the jail directory
    and check that '/' is inaccesssible. If \a mode is LogDir,
    secure() will chroot into the logfile directory, where the server
    hopefully can access the logfile.
*/

void Server::setChrootMode( ChrootMode mode )
{
    d->chrootMode = mode;
}


/*! Performs server setup for each stage up to but NOT including \a s. */

void Server::setup( Stage s )
{
    try {
        while ( d->stage < s ) {
            switch ( d->stage ) {
            case Configuration:
                configuration();
                break;
            case NameResolution:
                nameResolution();
                break;
            case Files:
                files();
                break;
            case LogSetup:
                logSetup();
                break;
            case Loop:
                loop();
                break;
            case Report:
                // This just gives us a good place to stop in main.
                break;
            case Fork:
                fork();
                break;
            case PidFile:
                pidFile();
                break;
            case LogStartup:
                logStartup();
                break;
            case Secure:
                secure();
                break;
            case MaintainChildren:
                maintainChildren();
                break;
            case Finish:
                // nothing more here
                break;
            }
            d->stage = (Stage)(d->stage + 1);
        }
    } catch ( Exception e ) {
        // don't allocate memory or call anything here.
        const char * c = 0;
        switch (e) {
        case Invariant:
            c = "Invariant failed during server startup.";
            break;
        case Memory:
            c = "Out of memory during server startup.";
            break;
        case FD:
            c = "FD error during server startup.";
            break;
        };
        uint i = 0;
        while( c[i] )
            i++;
        int r = ::write( 2, c, i ) + ::write( 2, "\n", 1 );
        if ( r < INT_MAX )
            exit( 1 );
    }
}


/*! Reads server configuration, either from the default config file or
    from the one supplied in argc.
*/

void Server::configuration()
{
    if ( d->configFile.isEmpty() )
        Configuration::setup( "archiveopteryx.conf" );
    else
        Configuration::setup( d->configFile );
    if ( d->useCache && !Configuration::scalar( Configuration::MemoryLimit ) )
        d->useCache = false;
}


/*! Resolves any domain names used in the configuration file before we
    chroot.
*/

void Server::nameResolution()
{
    List<Configuration::Text>::Iterator i( Configuration::addressVariables() );
    while ( i ) {
        const EStringList & r
            = Resolver::resolve( Configuration::text( *i ) );
        if ( r.isEmpty() ) {
            log( EString("Unable to resolve ") +
                 Configuration::name( *i ) +
                 " = " + Configuration::text( *i ),
                 Log::Disaster );
        }
        ++i;
    }
    if ( !Log::disastersYet() )
        return;

    EStringList::Iterator e( Resolver::errors() );
    while ( e ) {
        log( *e );
        ++e;
    }
}


/*! Closes all files except stdout and stderr. Attaches stdin to
    /dev/null in case something uses it. stderr is kept open so
    that we can tell our daddy about any disasters.
*/

void Server::files()
{
    int s = getdtablesize();
    while ( s > 0 ) {
        s--;
        if ( s != 2 && s != 1 )
            close( s );
    }
    s = open( "/dev/null", O_RDWR );

    Entropy::setup();
}


/*! Creates the global logging context, and sets up a LogClient if no
    Logger has been created already.

    This also creates the Loop object, so that the LogClient doesn't
    feel alone in the world, abandoned by its parents, depressed and
    generally bad.
*/

void Server::logSetup()
{
    EventLoop::setup();
    if ( !Logger::global() )
        LogClient::setup( d->name );
    Scope::current()->setLog( new Log );
    log( name() + ", Archiveopteryx version " +
         Configuration::compiledIn( Configuration::Version ) );
    Allocator::setReporting( true );
}


static void shutdownLoop( int )
{
    Server::killChildren();
    if ( !EventLoop::global() ) {
        (void)alarm( 60 );
        return;
    }

    uint used = Allocator::inUse() / 1024 + Allocator::allocated() / 1024;
    uint limit = Configuration::scalar( Configuration::MemoryLimit );
    if ( used > limit )
        used = limit;
    uint shorter = trunc( 10797.0 * used / limit );

    EventLoop::global()->stop( 10800 - shorter );
    (void)alarm( 10800 - shorter );
}


static void dumpCoreAndGoOn( int )
{
    if ( fork() )
        return;

    // we're now a child process. we can dump core and the real server
    // will just go on.

    // do we need to do anything about the files? no? I think not.

    abort();
}


/*! Called by signal handling to kill any children started in fork(). */

void Server::killChildren()
{
    List<pid_t>::Iterator child( d->children );
    while ( child ) {
        if ( *child )
            ::kill( *child, SIGTERM );
        ++child;
    }
}


/*! Initializes the global event loop. */

void Server::loop()
{
    struct sigaction sa;
    sa.sa_handler = 0;
    sa.sa_sigaction = 0; // may be union with sa_handler above
    sigemptyset( &sa.sa_mask ); // we block no other signals
    sa.sa_flags = 0; // in particular, we don't want SA_RESETHAND

    // we cannot reread files, so we ignore sighup
    sa.sa_handler = SIG_IGN;
    ::sigaction( SIGHUP, &sa, 0 );

    // sigint and sigterm both should stop the server
    sa.sa_handler = shutdownLoop;
    ::sigaction( SIGINT, &sa, 0 );
    ::sigaction( SIGTERM, &sa, 0 );

    // sigpipe happens if we're writing to an already-closed fd. we'll
    // discover that it's closed a little later.
    sa.sa_handler = SIG_IGN;
    ::sigaction( SIGPIPE, &sa, 0 );

    // a custom signal to dump core and go on
    sa.sa_handler = dumpCoreAndGoOn;
    ::sigaction( SIGUSR1, &sa, 0 );

    // a custom signal to die, quickly, for last-resort exit
    sa.sa_handler = ::exit;
    ::sigaction( SIGALRM, &sa, 0 );
}


/*! Forks the server as required by -f and the configuration variable
    server-processes.

    If -f is specified, the parent exits in this function and does not
    return from this function.

    As many processes as specified by server-processes return.
*/

void Server::fork()
{
    if ( !d->fork )
        return;

    pid_t p = ::fork();
    if ( p < 0 ) {
        log( "Unable to fork. Error code " + fn( errno ),
             Log::Disaster );
        exit( 1 );
    } else if ( p > 0 ) {
        exit( 0 );
    }
}


/*! Writes the server's pid to an almost hardcoded pidfile. We don't
    lock the file, since most of these servers don't have a problem
    with multiple instances of themselves. The pidfile is just a
    convenience for tools like start-stop-daemon.
*/

void Server::pidFile()
{
    EString dir( Configuration::compiledIn( Configuration::PidFileDir ) );

    EString n = dir + "/" + d->name + ".pid";
    File f( n, File::Write );
    if ( f.valid() )
        f.write( fn( getpid() ) + "\n" );
    else
        log( "Unable to write to PID file " + n );
}


/*! Logs the startup details. By this time, the logger must be in
    working order.
*/

void Server::logStartup()
{
    log( "Starting server " + d->name +
         " (host " + Configuration::hostname() + ")" +
         " (pid " + fn( getpid() ) + ") " +
         EString( d->secured ? "securely" : "insecurely" ) );
}


/*! Loses all rights. Dies with an error if that isn't possible, or if
    anything fails.
*/

void Server::secure()
{
    if ( Configuration::present( Configuration::DbOwnerPassword ) ) {
        log( "db-owner-password specified in archiveopteryx.conf "
             "(should be in aoxsuper.conf)",
             Log::Disaster );
        exit( 1 );
    }
    bool security = Configuration::toggle( Configuration::Security );
    if ( !security ) {
        if ( getuid() == 0 || geteuid() == 0 )
            log( "Warning: Starting " + d->name + " insecurely as root" );
        d->secured = false;
        return;
    }

    EString user( Configuration::text( Configuration::JailUser ) );
    struct passwd * pw = getpwnam( user.cstr() );
    if ( !pw ) {
        log( "Cannot secure server " + d->name +
             " since " + user + " is not a valid login (says getpwnam())",
             Log::Disaster );
        exit( 1 );
    }
    if ( pw->pw_uid == 0 ) {
        log( "Cannot secure server " + d->name + " since " + user +
             " has UID 0",
             Log::Disaster );
        exit( 1 );
    }

    EString group( Configuration::text( Configuration::JailGroup ) );
    struct group * gr = getgrnam( group.cstr() );
    if ( !gr ) {
        log( "Cannot secure server " + d->name +
             " since " + group + " is not a valid group (says getgrnam())",
             Log::Disaster );
        exit( 1 );
    }

    EString cfn( d->configFile );
    if ( cfn.isEmpty() )
        cfn = Configuration::configFile();

    struct stat st;
    if ( stat( cfn.cstr(), &st ) < 0 ) {
        log( "Cannot stat configuration file " + cfn,
             Log::Disaster );
        exit( 1 );
    }
    if ( st.st_uid != pw->pw_uid ) {
        log( "Configuration file " + cfn +
             " must be owned by " + user +
             " (uid " + fn( pw->pw_uid ) + ")" +
             " (is owned by uid " +
             fn( st.st_uid ) + ")",
             Log::Disaster );
        exit( 1 );
    }
    if ( (gid_t)st.st_gid != (gid_t)gr->gr_gid ) {
        log( "Configuration file " + cfn +
             " must be in group " + user +
             " (gid " + fn( gr->gr_gid ) + ")" +
             " (is in gid " +
             fn( st.st_gid ) + ")",
             Log::Disaster );
        exit( 1 );
    }
    if ( (st.st_mode & 027) != 0 ) {
        log( "Configuration file " + cfn +
             " must be readable for user " + user + "/group " + group +
             " only (mode is " +
             fn( st.st_mode & 0777, 8 ) + ", should be " +
             fn( st.st_mode & 0740, 8 ) + ")",
             Log::Disaster );
        exit( 1 );
    }

    EString root;
    switch ( d->chrootMode ) {
    case JailDir:
        root = Configuration::text( Configuration::JailDir );
        break;
    case LogDir:
        root = Configuration::text( Configuration::LogFile );
        if ( root == "-" ) {
            root = Configuration::text( Configuration::JailDir );
        }
        else if ( root.startsWith( "syslog/" ) ) {
            root = "/";
        }
        else {
            uint i = root.length();
            while ( i > 0 && root[i] != '/' )
                i--;
            if ( i == 0 ) {
                log( "Cannot secure server " + d->name +
                     " since logfile does not contain '/'",
                     Log::Disaster );
                log( "Value of logfile: " + root, Log::Info );
                exit( 1 );
            }
            root.truncate( i );
        }
        break;
    }
    if ( chroot( root.cstr() ) ) {
        log( "Cannot secure server " + d->name + " since chroot( \"" +
             root + "\" ) failed with error " + fn( errno ),
             Log::Disaster );
        exit( 1 );
    }
    if ( chdir( "/" ) ) {
        log( "Cannot secure server " + d->name + " since chdir( \"/\" ) "
             "failed in jail directory (\"" + root + "\") with error " +
             fn( errno ),
             Log::Disaster );
        exit( 1 );
    }
    File::setRoot( root );

    if ( setregid( gr->gr_gid, gr->gr_gid ) ) {
        log( "Cannot secure server " + d->name + " since setregid( " +
             fn( gr->gr_gid ) + ", " + fn( gr->gr_gid ) + " ) "
             "failed with error " + fn( errno ),
             Log::Disaster );
        exit( 1 );
    }

    if ( setgroups( 1, (gid_t*)&(gr->gr_gid) ) ) {
        log( "Cannot secure server " + d->name + " since setgroups( 1, [" +
             fn( gr->gr_gid ) + "] ) failed with error " + fn( errno ),
             Log::Disaster );
        exit( 1 );
    }

    if ( setreuid( pw->pw_uid, pw->pw_uid ) ) {
        log( "Cannot secure server " + d->name + " since setreuid( " +
             fn( pw->pw_uid ) + ", " + fn( pw->pw_uid ) + " ) "
             "failed with error " + fn( errno ),
             Log::Disaster );
        exit( 1 );
    }

    // one final check...
    if ( geteuid() != pw->pw_uid || getuid() != pw->pw_uid ) {
        log( "Cannot secure server " + d->name +
             " since setreuid() failed. Desired uid " +
             fn( pw->pw_uid ) + ", got uid " + fn( getuid() ) +
             " and euid " + fn( geteuid() ),
             Log::Disaster );
        exit( 1 );
    }

    // success
    log( "Secured server " + d->name + " using jail directory " + root +
         ", uid " + fn( pw->pw_uid ) + ", gid " + fn( gr->gr_gid ) );
    d->secured = true;
}


/*! Finishes setup and runs the main loop of the server. */

void Server::run()
{
    setup( Finish );
    Configuration::report();

    uint listeners = 0;
    List< Connection >::Iterator it( EventLoop::global()->connections() );
    while ( it ) {
        if ( it->type() == Connection::Listener )
            listeners++;
        ++it;
    }

    if ( listeners == 0 ) {
        log( "No active listeners. " + d->name + " exiting.", Log::Disaster );
        exit( 1 );
    }

    if ( Scope::current()->log()->disastersYet() ) {
        log( "Aborting server " + d->name + " due to earlier problems." );
        exit( 1 );
    }

    dup2( 0, 1 );
    if ( d->fork )
        dup2( 0, 2 );
    EventLoop::global()->start();

    if ( Scope::current()->log()->disastersYet() )
        exit( 1 );
    exit( 0 );
}


/*! This static function returns the name of the application.
    Is server the right way to publicise this name?
*/

EString Server::name()
{
    if ( d )
        return d->name;
    return "";
}


/*! Returns true if this server is configured to cache this and that,
    and false if it shouldn't cache.

    Running without cache is a debugging aid.
*/


bool Server::useCache()
{
    if ( d )
        return d->useCache;
    return false;
}


/*! Maintains the requisite number of children. Only child processes
    return from this function.
*/

void Server::maintainChildren()
{
    d->mainProcess = true;
    d->children = new List<pid_t>;
    uint children = 1;
    if ( d->name == "archiveopteryx" )
        children = Configuration::scalar( Configuration::ServerProcesses );
    uint i = 0;
    while ( i < children ) {
        d->children->append( new pid_t( 0 ) );
        i++;
    }
    uint failures = 0;
    while ( children > 1 && d->mainProcess ) {
        // check that all children exist
        List<pid_t>::Iterator c( d->children );
        while ( c ) {
            if ( *c ) {
                int r = ::kill( *c, 0 );
                if ( r < 0 && errno == ESRCH )
                    *c = 0;
            }
            ++c;
        }
        // add new children in each empty slot
        c = d->children->first();
        while ( c && d->mainProcess ) {
            if ( !*c ) {
                *c = ::fork();
                if ( *c < 0 ) {
                    log( "Unable to fork server; pressing on. Error code " +
                         fn( errno ), Log::Error );
                    *c = 0;
                }
                else if ( *c > 0 ) {
                    // the parent, all is well
                }
                else {
                    // a child. fork() must return.
                    d->mainProcess = false;
                }
            }
            ++c;
        }
        // wait() on the children, and look for rapid death syndrome
        if ( d->mainProcess ) {
            int status = 0;
            time_t now = time( 0 );
            pid_t child = ::waitpid( -1, &status, 0 );
            if ( child == (pid_t)-1 && errno == ECHILD ) {
                log( "Qutting due to unexpected lack of child processes.",
                     Log::Error );
                exit( 0 );
            }
            if ( time( 0 ) >= now + 5 ) {
                // not a failure, or the first in a long while
                failures = 0;
            }
            else if ( failures > 5 ) {
                log( "Quitting due to five failed children.",
                     Log::Error );
                exit( 0 ); // the children keep dying, best quit
            }
            else if ( failures ) {
                log( "Observed " + fn( failures ) + " failing children.",
                      Log::Error );
                failures++;
            }
            else {
                ::sleep( 1 );
                failures++;
            }
        }
    }

    // the mother never gets this far: by this time, we know we should
    // serve users.
    d->children = 0;
    EventLoop::global()->closeAllExceptListeners();
    log( "Process " + fn( getpid() ) + " started" );
    if ( Configuration::toggle( Configuration::UseStatistics ) ) {
        uint port = Configuration::scalar( Configuration::StatisticsPort );
        log( "Using port " + fn( port + i - 1 ) +
             " for statistics queries" );
        Configuration::add( "statistics-port = " + fn( port + i - 1 ) );
    }
}

