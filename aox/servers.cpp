// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "servers.h"

#include "file.h"
#include "dict.h"
#include "timer.h"
#include "query.h"
#include "paths.h"
#include "buffer.h"
#include "endpoint.h"
#include "database.h"
#include "resolver.h"
#include "eventloop.h"
#include "connection.h"
#include "configuration.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>


static const char * buildinfo[] = {
#include "buildinfo.inc"
    ""
};


static const char * servers[] = {
    "logd", "tlsproxy", "archiveopteryx"
};
static const int nservers = sizeof( servers ) / sizeof( servers[0] );


static void error( const EString & s )
{
    fprintf( stderr, "%s\n", s.cstr() );
    exit( -1 );
}


static EString pidFile( const char * s )
{
    EString pf( Configuration::compiledIn( Configuration::PidFileDir ) );
    pf.append( "/" );
    pf.append( s );
    pf.append( ".pid" );
    return pf;
}


static int serverPid( const char * s )
{
    EString pf = pidFile( s );
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


class Path
    : public Garbage
{
public:
    enum Type {
        ReadableFile,
        ReadableDir,
        WritableFile,
        WritableDir,
        CreatableFile,
        CreatableSocket,
        ExistingSocket,
        JailDir
    };

    Path( const EString &, Type );
    bool checked;
    bool ok;
    void check();
    static bool allOk;

    Path * parent;
    const char * message;
    EStringList variables;
    EString name;
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
    EString name = Configuration::text( variable );
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
        p->variables.append( Configuration::name( variable ) );
        p = p->parent;
    }
}


static void addPath( Path::Type type,
                     Configuration::CompileTimeSetting variable )
{
    EString name = Configuration::compiledIn( variable );
    Path * p = paths.find( name );
    if ( name.startsWith( "/" ) ) {
        if ( !p ) {
            p = new Path( name, type );
            paths.insert( name, p );
        }
    }
}


static EString parentOf( const EString & name )
{
    uint i = name.length();
    while ( i > 0 && name[i] != '/' )
        i--;
    EString pn = name.mid( 0, i );
    if ( i == 0 )
        pn = "/";
    return pn;
}


Path::Path( const EString & s, Type t )
    : Garbage(),
      checked( false ), ok( true ),
      parent( 0 ), message( 0 ),
      name( s ), type( t )
{
    EString pn = parentOf( name );
    if ( pn.length() < name.length() ) {
        Path * p = paths.find( pn );
        if ( !p ) {
            if ( t == CreatableFile ||
                 t == WritableFile ||
                 t == CreatableSocket )
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
    case CreatableSocket:
        if ( exist &&
             !S_ISSOCK( st.st_mode ) &&
             !S_ISFIFO( st.st_mode ) )
            message = "is not a socket or FIFO";
        break;
    case ExistingSocket:
        if ( !exist ||
             !(S_ISSOCK( st.st_mode ) ||
               S_ISFIFO( st.st_mode ) ||
               st.st_mode & S_IFCHR ) )
            message = "is not a socket/FIFO";
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
    variables.removeDuplicates();
    EStringList::Iterator i( variables );
    while ( i ) {
        fprintf( stderr, " - affected variable: %s\n", i->cstr() );
        ++i;
    }
    ok = false;
    allOk = false;
}


static void checkFilePermissions()
{
    EString user( Configuration::text( Configuration::JailUser ) );
    struct passwd * pw = getpwnam( user.cstr() );
    if ( !pw )
        error( user + " (jail-user) is not a valid username." );
    if ( pw->pw_uid == 0 )
        error( user + " (jail-user) has UID 0." );

    EString group( Configuration::text( Configuration::JailGroup ) );
    struct group * gr = getgrnam( group.cstr() );
    if ( !gr )
        error( group + " (jail-group) is not a valid group." );

    Path::uid = pw->pw_uid;
    Path::gid = gr->gr_gid;
    Path::allOk = true;

    if ( Configuration::text( Configuration::MessageCopy ).lower() != "none" )
        addPath( Path::WritableDir, Configuration::MessageCopyDir );
    addPath( Path::JailDir, Configuration::JailDir );
    addPath( Path::ReadableFile, Configuration::TlsCertFile );
    addPath( Path::ExistingSocket, Configuration::EntropySource );
    EString lf = Configuration::text( Configuration::LogFile );
    if ( lf != "-" && !lf.startsWith( "syslog/" ) )
        addPath( Path::CreatableFile, Configuration::LogFile );
    addPath( Path::ReadableDir, Configuration::BinDir );
    addPath( Path::ReadableDir, Configuration::PidFileDir );
    addPath( Path::ReadableDir, Configuration::SbinDir );
    addPath( Path::ReadableDir, Configuration::ManDir );
    addPath( Path::ReadableDir, Configuration::LibDir );
    addPath( Path::ReadableDir, Configuration::InitDir );

    List<Configuration::Text>::Iterator
        it( Configuration::addressVariables() );
    while ( it ) {
        EString s( Configuration::text( *it ) );
        if ( s[0] == '/' &&
             ( *it == Configuration::DbAddress ||
               *it == Configuration::SmartHostAddress ) )
            addPath( Path::ExistingSocket, *it );
        else if ( s[0] == '/' )
            addPath( Path::CreatableSocket, *it );
        ++it;
    }

    Dict<Path>::Iterator i( paths );
    while ( i ) {
        i->check();
        ++i;
    }

    if ( !Path::allOk )
        error( "Checking as user " + user + " (uid " + fn( Path::uid ) +
               "), group " + group + " (gid " + fn( Path::gid ) + ")" );
}


static void checkListener( bool use,
                           Configuration::Text address,
                           Configuration::Scalar port,
                           const EString & description )
{
    if ( !use )
        return;

    EString a( Configuration::text( address ) );
    uint p( Configuration::scalar( port ) );

    EStringList addresses;
    if ( a.isEmpty() ) {
        addresses.append( "::" );
        addresses.append( "0.0.0.0" );
    }
    else {
        EStringList::Iterator it( Resolver::resolve( a ) );
        while ( it ) {
            addresses.append( *it );
            ++it;
        }
    }

    EStringList::Iterator it( addresses );
    while ( it ) {
        Endpoint e( *it, p );

        if ( !e.valid() )
            error( "Invalid address specified for " +
                   description + " = " + e.string().quoted() );

        if ( e.protocol() == Endpoint::Unix ) {
            fprintf( stderr,
                     "Warning: Configuring %s to point to a "
                     "Unix socket ('%s') is untested and not "
                     "recommended.\n", description.cstr(),
                     e.string().cstr() );
        }

        // We bind to that address (and port 0, to make bind assign
        // a random number) to see if it's a valid local address at
        // all. I can't see any way to check if we can listen to a
        // Unix socket here without upsetting anything that may be
        // listening to it already.

        Endpoint e2( e );
        e2.zeroPort();

        int s = 0;
        if ( e2.protocol() != Endpoint::Unix &&
             ( ( s = Connection::socket( e2.protocol() ) ) < 0 ||
               bind( s, e2.sockaddr(), e2.sockaddrSize() ) < 0 ) )
        {
            error( "Couldn't bind socket for " + description +
                   " = " + e2.string().quoted() );
        }
        if ( s > 0 )
            close( s );

        // I put code to connect to the specified address:port here,
        // but then took it out again. For one thing, it means that
        // the Starter needs to call the Checker with some parameter
        // that is forwarded here (which looks increasingly clumsy),
        // so that we can decide whether to try the connect or not.
        // But the other problem is that it isn't useful: if any of
        // the listen attempts fail, the server will not start; and
        // in that case, detecting the problem here won't be useful
        // (in restart, the server is running while we check).

        ++it;
    }
}


static void checkInetAddresses()
{
    checkListener(
        true,
        Configuration::LogAddress, Configuration::LogPort,
        "log-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseImap ),
        Configuration::ImapAddress, Configuration::ImapPort,
        "imap-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseImaps ),
        Configuration::ImapsAddress, Configuration::ImapsPort,
        "imaps-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UsePop ),
        Configuration::PopAddress, Configuration::PopPort,
        "pop-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseLmtp ),
        Configuration::LmtpAddress, Configuration::LmtpPort,
        "lmtp-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseSmtp ),
        Configuration::SmtpAddress, Configuration::SmtpPort,
        "smtp-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseSmtps ),
        Configuration::SmtpsAddress, Configuration::SmtpsPort,
        "smtps-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseSmtpSubmit ),
        Configuration::SmtpSubmitAddress, Configuration::SmtpSubmitPort,
        "smtp-submit-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseHttp ),
        Configuration::HttpAddress, Configuration::HttpPort,
        "http-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseSieve ),
        Configuration::ManageSieveAddress,
        Configuration::ManageSievePort,
        "managesieve-address:port"
    );

    checkListener(
        Configuration::toggle( Configuration::UseTls ),
        Configuration::TlsProxyAddress, Configuration::TlsProxyPort,
        "tlsproxy-address:port"
    );
}


static void checkMiscellaneous()
{
    if ( Configuration::toggle( Configuration::UseSmtp ) ||
         Configuration::toggle( Configuration::UseLmtp ) )
    {
        EString mc( Configuration::text( Configuration::MessageCopy ) );
        EString mcd( Configuration::text( Configuration::MessageCopyDir ) );
        if ( mc == "all" || mc == "errors" || mc == "delivered" ) {
            struct stat st;
            if ( mcd.isEmpty() )
                error( "message-copy-directory not set" );
            else if ( ::stat( mcd.cstr(), &st ) < 0 ||
                      !S_ISDIR( st.st_mode ) )
                error( "message-copy-directory is not a directory" );

            // We should also check that the directory is writable by
            // whatever user the server will be running as.
        }
        else if ( mc == "none" ) {
            if ( Configuration::present( Configuration::MessageCopyDir ) )
                fprintf( stderr, "Note: Disregarding message-copy-directory "
                         "(value %s) because message-copy is set to none\n",
                         mcd.cstr() );
        }
        else {
            error( "Invalid value for message-copy: " + mc );
        }
    }

    EString sA( Configuration::text( Configuration::SmartHostAddress ) );
    uint sP( Configuration::scalar( Configuration::SmartHostPort ) );

    if ( Configuration::toggle( Configuration::UseSmtp ) &&
         Configuration::scalar( Configuration::SmtpPort ) == sP &&
         ( Configuration::text( Configuration::SmtpAddress ) == sA ||
           ( Configuration::text( Configuration::SmtpAddress ) == "" &&
             sA == "127.0.0.1" ) ) )
    {
        error( "smarthost-address/port are the same as "
               "smtp-address/port" );
    }

    if ( Configuration::toggle( Configuration::UseLmtp ) &&
         Configuration::scalar( Configuration::LmtpPort ) == sP &&
         ( Configuration::text( Configuration::LmtpAddress ) == sA ||
           ( Configuration::text( Configuration::LmtpAddress ) == "" &&
             sA == "127.0.0.1" ) ) )
    {
        error( "smarthost-address/port are the same as "
               "lmtp-address/port" );
    }

    if ( Configuration::toggle( Configuration::UseSmtpSubmit ) &&
         Configuration::scalar( Configuration::SmtpSubmitPort ) == sP &&
         ( Configuration::text( Configuration::SmtpSubmitAddress ) == sA ||
           ( Configuration::text( Configuration::SmtpSubmitAddress ) == "" &&
             sA == "127.0.0.1" ) ) )
    {
        error( "smarthost-address/port are the same as "
               "smtp-submit-address/port" );
    }
}


class CheckerData
    : public Garbage
{
public:
    CheckerData()
        : verbose( 0 ), owner( 0 ), q( 0 ), done( false )
    {}

    int verbose;
    EventHandler * owner;
    Query * q;
    bool done;
};


/*! \class Checker servers.h
    Checks that the server configuration and environment are sensible.
    This class is meant to be shared by start/restart.
*/

/*! Creates a new Checker for \a owner. If \a verbose is >0, then
    explanatory messages are printed in addition to any errors that
    may occur.
*/

Checker::Checker( int verbose, EventHandler * owner )
    : d( new CheckerData )
{
    d->verbose = verbose;
    d->owner = owner;
}


/*! Performs various configuration checks, and notifies the owner when
    they are done() or if something failed().
*/

void Checker::execute()
{
    if ( !d->q ) {
        Database::setup( 1 );

        checkFilePermissions();
        checkInetAddresses();
        checkMiscellaneous();

        d->q = new Query( "select login from users where "
                          "lower(login)='anonymous'", this );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    if ( d->q->failed() )
        error( "Couldn't execute a simple Postgres query: " +
               d->q->error() );

    Row * r = d->q->nextRow();
    if ( r ) {
        if ( !Configuration::toggle( Configuration::AuthAnonymous ) )
            fprintf( stderr, "Note: auth-anonymous is disabled, but "
                     "there is an anonymous user.\nThe anonymous user "
                     "will not be used. You may wish to delete it:\n\n"
                     "\taox delete user anonymous\n" );
    }
    else {
        if ( Configuration::toggle( Configuration::AuthAnonymous ) )
            fprintf( stderr, "Note: auth-anonymous is enabled, but will "
                     "not work, because there is no anonymous user,\nYou "
                     "may want to add one with:\n\n"
                     "\taox add user anonymous anonymous "
                     "anon@example.org\n" );
    }

    d->done = true;
    d->owner->execute();
}


/*! Returns true if this Checker has finished its work (successfully or
    otherwise), and false if it is still working.
*/

bool Checker::done() const
{
    return d->done;
}


/*! Returns true if this Checker found a problem with the configuration
    that merits more than a warning, and false otherwise, in which case
    it is safe to continue to stop or start the servers.
*/

bool Checker::failed() const
{
    return false;
}


class StarterData
    : public Garbage
{
public:
    StarterData()
        : verbose( 0 ), owner( 0 ), done( false )
    {}

    int verbose;
    EventHandler * owner;
    bool done;
};


/*! \class Starter servers.h
    Starts the servers.
*/

/*! Creates a new Starter for \a owner. If \a verbose is >0, then
    explanatory messages are printed in addition to any errors that
    may occur.
*/

Starter::Starter( int verbose, EventHandler * owner )
    : d( new StarterData )
{
    d->verbose = verbose;
    d->owner = owner;
}


/*! Starts the servers, and notifies the owner when they are done() or
    if something failed().
*/

void Starter::execute()
{
    EString sbin( Configuration::compiledIn( Configuration::SbinDir ) );
    if ( chdir( sbin.cstr() ) < 0 )
        error( "Couldn't chdir to SBINDIR (" + sbin + ")" );

    int i = 0;
    bool started = false;
    while ( i < nservers )
        if ( startServer( servers[i++] ) )
            started = true;

    if ( !started )
        printf( "No processes need to be started.\n" );

    d->done = true;
    d->owner->execute();
}


/*! Starts the server named \a s and returns true, or false if the
    server did not need to be started.
*/

bool Starter::startServer( const char * s )
{
    EString srv( Configuration::compiledIn( Configuration::SbinDir ) );
    srv.append( "/" );
    srv.append( s );

    bool use = true;

    EString t( s );
    if ( t == "tlsproxy" )
        use = Configuration::toggle( Configuration::UseTls );
    else if ( t == "logd" )
        use = Configuration::present( Configuration::LogFile ) &&
              !Configuration::text(
                  Configuration::LogFile ).startsWith( "syslog/" );
    else if ( t == "archiveopteryx" )
        use = Configuration::toggle( Configuration::UseImap ) ||
              Configuration::toggle( Configuration::UseImaps ) ||
              Configuration::toggle( Configuration::UseSmtp ) ||
              Configuration::toggle( Configuration::UseLmtp ) ||
              Configuration::toggle( Configuration::UseHttp ) ||
              Configuration::toggle( Configuration::UsePop );
    // that big use looks like a configuration sanity check to me...

    if ( !use ) {
        if ( d->verbose > 0 )
            printf( "Don't need to start %s\n", srv.cstr() );
        return false;
    }

    int p = serverPid( s );
    if ( p != -1 ) {
        if ( kill( p, 0 ) != 0 && errno == ESRCH ) {
            File::unlink( pidFile( s ) );
        }
        else {
            if ( d->verbose > 0 )
                printf( "%s(%d) is already running\n", s, p );
            return false;
        }
    }

    if ( d->verbose > 0 )
        printf( "Starting %s\n", srv.cstr() );

    pid_t pid = fork();
    if ( pid < 0 ) {
        error( "Couldn't fork to exec(" + srv + ")" );
    }
    else if ( pid == 0 ) {
        execl( srv.cstr(), srv.cstr(), "-f", (char *)NULL );
        exit( -1 );
    }
    else {
        int status = 0;
        if ( waitpid( pid, &status, 0 ) < 0 ||
             ( WIFEXITED( status ) && WEXITSTATUS( status ) != 0 ) )
            error( "Couldn't exec(" + srv + ")" );
    }

    return true;
}


/*! Returns true if this Starter has finished its work (successfully or
    otherwise), and false if it is still working.
*/

bool Starter::done() const
{
    return d->done;
}


/*! Returns true if this Starter failed to start the servers, and false
    if the servers were started successfully.
*/

bool Starter::failed() const
{
    return false;
}



class ServerPinger
    : public Connection
{
public:
    ServerPinger( Configuration::Text a, Configuration::Scalar p,
                  EventHandler * owner )
        : Connection(), up( false ), o( owner ) {
        EString addr;
        if ( Configuration::text( a ).isEmpty() ) {
            addr = "127.0.0.1";
        }
        else {
            EStringList::Iterator it(
                Resolver::resolve( Configuration::text( a ) ) );
            if ( it )
                addr = *it;
        }
        if ( addr.isEmpty() ) {
            up = false;
        }
        else {
            connect( Endpoint( addr, Configuration::scalar( p ) ) );
            EventLoop::global()->addConnection( this );
        }
    }
    void react( Event e ) {
        switch ( e ) {
        case Read:
        case Timeout:
        case Shutdown:
            break;

        case Connect:
            setState( Closing );
            up = true;
            break;

        case Error:
            setState( Closing );
            up = false;
            break;

        case Close:
            up = false;
            break;
        }
        o->execute();
    }
    bool probing() const {
        if ( up )
            return false;
        if ( state() == Connecting )
            return true;
        return false;
    }
    bool serverUp() const {
        return up;
    }
    bool up;
    EventHandler * o;
};


class StopperData
    : public Garbage
{
public:
    StopperData()
        : state( 0 ), verbose( 0 ), owner( 0 ), timer( 0 ),
          done( false ), pingers( 0 )
    {
        int i = 0;
        while ( i < nservers )
            pids[i++] = 0;
    }

    int state;
    int verbose;
    EventHandler * owner;
    Timer * timer;
    int pids[nservers];
    bool done;
    List<ServerPinger> * pingers;
};


/*! \class Stopper servers.h
    Stops the running servers.
*/

/*! Creates a new Stopper for \a owner. If \a verbose is >0, then
    explanatory messages are printed in addition to any errors that
    may occur.
*/

Stopper::Stopper( int verbose, EventHandler * owner )
    : d( new StopperData )
{
    d->verbose = verbose;
    d->owner = owner;
}


/*! Performs various configuration checks, and notifies the owner when
    they are done() or if something failed().
*/

void Stopper::execute()
{
    // We decide what servers are running by looking at the pid files,
    // kill those servers with SIGTERM, try a few times to connect,
    // and if we still can connect after 2-3 seconds, then we use
    // SIGKILL.

    if ( d->state == 0 ) {
        // State 0: Send SIGTERM and see if that helps
        int i = 0;
        int n = 0;
        while ( i < nservers ) {
            d->pids[i] = serverPid( servers[nservers-i-1] );
            if ( d->pids[i] != -1 ) {
                if ( d->verbose > 0 && !n )
                    printf( "Stopping servers: " );
                n++;
                if ( d->verbose > 0 )
                    printf( "%s%s", servers[nservers-i-1],
                            i == nservers-1 ? "" : " " );
            }
            i++;
        }
        if ( d->verbose > 0 && n )
            printf( ".\n" );

        i = 0;
        while ( i < nservers ) {
            if ( d->pids[i] != -1 ) {
                if ( d->verbose > 1 )
                    printf( "Sending SIGTERM to %s (pid %d)\n",
                            servers[nservers-i-1], d->pids[i] );
                File::unlink( pidFile( servers[nservers-i-1] ) );
                kill( d->pids[i], SIGTERM );
            }
            i++;
        }

        if ( n > 0 ) {
            d->state = 1;
            d->timer = new Timer( this, 2 );
        }
        else {
            d->state = 2;
        }
    }

    if ( d->timer && !d->timer->active() && d->state < 2 ) {
        // Servers didn't cooperate. We send SIGKILL and see whether
        // that does the trick.
        int i = 0;
        while ( i < nservers ) {
            if ( d->pids[i] != -1 && kill( d->pids[i], 0 ) == 0 ) {
                if ( d->verbose > 1 )
                    printf( "Sending SIGKILL to %s (pid %d)\n",
                            servers[nservers-i-1], d->pids[i] );
                kill( d->pids[i], SIGKILL );
            }
            i++;
        }
        d->state = 2;
    }

    if ( d->state == 1 ) {
        // State 1: We try to connect to each server. If all attempts
        // are refused, we're done. If an attempt succeeds, we try
        // again. That's a busylock. The timer above will break it.

        if ( !d->pingers ) {
            d->pingers = new List<ServerPinger>;

            if ( Configuration::toggle( Configuration::UseImap ) )
                d->pingers->append(
                    new ServerPinger( Configuration::ImapAddress,
                                      Configuration::ImapPort, this ) );
            if ( Configuration::toggle( Configuration::UseTls ) )
                d->pingers->append(
                    new ServerPinger( Configuration::TlsProxyAddress,
                                      Configuration::TlsProxyPort, this ) );
            if ( Configuration::present( Configuration::LogFile ) &&
                 !Configuration::text(
                     Configuration::LogFile ).startsWith( "syslog/" ) )
                d->pingers->append(
                    new ServerPinger( Configuration::LogAddress,
                                      Configuration::LogPort, this ) );
        }

        List<ServerPinger>::Iterator i( d->pingers );
        while ( i ) {
            if ( i->probing() ) {
                return;
            }
            else if ( i->serverUp() ) {
                i = d->pingers->first();
                while ( i ) {
                    i->close();
                    EventLoop::global()->removeConnection( i );
                    ++i;
                }
                d->pingers = 0;
                (void)new Timer( this, 0 ); // this leaks memory
                return;
            }
            ++i;
        }
        if ( !i )
            d->state = 2;
    }

    if ( d->state < 2 )
        return;

    d->done = true;
    d->owner->execute();
}


/*! Returns true if this Stopper has finished its work (successfully or
    otherwise), and false if it is still working.
*/

bool Stopper::done() const
{
    return d->done;
}


/*! Returns true if this Stopper was unable to stop the servers, and
    false if the servers were stopped successfully.
*/

bool Stopper::failed() const
{
    return false;
}



static AoxFactory<CheckConfig>
f( "check", "config", "Check that the configuration is sane.",
   "    Synopsis: aox check config\n\n"
   "    Reads the configuration and reports any problems it finds.\n" );


/*! \class CheckConfig servers.h
    This class handles the "aox check config" command.
*/

CheckConfig::CheckConfig( EStringList * args )
    : AoxCommand( args )
{
}


void CheckConfig::execute()
{
    if ( !checker ) {
        parseOptions();
        end();

        checker = new Checker( opt( 'v' ), this );
        checker->execute();
    }

    if ( !checker->done() )
        return;

    finish();
}



class StartData
    : public Garbage
{
public:
    StartData()
        : checker( 0 ), starter( 0 )
    {}

    Checker * checker;
    Starter * starter;
};


static AoxFactory<Start>
f2( "start", "", "Start the server(s).",
    "    Synopsis: aox start [-v]\n\n"
    "    Starts Archiveopteryx and helper servers in the correct order.\n"
    "    The -v flag enables (slightly) verbose diagnostic output.\n" );


/*! \class Start servers.h
    This class handles the "aox start" command.
*/

Start::Start( EStringList * args )
    : AoxCommand( args ), d( new StartData )
{
}


void Start::execute()
{
    if ( !d->checker ) {
        parseOptions();
        end();

        EString pfd( Configuration::compiledIn( Configuration::PidFileDir ) );
        if ( pfd.startsWith( "/var/run/" ) ) {
            // /var/run is wiped out at boot on many systems, which can
            // bother us. so if our pidfiledir is in a subdirectory of
            // that, we'll create it as needed.
            uint l = 9;
            bool ok = true;
            bool any = false;
            while ( l <= pfd.length() ) {
                if ( l == pfd.length() || pfd[l] == '/' ) {
                    struct stat st;
                    if ( stat( pfd.mid( 0, l ).cstr(), &st ) < 0 ) {
                        int m = mkdir( pfd.mid( 0, l ).cstr(), 01777 );
                        int c = chmod( pfd.mid( 0, l ).cstr(), 01777 );
                        if ( m >= 0 && c >= 0 )
                            any = true;
                        if ( m < 0 || c < 0 )
                            ok = false;
                    }
                }
                ++l;
            }
            // this message probably disappears, but that's a general
            // problem - what should aox do about log messages before
            // logd is there?
            if ( any && ok )
                log( "Created pid file directory: " + pfd );
        }

        d->checker = new Checker( opt( 'v' ), this );
        d->checker->execute();
    }

    if ( !d->checker->done() )
        return;

    if ( !d->starter ) {
        if ( d->checker->failed() ) {
            finish();
            return;
        }

        d->starter = new Starter( opt( 'v' ), this );
        d->starter->execute();
    }

    if ( !d->starter->done() )
        return;

    finish();
}



static AoxFactory<Stop>
f3( "stop", "", "Start the server(s).",
    "    Synopsis: aox stop [-v]\n\n"
    "    Stops Archiveopteryx and helper servers in the correct order.\n"
    "    The -v flag enables (slightly) verbose diagnostic output.\n" );


/*! \class Stop servers.h
    This class handles the "aox stop" command.
*/

Stop::Stop( EStringList * args )
    : AoxCommand( args )
{
}


void Stop::execute()
{
    if ( !stopper ) {
        parseOptions();
        end();

        stopper = new Stopper( opt( 'v' ), this );
        stopper->execute();
    }

    if ( !stopper->done() )
        return;

    finish();
}



class RestartData
    : public Garbage
{
public:
    RestartData()
        : checker( 0 ), stopper( 0 ), starter( 0 )
    {}

    Checker * checker;
    Stopper * stopper;
    Starter * starter;
};


static AoxFactory<Restart>
f4( "restart", "", "Restart the servers.",
    "    Synopsis: aox restart [-v]\n\n"
    "    Restarts Archiveopteryx and its helpers in the correct order.\n"
    "    (Currently equivalent to start && stop.)\n\n"
    "    The -v flag enables (slightly) verbose diagnostic output.\n" );


/*! \class Restart servers.h
    This class handles the "aox restart" command.
*/

Restart::Restart( EStringList * args )
    : AoxCommand( args ), d( new RestartData )
{
}


void Restart::execute()
{
    if ( !d->checker ) {
        parseOptions();
        end();

        d->checker = new Checker( opt( 'v' ), this );
        d->checker->execute();
    }

    if ( !d->checker->done() )
        return;

    if ( !d->stopper ) {
        if ( d->checker->failed() ) {
            finish();
            return;
        }

        d->stopper = new Stopper( opt( 'v' ), this );
        d->stopper->execute();
    }

    if ( !d->stopper->done() )
        return;

    if ( !d->starter ) {
        if ( d->stopper->failed() ) {
            finish();
            return;
        }

        d->starter = new Starter( opt( 'v' ), this );
        d->starter->execute();
    }

    if ( !d->starter->done() )
        return;

    finish();
}



static AoxFactory<ShowStatus>
f5( "show", "status", "Display a summary of the running servers.",
    "    Synopsis: aox show status [-v]\n\n"
    "    Displays a summary of the running servers.\n"
    "    The -v flag enables (slightly) verbose diagnostic output.\n" );


/*! \class ShowStatus servers.h
    This class handles the "aox show status" command.
*/

ShowStatus::ShowStatus( EStringList * args )
    : AoxCommand( args )
{
    execute();
}


void ShowStatus::execute()
{
    parseOptions();
    end();

    printf( "Servers: " );
    if ( opt( 'v' ) > 0 )
        printf( "\n  " );

    int i = 0;
    while ( i < nservers ) {
        int pid = serverPid( servers[i] );
        printf( "%s", servers[i] );

        bool started = true;
        EString t( servers[i] );
        if ( t == "tlsproxy" )
            started = Configuration::toggle( Configuration::UseTls );

        const char * noState = started ? "not running" : "not started";

        if ( pid < 0 ) {
            printf( " (%s)", noState );
        }
        else if ( kill( pid, 0 ) != 0 && errno == ESRCH ) {
            if ( opt( 'v' ) > 0 )
                printf( " (%s, stale pidfile)", noState );
            else
                printf( " (%s)", noState );
        }
        else if ( opt( 'v' ) > 0 ) {
            printf( " (%d)", pid );
        }

        if ( i != nservers-1 ) {
            if ( opt( 'v' ) > 0 )
                printf( "\n  " );
            else
                printf( ", " );
        }
        i++;
    }

    if ( opt( 'v' ) == 0 )
        printf( "." );
    printf( "\n" );

    finish();
}



static AoxFactory<ShowBuild>
f6( "show", "build", "Display build settings.",
    "    Synopsis: aox show build\n\n"
    "    Displays the build settings used for this installation.\n"
    "    (As configured in Jamsettings.)\n" );


/*! \class ShowBuild servers.h
    This class handles the "aox show build" command.
*/

ShowBuild::ShowBuild( EStringList * args )
    : AoxCommand( args )
{
    execute();
}


void ShowBuild::execute()
{
    end();

    printf( "Archiveopteryx version %s, "
            "http://www.archiveopteryx.org/%s\n",
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
    printf( "SBINDIR = %s\n",
            Configuration::compiledIn( Configuration::SbinDir ) );
    printf( "MANDIR = %s\n",
            Configuration::compiledIn( Configuration::ManDir ) );
    printf( "LIBDIR = %s\n",
            Configuration::compiledIn( Configuration::LibDir ) );
    printf( "INITDIR = %s\n",
            Configuration::compiledIn( Configuration::InitDir ) );
    printf( "AOXUSER = %s\n",
            Configuration::compiledIn( Configuration::AoxUser ) );
    printf( "AOXGROUP = %s\n",
            Configuration::compiledIn( Configuration::AoxGroup ) );
    printf( "VERSION = %s\n",
            Configuration::compiledIn( Configuration::Version ) );

    finish();
}



static AoxFactory<ShowConfiguration>
f7( "show", "configuration", "Display configuration variables.",
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
    "      aox show cf -v imap-address\n" );

static AoxFactory<ShowConfiguration>
f8( "show", "cf", &f7 );

static AoxFactory<ShowConfiguration>
f9( "show", "conf", &f7 );


/*! \class ShowConfiguration servers.h
    This class handles the "aox show configuration" command.
*/

ShowConfiguration::ShowConfiguration( EStringList * args )
    : AoxCommand( args )
{
}


void ShowConfiguration::execute()
{
    SortedList<EString> output;

    parseOptions();
    EString pat = next();
    end();

    uint i = 0;
    while ( i < Configuration::NumScalars ) {
        Configuration::Scalar j = (Configuration::Scalar)i++;

        EString n( Configuration::name( j ) );
        EString v( fn( Configuration::scalar( j ) ) );
        addVariable( &output, n, v, pat, Configuration::present( j ) );
    }

    i = 0;
    while ( i < Configuration::NumToggles ) {
        Configuration::Toggle j = (Configuration::Toggle)i++;

        EString n( Configuration::name( j ) );
        EString v( Configuration::toggle( j ) ? "on" : "off" );
        addVariable( &output, n, v, pat, Configuration::present( j ) );
    }

    i = 0;
    while ( i < Configuration::NumTexts ) {
        Configuration::Text j = (Configuration::Text)i++;

        EString n( Configuration::name( j ) );
        EString v( Configuration::text( j ) );
        if ( j != Configuration::DbPassword &&
             j != Configuration::DbOwnerPassword ) {
            if ( !v.boring() )
                v = v.quoted();
            addVariable( &output, n, v, pat, Configuration::present( j ) );
        }
    }

    EStringList::Iterator it( output );
    while ( it ) {
        printf( "%s\n", it->cstr() );
        ++it;
    }

    finish();
}


/*! Adds the variable named \a n with value \a v to the output list
    \a l if it matches \a pat and is explicitly \a mentioned.
*/

void ShowConfiguration::addVariable( SortedList< EString > * l,
                                     EString n, EString v, EString pat,
                                     bool mentioned )
{
    int np = opt( 'p' );
    int nv = opt( 'v' );

    if ( ( pat.isEmpty() || n == pat ) &&
         ( np == 0 || mentioned ) )
    {
        EString * s = new EString;

        if ( nv == 0 ) {
            s->append( n );
            s->append( " = " );
        }
        s->append( v );
        l->insert( s );
    }
}
