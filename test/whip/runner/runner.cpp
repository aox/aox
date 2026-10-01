#include "runner.h"

#include "client.h"
#include "obliterator.h"

#include "allocator.h"
#include "eventloop.h"
#include "buffer.h"
#include "scope.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h> // sleep


TestRunner * runningRunner = 0;
List<TestScript> * waitingScripts = 0;

extern bool patient;
extern bool stopOnFailure;


class TestRunnerData
    : public Garbage
{
public:
    TestRunnerData()
        : scripts( 0 ),
          clients( new List<TestClient> ),
          active( 0 ),
          obliterator( 0 ),
          verbose( false )
        {}

    List<TestScript> * scripts;
    List<TestClient> * clients;
    TestClient * active;
    Obliterator * obliterator;
    EString expected;
    EString log;
    bool verbose;
};


/*! Constructs a test runner that will run through \a scripts and then
    disappear. If \a verbose is true, the runner dumps input and
    output to stdout even if no errors happen. If it's false, i/o is
    dumped to stderr, and only if an error happens.
*/

TestRunner::TestRunner( List<TestScript> * scripts, bool verbose )
    : d( new TestRunnerData )
{
    ::runningRunner = this;
    Allocator::addEternal( ::runningRunner, "the current test runner" );
    d->scripts = scripts;
    d->verbose = verbose;

    EString names( "running" );
    List<TestScript>::Iterator s( d->scripts );
    while ( s ) {
        names.append( " " );
        names.append( s->name() );
        ++s;
    }
    log( names );
    d->scripts->first()->start();
    log( " - running " + d->scripts->first()->name() );
    send();
}


static Log * globalLog = 0;


/*! Looks up the oldest waiting script and runs a TestRunner on it, \a
    verbose or not \a verbose.
*/

void TestRunner::run( bool verbose )
{
    if ( !::waitingScripts )
        return;

    if ( !::globalLog ) {
        ::globalLog = Scope::current()->log();
        Allocator::addEternal( ::globalLog, "the mother of all logs" );
    }
    Scope x( ::globalLog );

    List<TestScript>::Iterator s( ::waitingScripts );
    List<TestScript> * l = 0;
    while ( s && !l ) {
        l = new List<TestScript>;
        l->append( s );
        if ( !s->necessary() ) {
            fprintf( stderr,
                     "whip: skipping %s because it will be included "
                     "by a later script\n",
                     s->name().cstr() );
            l = 0;
        }
        else if ( s->failed() ) {
            fprintf( stderr,
                     "whip: skipping %s because it has failed already\n",
                     s->name().cstr() );
            l = 0;
        }
        while ( l && !l->first()->depends().isEmpty() ) {
            TestScript * p
                = TestScript::findProvider( l->first()->depends() );
            if ( !p ) {
                fprintf( stderr,
                         "whip: cannot execute script %s.\n"
                         "        %s requires state %s, which noone provides\n",
                         s->name().cstr(),
                         l->first()->name().cstr(),
                         l->first()->depends().cstr() );
                l = 0;
            }
            else if ( l->find( p ) ) {
                fprintf( stderr,
                         "whip: circular dependency for script %s.\n"
                         "        %s required twice.\n",
                         s->name().cstr(),
                         l->first()->name().cstr() );
                l = 0;
            }
            else if ( p->failed() ) {
                fprintf( stderr,
                         "whip: skipping %s because it depends on %s, "
                         "which is known to fail\n",
                         s->name().cstr(), p->name().cstr() );
                l = 0;
            }
            else if ( p->broken() ) {
                fprintf( stderr,
                         "whip: skipping %s because it depends on %s, "
                         "which is marked as broken\n",
                         s->name().cstr(), p->name().cstr() );
                l = 0;
            }
            if ( l && p )
                l->prepend( p );
        }
        ::waitingScripts->take( s );
    }
    if ( !l ) {
        EventLoop::global()->stop();
        return;
    }

    (void)new TestRunner( l, verbose );
}


/*! Logs a successful finish and closes. */

void TestRunner::finish()
{
    if ( ::runningRunner != this )
        return;

    log( "succesfully finished" );
    close( false );
}


/*! Closes this test runner and optionally starts a new, assuming
    there's a new one waiting. If \a verbose is true, close() dumps
    the entire log (unless it's been done already because of -v).

    At the moment, we pick the oldest waiting runner, ie. the one that
    was parsed first and hasn't yet been executed yet. We might want
    to pick a random one instead.
*/

void TestRunner::close( bool verbose )
{
    d->active = 0;

    List<TestClient>::Iterator ci( d->clients );
    while ( ci ) {
        ci->close();
        ++ci;
    }

    if ( verbose && !d->verbose ) {
        write( 2, d->log.data(), d->log.length() );
        write( 2, "\n", 1 );
    }

    Allocator::removeEternal( ::runningRunner );
    ::runningRunner = 0;
    EventLoop::freeMemorySoon();
    if ( verbose && stopOnFailure )
        EventLoop::global()->stop();
    else
        run( d->verbose );
}


/*! Processes server output, timeouts etc. and sends new input to the
    server. \a e is either server information or a 10-second timeout.
*/

void TestRunner::react( Connection::Event e, TestClient * c )
{
    if ( ::runningRunner != this )
        return;

    List<TestClient>::Iterator i( d->clients );
    while ( i && i != c )
        ++i;
    if ( !i )
        return; // it's one we've discarded

    switch ( e ) {
    case Connection::Read:
        if ( c->state() == Connection::Listening ) {
            accept( c );
            return;
        }
        if ( c != d->active ) {
            return;
        }
        compare();
        break;

    case Connection::Timeout:
        if ( c != d->active )
            return;
        error( "No response after 10 seconds" );
        if ( d->scripts->first() )
            d->scripts->first()->setFailed( true );
        break;

    case Connection::Connect:
        log( "Connected: " + c->name() + " (fd " + fn( c->fd() ) + ")" );
        if ( d->expected.isEmpty() )
            send();
        else if ( !patient ) {
            c->setTimeoutAfter( 15 );
            log( "Timeout set: 15s after connect on " + c->name() );
        }
        break;

    case Connection::Error:
        error( "Unexpected network error" );
        if ( d->scripts->first() )
            d->scripts->first()->setFailed( true );
        break;

    case Connection::Close:
        d->clients->take( i );
        if ( c == d->active &&
             d->scripts->first() &&
             d->scripts->first()->action() == TestScript::Close &&
             d->scripts->first()->clientName() == c->name() ) {
            log( "Connection closed: " + c->name() );
            return;
        }

        if ( !d->expected.isEmpty() ) {
            error( "Unexpected network close: " + c->name() );
            if ( d->scripts->first() )
                d->scripts->first()->setFailed( true );
        }
        else {
            send();
        }
        break;

    case Connection::Shutdown:
        log( "Memory pressure closed connection: " + c->name() );
        if ( d->scripts->first() )
            d->scripts->first()->setFailed( true );
        close( true );
        return;
    }
}


/*! Returns true if \a pattern matches \a actual starting at positions
    \a pi and \a ai respectively. "..." in the pattern matches any
    sequence of zero or more characters.
*/

static bool matchLine( const EString & pattern, uint pi,
                       const EString & actual, uint ai )
{
    while ( true ) {
        if ( pi + 2 < pattern.length() &&
             pattern[pi] == '.' && pattern[pi+1] == '.' &&
             pattern[pi+2] == '.' ) {
            pi += 3;
            for ( uint i = ai; i <= actual.length(); i++ )
                if ( matchLine( pattern, pi, actual, i ) )
                    return true;
            return false;
        }
        if ( pi == pattern.length() )
            return ai == actual.length();
        if ( ai == actual.length() )
            return false;
        if ( pattern[pi] != actual[ai] )
            return false;
        pi++;
        ai++;
    }
}


/*! Reads server output, compares it against the expected text and
    sends any commands that may now be sent. Logs errors.
*/

void TestRunner::compare()
{
    bool any = false;
    uint errors = 0;
    EString * r = d->active->readBuffer()->removeLine( );
    while ( r ) {
        any = true;
        r->append( "\r\n" );
        EString ll( "<<  " );
        ll.append( *r );
        log( ll );
        int cr = d->expected.find( '\n' ) + 1;
        if ( cr <= 0 )
            cr = r->length();
        EString el = d->expected.mid( 0, cr );
        d->expected = d->expected.mid( cr );
        if ( !matchLine( el, 0, *r, 0 ) ) {
            EString ll( "*** " );
            ll.append( el );
            if ( el.isEmpty() )
                ll.append( "\n" );
            log( ll );
            errors++;
        }
        r = d->active->readBuffer()->removeLine( );
    }
    if ( errors ) {
        error( "Server output error" );
        if ( d->scripts->first() )
            d->scripts->first()->setFailed( true );
        return;
    }
    else if ( any && !patient ) {
        d->active->setTimeoutAfter( 10 );
        log( "Timeout set: 10s after compare on " + d->active->name() );
    }
    if ( !d->expected.isEmpty() )
        return;
    if ( d->active->readBuffer()->size() )
        log( "Note: Read buffer contains " +
             fn( d->active->readBuffer()->size() ) +
             " bytes, even though we're not expecting anything" );
    TestScript * s = d->scripts->first();
    if ( !s )
        return;
    send();
    if ( !d->expected.isEmpty() )
        return;
    if ( s->action() != TestScript::Done )
        return;
    d->scripts->shift();
    if ( d->scripts->isEmpty() ) {
        finish();
    }
    else {
        d->scripts->first()->start();
        log( " - running " + d->scripts->first()->name() );
        if ( d->expected.isEmpty() )
            send();
    }
}


/*! Emits an error \a message and everything that led up to it. */

void TestRunner::error( EString message )
{
    if ( ::runningRunner != this )
        return;

    log( d->scripts->first()->name() + ": Error: " + message );
    close( true );
}


/*! Logs \a s as something that occured while testing. This is emitted
    in its proper place if an error occurs.
*/

void TestRunner::log( EString s )
{
    EString ll( s );
    if ( !ll.endsWith( "\n" ) )
        ll.append( "\n" );

    if ( d->verbose )
        write( 2, ll.data(), ll.length() );
    else
        d->log.append( ll );
}


/*! Returns true if a runner is running, and false if not. */

bool TestRunner::running()
{
    return ::runningRunner;
}


/*! Sends text to the IMAP server, if it's now our turn to speak, and
    remembers what the IMAP servers should answer.
*/

void TestRunner::send()
{
    if ( d->obliterator ) {
        if ( !d->obliterator->done() )
            return;
        if ( d->clients && !d->clients->isEmpty() )
            return;
        if ( !d->obliterator->error().isEmpty() ) {
            error( "Obliteration error: " + d->obliterator->error() );
            return;
        }
        log( "Obliteration completed." );
        d->obliterator = 0;
    }
    TestScript * s = 0;
    do {
        s = d->scripts->first();
        if ( !s )
            return;
        if ( s->action() == TestScript::Close ) {
            List<TestClient>::Iterator i( d->clients );
            while ( i && i->name() != s->clientName() )
                ++i;
            if ( i ) {
                i->setState( Connection::Closing );
                d->clients->take( i );
            }
            else {
                error( "Close: no connection called " + s->clientName() );
            }
            s->step();
        }
        if ( s->action() == TestScript::Connect ) {
            EString srv( TestClient::serverAddress() );
            EString name( s->string() );
            EString proto( s->protocol() );
            TestClient * c = new TestClient( this, s->clientName() );
            d->clients->append( c );
            d->active = c;
            if ( proto == "imap" ) {
                c->connect( Endpoint( srv, 143 ) );
            }
            else if ( proto == "smtp" ) {
                c->connect( Endpoint( srv, 25 ) );
            }
            else if ( proto == "submit" ) {
                c->connect( Endpoint( srv, 587 ) );
            }
            else if ( proto == "lmtp" ) {
                c->connect( Endpoint( srv, 2026 ) );
            }
            else if ( proto == "pop3" ) {
                c->connect( Endpoint( srv, 110 ) );
            }
            else if ( proto == "managesieve" ) {
                c->connect( Endpoint( srv, 2000 ) );
            }
            else if ( proto == "ocd" ) {
                c->connect( Endpoint( srv, 2050 ) );
            }
            else {
                error( "no idea what port to use for protocol " +
                       proto.quoted() );
            }
            if ( !patient ) {
                c->setTimeoutAfter( 3 );
                log( "Timeout set: 3s after connect request on " +
                     c->name() );
            }
            log( "Connecting " + c->name() +
                 " to " + c->peer().address() +
                 " using fd " + fn( c->fd() ) );
            s->step();
        }
        else if ( s->action() == TestScript::Listen ) {
            log( "Listening on port " + fn( s->port() ) +
                 " for connection " + s->clientName() );
            TestClient * c = new TestClient( this, s->clientName() );
            d->clients->append( c );
            c->listen( Endpoint( TestClient::serverAddress(), s->port() ),
                       false );
            s->step();
        }
        else if ( s->action() == TestScript::Use ) {
            log( "Using connection " + s->clientName() );
            List<TestClient>::Iterator i( d->clients );
            while ( i && i->name() != s->clientName() )
                ++i;
            if ( i )
                d->active = i;
            else
                error( "Use: no connection called " + s->clientName() );
            s->step();
            if ( i->state() == Connection::Listening ) {
                if ( !patient ) {
                    i->setTimeoutAfter( 10 );
                    log( "Timeout set: 10s waiting for listen on " +
                         i->name() );
                }
                return;
            }
        }
        else if ( s->action() == TestScript::Obliterate ) {
            EString login = s->clientName();
            s->step();
            d->obliterator = new Obliterator( this, login );
            log( "Obliterating user " + login );
            return;
        }
        else if ( s->action() == TestScript::Send ) {
            EString tmp = s->string();
            s->step();
            if ( !d->active ) {
                error( "Need to send, but have no active connection" );
                return;
            }
            d->active->enqueue( tmp );
            uint i = 0;
            bool sol = true;
            EString ll;
            while ( i < tmp.length() ) {
                if ( sol )
                    ll.append( " >> " );
                sol = false;
                ll.append( tmp[i] );
                if ( tmp[i] == '\n' )
                    sol = true;
                i++;
            }
            log( ll );
            if ( !patient ) {
                d->active->setTimeoutAfter( 10 );
                log( "Timeout set: 10s after send on " +
                     d->active->name() );
            }
        }
    } while ( s && ( s->action() == TestScript::Close ||
                     s->action() == TestScript::Connect ||
                     s->action() == TestScript::Listen ||
                     s->action() == TestScript::Use ||
                     s->action() == TestScript::Obliterate ||
                     s->action() == TestScript::Send ) );
    while ( s->action() == TestScript::Receive ) {
        if ( !d->active ) {
            error( "Expect to receive, but have no active connection" );
            return;
        }
        d->expected.append( s->string() );
        s->step();
    }
    if ( d->active->readBuffer()->size() )
        compare();
}


/*! Adds \a s to the list of TestScript objects to be run. run() will
    later run it.
*/

void TestRunner::add( TestScript * s )
{
    if ( !::waitingScripts ) {
        ::waitingScripts = new List<TestScript>;
        Allocator::addEternal( ::waitingScripts, "scripts waiting to be run" );
    }
    ::waitingScripts->append( s );
}


/*! Accepts a single connection from \a c, gets rid of \a c and
    replaces \a c with the new TestClient.

*/

void TestRunner::accept( TestClient * c )
{
    TestClient * a = new TestClient( this, c->name(), c->accept() );
    a->setState( Connection::Connected );
    c->setState( Connection::Closing );
    d->clients->append( a );
    List<TestClient>::Iterator i( d->clients );
    while ( i && i != c )
        ++i;
    if ( i )
        d->clients->take( i );
    log( "Accepted connection on " + c->name() +
         " (fd " + fn( a->fd() ) + ")" );
    if ( d->active != c ) {
        TestScript * s = d->scripts->first();
        if ( s && s->action() == TestScript::Use &&
             s->clientName() == c->name() )
            send();
        return;
    }
    log( "Activating new connection" );
    i = d->clients->first();
    while ( i && i != a )
        ++i;
    d->active = i;
    a->setTimeout( c->timeout() );
    send();
}
