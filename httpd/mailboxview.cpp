// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailboxview.h"

#include "allocator.h"
#include "mailbox.h"
#include "message.h"
#include "event.h"
#include "dict.h"
#include "map.h"


class MailboxViewData
{
public:
    MailboxViewData()
        : unready( 0 ), working( false ) {}
    uint unready;
    bool working;
    Dict<MailboxView::Thread> subjects;
    List<MailboxView::Thread> threads;
};


/*! \class MailboxView mailboxview.h

   The MailboxView class models a webmail client's view of a
   mailbox. It subclasses Session and provides threading, so Page can
   show the messages sorted by subject.

   Additionally, it provides the utility function baseSubject(), which
   strips extras such as "Re:" and "(fwd)" off a string to find the
   presumed base subject of the message.
*/


/*! Constructs an MailboxView looking at the Mailbox \a m. Initially
    the new MailboxView is not ready().

    It's generally better to call find() than the constructor.
*/

MailboxView::MailboxView( Mailbox * m )
    : Session( m, true ), d( new MailboxViewData )
{
}


class MailboxViewBouncer: public EventHandler
{
public:
    MailboxViewBouncer( EventHandler * owner, MailboxView * view )
        : EventHandler(), o( owner ), v( view ) {
    }

    void execute() {
        if ( v->ready() )
            o->execute();
    }

    EventHandler * o;
    MailboxView * v;
};


/*! Refreshes this MailboxView and calls EventHandler::execute() on \a
    owner as soon as this object is ready().

    If the object is ready() already (often the case when there are no
    new messages), EventHandler::execute() is not called.

    If several objects all call refresh(), all of them are notified.
*/

void MailboxView::refresh( EventHandler * owner )
{
    if ( d->working || ready() )
        return;

    d->working = true;

    EventHandler * h = new MailboxViewBouncer( owner, this );

    MessageSet s;
    s.add( uidnext(), mailbox()->uidnext() - 1 );
    mailbox()->fetchHeaders( s, new MailboxViewBouncer( owner, this ) );

    Session::refresh( h );
}


/*! Returns true if we've fetched enough data from the database to
    thread the messages, and false if we haven't.

    In practice this function returns false for a while after object
    construction and after each refresh() call, then it returns true.
*/

bool MailboxView::ready()
{
    if ( !initialised() )
        return false;
    if ( !d->unready ) {
        if ( count() )
            d->unready = uid( 1 );
        else
            d->unready = uidnext();
    }
    while ( d->unready < uidnext() ) {
        Message * m = mailbox()->message( d->unready, false );
        if ( !m || !m->hasHeaders() )
            return false;
        threadMessage( d->unready, m );
        uint x = uid( msn( d->unready ) + 1 );
        if ( x < d->unready )
            x = uidnext();
        d->unready = x;
    }
    d->working = false;
    return true;
}


/*! Tries to remove the prefixes and suffixes used by MUAs from \a subject
    to find a base subject that can be used to tie threads together
    linearly.
*/

String MailboxView::baseSubject( const String & subject )
{
    String s( subject.simplified() );
    uint b = 0;
    uint e = s.length();

    // try to get rid of leading Re:, Fwd:, Re[2]: and similar.
    bool done = false;
    while ( !done ) {
        done = true;
        uint i = b;
        if ( s[i] == '(' ) {
            i++;
            while ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                    ( s[i] >= 'a' && s[i] <= 'z' ) )
                i++;
            if ( i - b > 2 && i - b < 5 && s[i] == ')' ) {
                done = false;
                b = i + 1;
            }
        }
        else if ( s[i] == '[' ) {
            uint j = i;
            i++;
            while ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                    ( s[i] >= 'a' && s[i] <= 'z' ) ||
                    ( s[i] >= '0' && s[i] <= '9' ) ||
                    s[i] == '-' )
                i++;
            if ( s[i] == ']' ) {
                i++;
                done = false;
                b = i;
            }
            else {
                i = j;
            }
        }
        else if ( s[i] >= 'A' && s[i] <= 'Z' ) {
            while ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                    ( s[i] >= 'a' && s[i] <= 'z' ) )
                i++;
            uint l = i - b;
            if ( s[i] == '[' ) {
                uint j = i;
                i++;
                while ( ( s[i] >= '0' && s[i] <= '9' ) )
                    i++;
                if ( s[i] == ']' )
                    i++;
                else
                    i = j;
            }
            if ( l >= 2 && l < 4 && s[i] == ':' && s[i+1] == ' ' ) {
                i++;
                b = i;
                done = false;
            }
        }
        if ( !done && s[b] == 32 )
            b++;
    }

    // try to get rid of trailing (Fwd) etc.
    done = false;
    while ( !done ) {
        done = true;
        uint i = e;
        if ( i > 2 && s[i-1] == ')' ) {
            i = i - 2;
            while ( i > 0 &&
                    ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                      ( s[i] >= 'a' && s[i] <= 'z' ) ) )
                i--;
            if ( e - i >= 4 && e - i < 6 && s[i] == '(' ) {
                if ( i >0 && s[i-1] == ' ' )
                    i--;
                e = i;
                done = false;
            }
        }
    }

    return s.mid( b, e-b );
}


/*! This private helper adds message \a m, which is assumed to have
     UID \a u to the thread datastructures.
*/

void MailboxView::threadMessage( uint u, Message * m )
{
    HeaderField * hf = m->header()->field( HeaderField::Subject );
    String subject;
    if ( hf )
        subject = baseSubject( hf->data().simplified() );
    Thread * t = d->subjects.find( subject );
    if ( !t ) {
        t = new Thread;
        d->subjects.insert( subject, t );
        d->threads.append( t );
    }
    t->append( u, m );
}


static Map<MailboxView> * views;


/*! Returns a pointer to a MailboxView for \a m. If one already
    exists, find() returns a pointer to it, otherwise it creates and
    returns one.
*/

MailboxView * MailboxView::find( Mailbox * m )
{
    MailboxView * v = 0;
    if ( ::views )
        v = ::views->find( m->id() );
    if ( v )
        return v;

    v = new MailboxView( m );
    if ( !::views ) {
        ::views = new Map<MailboxView>;
        Allocator::addEternal( ::views, "mailbox views" );
    }
    ::views->insert( m->id(), v );
    return v;
}


/*! Returns the MailboxView::Thread for \a subject, creating a
    MailboxView::Thread object if necessary.
*/

MailboxView::Thread * MailboxView::thread( const String & subject )
{
    String s( baseSubject( subject ) );
    Thread * t = d->subjects.find( subject );
    if ( t )
        return t;

    t = new Thread;
    d->subjects.insert( s, t );
    d->threads.append( t );
    return t;
}


/*! Returns the MailboxView::Thread that starts at \a uid. If \a uid
    doesn't start a thread, this function returns a null pointer.
*/

MailboxView::Thread * MailboxView::thread( uint uid )
{
    List<MailboxView::Thread>::Iterator it( d->threads );
    while ( it && it->uid( 0 ) < uid )
        ++it;
    if ( it && it->uid( 0 ) == uid )
        return it;

    it = d->threads.first();
    while ( it && it->uid( 0 ) < uid ) {
        uint c = it->messages(); // O(n)
        uint n = 0;
        while ( n < c && it->uid( n ) < uid ) // O(n SQUARED)
            n++;
        if ( it->uid( n ) == uid )
            return it;
        ++it;
    }

    return 0;
}


/*! Returns a pointer to the list of threads. This list must not be
    changed.

    The return value is never a null pointer.
*/

List<MailboxView::Thread> * MailboxView::allThreads() const
{
    return &d->threads;
}
