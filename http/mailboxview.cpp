// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailboxview.h"

#include "allocator.h"
#include "mailbox.h"
#include "fetcher.h"
#include "message.h"
#include "event.h"
#include "dict.h"
#include "map.h"


class MailboxViewBouncer: public EventHandler
{
public:
    MailboxViewBouncer( MailboxView * view )
        : v( view )
    {}

    void execute() {
        v->refresh( 0 );
    }

    MailboxView * v;
};


class MailboxViewData
    : public Garbage
{
public:
    MailboxViewData()
        : uidnext( 0 ), bouncer( 0 )
    {}

    uint uidnext;
    List<Message> messages;
    List<EventHandler> owners;
    Dict<MailboxView::Thread> subjects;
    List<MailboxView::Thread> threads;
    MailboxViewBouncer * bouncer;
    List<Message>::Iterator firstUnthreaded;
};


/*! \class MailboxView mailboxview.h

    The MailboxView class models a webmail client's view of a mailbox.
    It subclasses Session and provides threading, so Page can show the
    messages sorted by subject.
*/


/*! Constructs an MailboxView looking at the Mailbox \a m. Initially
    the new MailboxView is not ready().

    It's generally better to call find() than the constructor.
*/

MailboxView::MailboxView( Mailbox * m )
    : Session( m, true ), d( new MailboxViewData )
{
}


/*! Refreshes this MailboxView and calls EventHandler::execute() on \a
    owner as soon as this object is ready().

    If the object is ready() already (often the case when there are no
    new messages), EventHandler::execute() is not called.

    If several objects all call refresh(), all of them are notified.
*/

void MailboxView::refresh( EventHandler * owner )
{
    if ( owner && !d->owners.find( owner ) )
        d->owners.append( owner );

    if ( !d->bouncer )
        d->bouncer = new MailboxViewBouncer( this );

    if ( ( initialised() && uidnext() < mailbox()->uidnext() ) ||
         uidnext() == 0 )
    {
        Session::refresh( d->bouncer );
        return;
    }

    List<Message> newMessages;

    while ( d->uidnext < uidnext() ) {
        uint n = msn( d->uidnext );
        if ( n ) {
            Message * msg = new Message;
            msg->setUid( d->uidnext );
            d->messages.append( msg );
            newMessages.append( msg );

            if ( !d->firstUnthreaded )
                d->firstUnthreaded = d->messages.last();

            n++;
            if ( uid( n ) )
                d->uidnext = uid( n );
            else
                d->uidnext = uidnext();
        }
        else {
            d->uidnext++;
        }
    }

    if ( !newMessages.isEmpty() ) {
        Fetcher * f = new MessageHeaderFetcher( mailbox(), &newMessages,
                                                d->bouncer );
        f->execute();
        f = new MessageAddressFetcher( mailbox(), &newMessages, d->bouncer );
        f->execute();
    }

    while ( d->firstUnthreaded &&
            d->firstUnthreaded->hasHeaders() &&
            d->firstUnthreaded->hasAddresses() )
    {
        threadMessage( d->firstUnthreaded );
        ++d->firstUnthreaded;
    }

    if ( !ready() )
        return;

    List<EventHandler>::Iterator it( d->owners );
    while ( it ) {
        EventHandler * ev = it;
        d->owners.take( it );
        ev->execute();
    }
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

    if ( d->firstUnthreaded )
        return false;

    return true;
}


/*! This private helper adds message \a m to the thread datastructures.
*/

void MailboxView::threadMessage( Message * m )
{
    HeaderField * hf = m->header()->field( HeaderField::Subject );
    String subject;
    if ( hf )
        subject = Message::baseSubject( hf->data().simplified() );
    Thread * t = d->subjects.find( subject );
    if ( !t ) {
        t = new Thread;
        d->subjects.insert( subject, t );
        d->threads.append( t );
    }
    t->m.append( m );
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
    String s( Message::baseSubject( subject ) );
    Thread * t = d->subjects.find( subject );
    if ( t )
        return t;

    t = new Thread;
    d->subjects.insert( s, t );
    d->threads.append( t );
    return t;
}


/*! Returns the MailboxView::Thread that contains \a uid. If no thread
    contains \a uid, this function returns a null pointer.
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
