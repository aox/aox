// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "eventmap.h"

#include "transaction.h"
#include "integerset.h"
#include "mailbox.h"
#include "query.h"
#include "user.h"


class EventFilterSpecData
    : public Garbage
{
public:
    EventFilterSpecData()
        : Garbage(),
          type( EventFilterSpec::SelectedDelayed ),
          fetcher( 0 )
        {
            uint i = 0;
            while ( i <= EventFilterSpec::Subscription ) {
                notify[i] = false;
                ++i;
            }
        }
    EventFilterSpec::Type type;
    List<Mailbox> mailboxes;
    Fetch * fetcher;
    bool notify[EventFilterSpec::Subscription];
};


/*! \class EventFilterSpec eventmap.h

    The EventFilterSpec class is a helper for EventMap: It remembers
    what the client wants for a particular something (the selected
    mailbox, a subtree, etc.) EventMap and IMAP use that to notify the
    IMAP client about the kinds of events that interest it.
*/



/*! Constructs an empty EventFilterSpec with a strong omerta policy.
*/

EventFilterSpec::EventFilterSpec()
    : Garbage(), d( new EventFilterSpecData )
{
    // nothing
}


/*! Records \a t as the type. The initial value is SelectedDelayed.

*/

void EventFilterSpec::setType( Type t )
{
    d->type = t;
}


/*! Returns whatever setType() recorded. */

EventFilterSpec::Type EventFilterSpec::type() const
{
    return d->type;
}


/*! Records that this spec applies to \a mailboxes. The initial value
    is an empty list.

    EventMap::refresh() overwrites this for the Subscribed etc.
*/

void EventFilterSpec::setMailboxes( List<Mailbox> * mailboxes )
{
    d->mailboxes.clear();
    d->mailboxes.append( mailboxes );
}


/*! Returns whatever setMailboxes() recorded. This may be an empty
    list, but is never a null pointer.
*/

List<Mailbox> * EventFilterSpec::mailboxes() const
{
    return &d->mailboxes;
}


/*! Records that the client should be notified of new message events
    using \a f. The initial value is a null pointer; setting a null
    pointer is permissible.
*/

void EventFilterSpec::setNewMessageFetcher( class Fetch * f )
{
    d->fetcher = f;
}


/*! Records whatever setNewMessageFetcher() recorded.

*/

class Fetch * EventFilterSpec::newMessageFetcher() const
{
    return d->fetcher;
}


/*! Records that the client should be notified of events of \a type
    (if \a should is true) or not (if \a should is false). The initial
    value is... something.
*/

void EventFilterSpec::setNotificationWanted( Event type, bool should )
{
    d->notify[type] = should;
}


/*! Returns whatever setNotificationWanted() recorded for \a type. */

bool EventFilterSpec::notificationWanted( Event type )
{
    return d->notify[type];
}


/*! Returns true if \a mailbox is the list recorded by setMailboxes(),
    or if type() is Subtree and one of its parents is on that
    list. Returns false in all other cases.
*/

bool EventFilterSpec::appliesTo( Mailbox * mailbox )
{
    while ( mailbox ) {
        List<Mailbox>::Iterator i( d->mailboxes );
        while ( i && i != mailbox )
            ++i;
        if ( i )
            return true;
        if ( type() == Subtree )
            mailbox = mailbox->parent();
        else
            mailbox = 0;
    }
    return false;
}


class EventMapData
    : public Garbage
{
public:
    EventMapData(): Garbage(), 
                    t( 0 ),
                    inboxes( 0 ), personal( 0 ), subscribed( 0 ) {}

    List<EventFilterSpec> l;
    Transaction * t;
    Query * inboxes;
    Query * personal;
    Query * subscribed;
};


/*! \class EventMap eventmap.h

    The EventMap class describes what notifications are desired for a
    particular combination of event and mailbox(es). In principle
    notification for events can be toggled, but for some, a more
    complex setter/fetcher exists.

    EventMap doesn't actually do anything. It serves only to hold the
    desired settings.

    Most of the design is determined by RFC 5423 and RFC 5465.
*/


/*! Constructs an empty message event map. */

EventMap::EventMap()
    : EventHandler(), d( new EventMapData )
{
    // nothing
}


/*! Returns a pointer to the EventFilterSpec that applies to \a
    mailbox at the moment, or a null pointer if none do.

    If \a selected is non-null, then applicable() assumes that it
    points to the currently selected mailbox.
*/

EventFilterSpec * EventMap::applicable( Mailbox * mailbox, Mailbox * selected )
{
    List<EventFilterSpec>::Iterator i( d->l );
    while ( i ) {
        if ( selected && mailbox == selected &&
             ( i->type() == EventFilterSpec::Selected ||
               i->type() == EventFilterSpec::SelectedDelayed ) )
            return i;
        else if ( i->appliesTo( mailbox ) )
            return i;
        ++i;
    }
    return 0;
}


/*! Adds \a s to the filter specs in this event map. */

void EventMap::add( EventFilterSpec * s )
{
    d->l.append( s );
}


void EventMap::execute()
{
    if ( d->inboxes && !d->inboxes->done() )
        return;
    if ( d->personal && !d->personal->done() )
        return;
    if ( d->subscribed && !d->subscribed->done() )
        return;
    d->t = 0;
    List<Mailbox> * inboxes = new List<Mailbox>;
    List<Mailbox> * personal = new List<Mailbox>;
    List<Mailbox> * subscribed = new List<Mailbox>;
    if ( d->inboxes ) {
        while ( d->inboxes->hasResults() ) {
            Row * r = d->inboxes->nextRow();
            inboxes->append( Mailbox::find( r->getInt( "id" ) ) );
        }
        d->inboxes = 0;
    }
    if ( d->personal ) {
        while ( d->personal->hasResults() ) {
            Row * r = d->personal->nextRow();
            personal->append( Mailbox::find( r->getInt( "id" ) ) );
        }
        d->personal = 0;
    }
    if ( d->subscribed ) {
        while ( d->subscribed->hasResults() ) {
            Row * r = d->subscribed->nextRow();
            subscribed->append( Mailbox::find( r->getInt( "mailbox" ) ) );
        }
        d->subscribed = 0;
    }
    List<EventFilterSpec>::Iterator i( d->l );
    while ( i ) {
        if ( i->type() == EventFilterSpec::Inboxes )
            i->setMailboxes( inboxes );
        else if ( i->type() == EventFilterSpec::Personal )
            i->setMailboxes( personal );
        else if ( i->type() == EventFilterSpec::Subscribed )
            i->setMailboxes( subscribed );
        ++i;
    }
}


/*! Refreshes the mailbox lists in each of the filter specs using a
    subtransaction of \a t. Does nothing if already active. Uses \a u
    to interpret e.g. Inboxes.
*/

void EventMap::refresh( class Transaction * t, User * u )
{
    if ( d->t )
        return;
    d->t = t->subTransaction( this );
    List<EventFilterSpec>::Iterator i( d->l );
    while ( i ) {
        if ( i->type() == EventFilterSpec::Inboxes &&
             !d->inboxes ) {
            d->inboxes = new Query(
                "select m.id from mailboxes m "
                "join fileinto_targets ft on (m.id=ft.mailbox) "
                "where m.owner=$1 "
                "union "
                "select m.id from mailboxes m "
                "join aliases al on (m.id=al.mailbox) "
                "where m.owner=$1",
                this );
            d->inboxes->bind( 1, u->id() );
            d->t->enqueue( d->inboxes );
        }
        else if ( i->type() == EventFilterSpec::Personal &&
                  !d->personal ) {
            d->personal = new Query(
                "select m.id from mailboxes m "
                "where m.owner=$1",
                this );
            d->personal->bind( 1, u->id() );
            d->t->enqueue( d->personal );
        }
        else if ( i->type() == EventFilterSpec::Subscribed &&
                  !d->subscribed ) {
            d->subscribed = new Query(
                "select mailbox from subscriptions "
                "where owner=$1",
                this );
            d->subscribed->bind( 1, u->id() );
            d->t->enqueue( d->subscribed );
        }
        ++i;
    }
    d->t->commit();
}


static void add( List<Mailbox> * l, IntegerSet & in,
                 List<Mailbox> * s, bool r = false )
{
    List<Mailbox>::Iterator i( s );
    while ( i ) {
        if ( !i->deleted() && !in.contains( i->id() ) ) {
            in.add( i->id() );
            l->append( i );
        }
        if ( r )
            add( l, in, i->children(), true );
        ++i;
    }
}


/*! Returns a list of all the mailboxes in this Map. The list may be
    empty, but is never null. No mailboxes are repeated.
*/

List<Mailbox> * EventMap::mailboxes() const
{
    IntegerSet in;
    List<Mailbox> * l = new List<Mailbox>;
    List<EventFilterSpec>::Iterator i( d->l );
    while ( i ) {
        switch ( i->type() ) {
        case EventFilterSpec::Selected:
            // nothing
            break;
        case EventFilterSpec::SelectedDelayed:
            // nothing
            break;
        case EventFilterSpec::Inboxes:
            ::add( l, in, i->mailboxes() );
            break;
        case EventFilterSpec::Personal:
            ::add( l, in, i->mailboxes() );
            break;
        case EventFilterSpec::Subscribed:
            ::add( l, in, i->mailboxes() );
            break;
        case EventFilterSpec::Subtree:
            ::add( l, in, i->mailboxes(), true );
            break;
        case EventFilterSpec::Mailboxes:
            ::add( l, in, i->mailboxes() );
            break;
        }

        ++i;
    }
    return l;
}
