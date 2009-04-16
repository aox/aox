// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "eventmap.h"


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

    This is only used if the type() is Subtree or Mailboxes.
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


/*! Returns true if \a mailbox is the list recorded by
    setMailboxes().
*/

bool EventFilterSpec::appliesTo( Mailbox * mailbox )
{
    List<Mailbox>::Iterator i( d->mailboxes );
    while ( i && i != mailbox )
        ++i;
    if ( i )
        return true;
    return false;
}


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
    : Garbage()
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
    List<EventFilterSpec>::Iterator i( l );
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
    l.append( s );
}
