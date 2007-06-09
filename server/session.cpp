// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "session.h"

#include "transaction.h"
#include "messageset.h"
#include "allocator.h"
#include "selector.h"
#include "mailbox.h"
#include "message.h"
#include "event.h"
#include "query.h"
#include "flag.h"
#include "log.h"


class SessionData
    : public Garbage
{
public:
    SessionData()
        : readOnly( true ),
          initialiser( 0 ),
          mailbox( 0 ),
          uidnext( 0 ), nextModSeq( 0 ),
          firstUnseen( 0 ),
          permissions( 0 ),
          reportedExists( UINT_MAX/7 ) // random large number
    {}

    bool readOnly;
    bool active;
    SessionInitialiser * initialiser;
    Mailbox * mailbox;
    MessageSet msns;
    MessageSet recent;
    MessageSet expunges;
    uint uidnext;
    int64 nextModSeq;
    uint firstUnseen;
    Permissions * permissions;
    uint reportedExists;
    List<Message> newMessages;
    List<Message> modifiedMessages;
};


/*! \class Session session.h
    This class contains all data associated with the single use of a
    Mailbox, such as the number of messages visible, etc. Subclasses
    provide some protocol-specific actions.
*/

/*! Creates a new Session for the Mailbox \a m. If \a readOnly is true,
    the session is read-only.
*/

Session::Session( Mailbox *m, bool readOnly )
    : d( new SessionData )
{
    d->mailbox = m;
    d->readOnly = readOnly;
    d->mailbox->addSession( this );
}


/*! Exists to satisfy g++.
*/

Session::~Session()
{
    end();
}


/*! Ensures that the Mailbox will not keep this object alive. */

void Session::end()
{
    if ( d->mailbox )
        d->mailbox->removeSession( this );
}


/*! Returns true if this Session has updated itself from the database.
*/

bool Session::initialised() const
{
    if ( !d->uidnext )
        return false;
    if ( d->initialiser )
        return false;
    if ( d->nextModSeq < d->mailbox->nextModSeq() )
        return false;
    if ( d->uidnext < d->mailbox->uidnext() )
        return false;
    return true;
}


/*! Returns a pointer to the currently selected Mailbox, or 0 if there
    isn't one.
*/

Mailbox * Session::mailbox() const
{
    return d->mailbox;
}


/*! Returns true if this is a read-only session (as created by EXAMINE),
    and false otherwise (SELECT).
*/

bool Session::readOnly() const
{
    return d->readOnly;
}


/*! Returns a pointer to the Permissions object owned by this session,
    or 0 if none has been created (by Select). This object is ready to
    answer queries (with allows()) because Select waited for it to be.
*/

Permissions * Session::permissions() const
{
    return d->permissions;
}


/*! Sets the Permissions object for this session to \a p. Used only by
    Select. Session assumes that \a p is Permissions::ready().
*/

void Session::setPermissions( Permissions *p )
{
    d->permissions = p;
}


/*! Returns true only if this session knows that its user has the right
    \a r. If the session does not know, or the user doesn't have the
    right, it returns false.
*/

bool Session::allows( Permissions::Right r )
{
    return d->permissions->allowed( r );
}


/*! Returns the next UID to be used in this session. This is the same
    as Mailbox::uidnext() most of the time. It can lag behind if the
    Mailbox has changed and this session hasn't issued the
    corresponding untagged EXISTS and UIDNEXT responses.
*/

uint Session::uidnext() const
{
    return d->uidnext;
}


/*! Returns the uidvalidity of the mailbox. For the moment, this is
    always the same as Mailbox::uidvalidity(), and both are always 1.
*/

uint Session::uidvalidity() const
{
    return d->mailbox->uidvalidity();
}


/*! Returns the UID of the message with MSN \a msn, or 0 if there is
    no such message.
*/

uint Session::uid( uint msn ) const
{
    return d->msns.value( msn );
}


/*! Returns the MSN of the message with UID \a uid, or 0 if there is
    no such message.
*/

uint Session::msn( uint uid ) const
{
    return d->msns.index( uid );
}


/*! Returns the number of messages visible in this session. */

uint Session::count() const
{
    return d->msns.count();
}


/*! Returns the UID of the first unseen message in this session, or 0
    if the number isn't known.
*/

uint Session::firstUnseen() const
{
    return d->firstUnseen;
}


/*! Notifies this session that its first unseen message has \a uid. */

void Session::setFirstUnseen( uint uid )
{
    d->firstUnseen = uid;
}


/*! Notifies this session that it contains a message with \a uid. */

void Session::insert( uint uid )
{
    d->msns.add( uid );
}


/*! Notifies this session that it contains messages with UIDs from \a
    lowest to \a highest (in addition to whatever other messages it
    may contain). Both \a lowest and \a highest are inserted.
*/

void Session::insert( uint lowest, uint highest )
{
    d->msns.add( lowest, highest );
}


/*! Removes the message with \a uid from this session, adjusting MSNs
    as needed. This function does not emit any responses, nor does it
    cause responses to be emitted.
*/

void Session::remove( uint uid )
{
    d->msns.remove( uid );
}


/*! Returns a MessageSet containing all messages marked "\Recent" in
    this session.
*/

MessageSet Session::recent() const
{
    return d->recent.intersection( d->msns );
}


/*! Returns true only if the message \a uid is marked as "\Recent" in
    this session.
*/

bool Session::isRecent( uint uid ) const
{
    return d->recent.contains( uid );
}


/*! Marks the message \a uid as "\Recent" in this session. */

void Session::addRecent( uint uid )
{
    d->recent.add( uid );
}


/*! Returns true if this Session needs to refresh the client's
    world view in response to \a type changes.
*/

bool Session::responsesNeeded( ResponseType type ) const
{
    switch ( type ) {
    case New:
        if ( !d->newMessages.isEmpty() )
            return true;
        break;
    case Modified:
        if ( !d->modifiedMessages.isEmpty() )
            return true;
        break;
    case Deleted:
        if ( !d->expunges.isEmpty() )
            return true;
        break;
    }
    return false;
}


/*! Returns false if something's missing before \a type responses can
    be emitted, and true if nothing is known to be missing.
*/

bool Session::responsesReady( ResponseType type ) const
{
    type = type; // to stop the warnings
    if ( d->initialiser )
        return false;
    return true;
}


/*! Records that \a uids has been expunged, and that the clients should
    be told about it at the earliest possible moment.
*/

void Session::expunge( const MessageSet & uids )
{
    if ( uids.isEmpty() )
        return;
    List<Session>::Iterator i( mailbox()->sessions() );
    while ( i ) {
        i->d->expunges.add( uids );
        i->emitResponses();
        ++i;
    }
}


/*! Emit all the responses that are necessary and possible at this
    time. Carefully ensures that we emit responses in the same order
    every time - New cannot be sent before Modified.
*/

void Session::emitResponses()
{
    bool ok = true;
    if ( ok &&
         responsesNeeded( Deleted ) &&
         responsesPermitted( Deleted ) ) {
        if ( responsesReady( Deleted ) )
            emitResponses( Deleted );
        else
            ok = false;
    }
    if ( ok &&
         responsesNeeded( Modified ) &&
         responsesPermitted( Modified ) ) {
        if ( responsesReady( Modified ) )
            emitResponses( Modified );
        else
            ok = false;
    }
    if ( ok &&
         responsesNeeded( New ) &&
         responsesPermitted( New ) ) {
        if ( responsesReady( New ) )
            emitResponses( New );
        else
            ok = false;
    }
}


/*! Calls emitExpunge(), emitExists(), emitModification() etc. as
    needed and as indicated by \a type. Only sends the desired \a type
    of response. Does not check that responses may legally be sent at
    this point.
*/

void Session::emitResponses( ResponseType type )
{
    if ( type == Deleted ) {
        uint i = 1;
        while ( i <= d->expunges.count() ) {
            uint uid = d->expunges.value( i );
            uint msn = d->msns.index( uid );
            if ( msn ) {
                emitExpunge( msn );
                d->msns.remove( uid );
                if ( d->reportedExists > 0 )
                    d->reportedExists--;
            }
            i++;
        }
        d->expunges.clear();
    }
    else if ( type == Modified ) {
        if ( responsesReady( Modified ) ) {
            List<Message>::Iterator i( d->modifiedMessages );
            while ( i ) {
                List<Message>::Iterator m = i;
                ++i;
                if ( !msn( m->uid() ) ) {
                    // this message is no longer in our session, so we
                    // don't want to emit anything
                    d->modifiedMessages.take( m );
                }
                else if ( d->expunges.contains( m->uid() ) ) {
                    // we will send an expunge at the next
                    // opportunity, so why send a a change update now?
                    d->modifiedMessages.take( m );
                }
                else {
                    emitModification( m );
                    d->modifiedMessages.take( m );
                }
            }
        }
    }
    else { // New
        MessageSet n;
        List<Message>::Iterator i( d->newMessages.last() );
        while ( i ) {
            n.add( i->uid() );
            --i;
        }
        d->msns.add( n );
        d->newMessages.clear();
        uint c = d->msns.count();
        if ( c != d->reportedExists ) {
            d->reportedExists = c;
            emitExists( c );
        }
    }
}


/*! \fn Session::emitExpunge( uint msn )
    Does whatever the protocol requires when a message numbered \a msn
    is expunged. When this function is called, uid() and msn() are still
    valid.
*/

void Session::emitExpunge( uint )
{
}


/*! \fn Session::emitExists( uint number )
    Does whatever the protocol requires when the number of messages in
    the Mailbox changes to \a number.
*/

void Session::emitExists( uint )
{
}


/*! Sets our uidnext value to \a u. Used only by the SessionInitialiser.
*/

void Session::setUidnext( uint u )
{
    d->uidnext = u;
}


/*! Refreshes this session, notifying \a handler when it's done.
*/

void Session::refresh( EventHandler * handler )
{
    if ( handler && d->initialiser )
        d->initialiser->addWatcher( handler );
    else if ( d->initialiser )
        return;
    else if ( d->uidnext < d->mailbox->uidnext() )
        (void)new SessionInitialiser( this, handler );
    else if ( d->nextModSeq < d->mailbox->nextModSeq() )
        (void)new SessionInitialiser( this, handler );
    else if ( d->mailbox->type() == Mailbox::View &&
              d->mailbox->source()->nextModSeq() > d->mailbox->nextModSeq() )
        (void)new SessionInitialiser( this, handler );
}




class SessionInitialiserData
    : public Garbage
{
public:
    SessionInitialiserData()
        : session( 0 ),
          t( 0 ), recent( 0 ), messages( 0 ), seen( 0 ), nms( 0 ),
          oldUidnext( 0 ), newUidnext( 0 ),
          done( false )
        {}

    Session * session;
    List<EventHandler> watchers;

    Transaction * t;
    Query * recent;
    Query * messages;
    Query * seen;
    Query * nms;

    uint oldUidnext;
    uint newUidnext;
    int64 oldModSeq;
    int64 newModSeq;

    MessageSet expunged;
    List<Message> newMessages;
    List<Message> updated;

    bool done;
};


/*! \class SessionInitialiser imapsession.h

    The SessionInitialiser class performs the database queries
    needed to initialise an Session.

    When it's created, it immediately informs its owner that so-and-so
    many messages exist and returns. Later, it issues database queries
    to check that the messages do exist, and if any don't, it coerces
    its Session to emit corresponding expunges.

    When completed, it notifies its owner.
*/

/*! Constructs an SessionInitialiser for \a session, which will
    notify \a owner when it's done.
*/

SessionInitialiser::SessionInitialiser( Session * session,
                                        EventHandler * owner )
    : EventHandler(), d( new SessionInitialiserData )
{
    d->session = session;
    addWatcher( owner );
    d->oldModSeq = d->session->nextModSeq();
    d->newModSeq = d->session->mailbox()->nextModSeq();
    d->oldUidnext = d->session->uidnext();
    d->newUidnext = d->session->mailbox()->uidnext();
    if ( d->oldModSeq >= d->newModSeq && d->oldUidnext >= d->newUidnext )
        return;

    if ( d->watchers.isEmpty() &&
         d->newModSeq - d->oldModSeq <= 1 &&
         d->newUidnext > d->oldUidnext ) {
        // one or more messages have been injected, nothing else
        // changed, and noone is waiting for a callback. see if we can
        // skip all the hard work.
        List<Message> * l = d->session->newMessages();
        uint uid = d->oldUidnext;
        bool allKnown = true;
        while ( allKnown && uid < d->newUidnext ) {
            List<Message>::Iterator m( l );
            while ( m && m->uid() != uid )
                ++m;
            if ( !m )
                allKnown = false;
            uid++;
        }
        if ( allKnown ) {
            d->session->setUidnext( d->newUidnext );
            d->session->setNextModSeq( d->newModSeq );
            d->session->emitResponses();
            return;
        }
    }

    log( "Updating session on " + d->session->mailbox()->name() +
         " for modseq [" + fn( d->oldModSeq ) + "," +
         fn( d->newModSeq ) + ">, UID [" + fn( d->oldUidnext ) + "," +
         fn( d->newUidnext ) + ">" );

    d->session->addSessionInitialiser( this );
    execute();
}


void SessionInitialiser::execute()
{
    if ( !d->session->isSessionInitialiser( this ) )
        return;

    Mailbox * m = d->session->mailbox();

    if ( !d->t ) {
        // We update first_recent for our mailbox. Concurrent selects of
        // this mailbox will block until this transaction has committed.

        d->t = new Transaction( this );

        d->nms =
            new Query( "select nextmodseq from mailboxes where id=$1", this );
        d->nms->bind( 1, d->session->mailbox()->id() );
        d->t->enqueue( d->nms );

        Flag * seen = Flag::find( "\\seen" );

        if ( m->ordinary() ) {
            if ( d->oldUidnext < d->newUidnext ) {
                if ( d->session->readOnly() )
                    d->recent
                        = new Query( "select first_recent from mailboxes "
                                     "where id=$1", this );
                else
                    d->recent
                        = new Query( "select first_recent from mailboxes "
                                     "where id=$1 for update", this );
                d->recent->bind( 1, d->session->mailbox()->id() );
                d->t->enqueue( d->recent );

                if ( !d->session->readOnly() ) {
                    Query * q
                        = new Query( "update mailboxes set first_recent=$2 "
                                     "where id=$1", 0 );
                    q->bind( 1, d->session->mailbox()->id() );
                    q->bind( 2, d->session->mailbox()->uidnext() );
                    d->t->enqueue( q );
                }
            }

            bool initialising = false;
            if ( d->oldUidnext <= 1 )
                initialising = true;
            String msgs = "select m.uid from messages m ";
            if ( !initialising )
                msgs.append( "join modsequences ms "
                             " on (m.mailbox=ms.mailbox and m.uid=ms.uid) " );
            msgs.append( "left join deleted_messages dm "
                         " on (m.mailbox=dm.mailbox and m.uid=dm.uid) "
                         "where m.mailbox=$1 and dm.uid is null "
                         "and m.uid<$2" );
            if ( !initialising )
                msgs.append( " and (m.uid>=$3 or ms.modseq>=$4)" );
            msgs.append( " order by m.uid" );
            d->messages = new Query( msgs, this );
            d->messages->bind( 1, m->id() );
            d->messages->bind( 2, d->newUidnext );
            if ( !initialising ) {
                // XXX: I think ms.modseq>=3 in all cases where m.uid>=$2
                d->messages->bind( 3, d->oldUidnext );
                d->messages->bind( 4, d->oldModSeq );
            }

            d->t->enqueue( d->messages );

            if ( seen && !d->session->firstUnseen() ) {
                d->seen =
                    new Query( "select m.uid from messages m "
                               "left join flags f on "
                               "(f.mailbox=m.mailbox and f.uid=m.uid and"
                               " f.flag=$2) left join deleted_messages dm "
                               "on (m.mailbox=dm.mailbox and m.uid=dm.uid) "
                               "where m.mailbox=$1 and dm.uid is null and "
                               "f.flag is null order by uid limit 1", this );
                d->seen->bind( 1, d->session->mailbox()->id() );
                d->seen->bind( 1, seen->id() );
                d->seen->execute();
            }
        }
        else {
            Query * q;

            q = new Query( "select uidnext from mailboxes where id=$1 "
                           "for update", 0 );
            q->bind( 1, m->id() );
            d->t->enqueue( q );

            Selector * sel = new Selector;
            sel->add( new Selector( Selector::Modseq, Selector::Larger,
                                    d->oldModSeq ) );
            sel->add( Selector::fromString( m->selector() ) );
            sel->simplify();

            d->messages = sel->query( 0, m->source(), 0, this );
            uint oms = sel->placeHolder();

            String s( "select m.mailbox, m.uid, "
                      " vm.uid as vuid, "
                      " s.uid as suid, "
                      " ms.modseq, "
                      " f.flag as seen "
                      "from messages m "
                      "join modsequences ms on "
                      " (m.mailbox=ms.mailbox and m.uid=ms.uid) "
                      "left join view_messages vm on "
                      " (m.mailbox=vm.source and m.uid=vm.suid) "
                      "left join flags f on "
                      " (m.mailbox=f.mailbox and m.uid=f.uid and "
                      "  f.flag=" + fn( seen->id() ) + " ) " // XXX seen 0
                      "left join (" + d->messages->string() + ") s on "
                      " m.uid=s.uid "
                      "where m.mailbox=$" + sel->mboxId() +
                      " and ms.modseq>=$" + fn( oms ) + " "
                      "order by m.uid" );
            d->messages->bind( oms, d->oldModSeq );
            d->messages->setString( s );
            d->t->enqueue( d->messages );
        }

        d->t->execute();
    }

    Row * r = 0;

    while ( (r=d->nms->nextRow()) != 0 )
        m->setNextModSeq( r->getBigint( "nextmodseq" ) );

    if ( m->view() ) {
        MessageSet removeInDb;
        MessageSet addToDb;
        int64 hms = 0;
        while ( (r=d->messages->nextRow()) != 0 ) {
            int64 ms = r->getBigint( "modseq" );
            if ( ms > hms )
                hms = ms;
            bool seen = true;
            if ( r->isNull( "seen" ) )
                seen = false;

            uint uid = r->getInt( "uid" );
            uint vuid = 0;
            if ( !r->isNull( "vuid" ) )
                vuid = r->getInt( "vuid" );

            bool left = false;
            if ( r->isNull( "suid" ) )
                left = true;

            // if it left the search result but still is in the db, we
            // want to remove it
            if ( left && vuid )
                removeInDb.add( vuid );
            // if it entered the search result and isn't in the db, wep
            // want to add it
            if ( !left && !vuid )
                addToDb.add( uid );
            // if it is in the search results and also in the db...
            if ( !left && vuid ) {
                Message * message = new Message;
                message->setUid( vuid );
                message->setModSeq( r->getBigint( "modseq" ) );
                // ... then if it's in the session, its modseq increased...
                if ( d->session->msn( vuid ) ) {
                    d->updated.append( message );
                }
                else { // ... else it's new to this session
                    m->setSourceUid( vuid, uid );
                    d->newMessages.append( message );
                }
            }
        }

        if ( !removeInDb.isEmpty() ) {
            Query * q
                = new Query( "delete from view_messages "
                             "where view=$1 and source=$2 and (" +
                             removeInDb.where( "" ) + ")", 0 );
            q->bind( 1, m->id() );
            q->bind( 2, m->source()->id() );
            d->t->enqueue( q );
            d->expunged.add( removeInDb );
        }

        if ( !addToDb.isEmpty() ) {
            Query * q = new Query( "copy view_messages (source,suid,view,uid) "
                                   "from stdin with binary", 0 );
            while ( !addToDb.isEmpty() ) {
                uint suid = addToDb.value( 1 );
                addToDb.remove( suid );
                uint uid = d->newUidnext;
                d->newUidnext++;
                q->bind( 1, m->source()->id(), Query::Binary );
                q->bind( 2, suid, Query::Binary );
                q->bind( 3, m->id(), Query::Binary );
                q->bind( 4, uid, Query::Binary );
                q->submitLine();
                m->setSourceUid( uid, suid );
                Message * m = new Message;
                m->setUid( uid );
                d->newMessages.append( m );
            }
            d->t->enqueue( q );
        }

        if ( !removeInDb.isEmpty() || !addToDb.isEmpty() ) {
            Query * q = new Query( "update views set nextmodseq=$1 "
                                   "where view=$2 and nextmodseq<$1", 0 );
            q->bind( 1, hms + 1 );
            q->bind( 2, m->id() );
            d->t->enqueue( q );
        }
    }
    else {
        while ( (r=d->messages->nextRow()) != 0 ) {
            uint uid = r->getInt( "uid" );
            Message * m = new Message;
            m->setUid( uid );
            if ( m->uid() >= d->oldUidnext )
                d->newMessages.append( m );
            else
                d->updated.append( m );
        }
    }

    if ( !d->t->done() && d->messages->done() && !d->done ) {
        if ( m->view() && d->newUidnext > m->uidnext() ) {
            m->setUidnext( d->newUidnext );
            Query * q = new Query( "update mailboxes set uidnext=$1 "
                                   "where id=$2", 0 );
            q->bind( 1, d->newUidnext );
            q->bind( 2, m->id() );
            d->t->enqueue( q );
        }
        d->t->commit();
        d->done = true;
    }

    if ( !d->t->done() )
        return;

    if ( d->recent && !d->recent->done() )
        return;
    if ( d->seen && !d->seen->done() )
        return;

    if ( d->seen )
        while( (r=d->seen->nextRow()) )
            d->session->setFirstUnseen( r->getInt( "uid" ) );

    d->session->setUidnext( m->uidnext() );
    d->session->setNextModSeq( m->nextModSeq() );
    d->session->expunge( d->expunged.intersection( d->session->messages() ) );
    if ( d->recent && (r=d->recent->nextRow()) != 0 ) {
        uint recent = r->getInt( "first_recent" );
        uint n = recent;
        while ( n < d->session->uidnext() )
            d->session->addRecent( n++ );
    }
    d->session->recordChange( &d->newMessages, Session::New );
    d->session->recordChange( &d->updated, Session::Modified );

    d->session->removeSessionInitialiser();

    List<EventHandler>::Iterator it( d->watchers );
    while ( it ) {
        EventHandler * e = it;
        ++it;
        e->execute();
    }
    d->session->emitResponses();
}


/*! Returns true once the initialiser has done its job, and false
    until then.
*/

bool SessionInitialiser::done() const
{
    return d->done;
}


/*! Returns a message set containing all the UIDs that have been
    expunged in the database, but not yet reported to the client.
*/

const MessageSet & Session::expunged() const
{
    return d->expunges;
}


/*! Returns a message set containing all the messages that are
    currently valid in this session. This may include expunged
    messages.
*/

const MessageSet & Session::messages() const
{
    return d->msns;
}


/*! Clears the list of expunged messages without calling
    emitExpunge().
*/

void Session::clearExpunged()
{
    d->msns.remove( d->expunges );
    d->expunges.clear();
}


/*! The SessionInitialiser calls this when initialised() can return
    true. Noone else should ever call it.
*/

void Session::removeSessionInitialiser()
{
    d->initialiser = 0;
}


/*! Records that \a e should be notified when the initialiser has
    finished its work.
*/

void SessionInitialiser::addWatcher( EventHandler * e )
{
    if ( e && d->watchers.find( e ) == d->watchers.end() )
        d->watchers.append( e );
}


/*! The SessionInitialiser calls this when it's creating itself (thus,
    \a s refers to itself), so that initialised() can return false until
    removeSessionInitialiser() is called. Noone else should ever call it.
*/

void Session::addSessionInitialiser( class SessionInitialiser * s )
{
    d->initialiser = s;
}


/*! Returns true if \a si is working on this session at the moment,
    and false otherwise.
*/

bool Session::isSessionInitialiser( class SessionInitialiser * si )
{
    if ( si == d->initialiser )
        return true;
    return false;
}


/*! Returns a list of the messages that have been modified and about
    which which the client may need to be told. The returned list may
    be empty, but is never a null pointer.

*/

List<Message> * Session::modifiedMessages() const
{
    return &d->modifiedMessages;
}


/*! Returns a list of the messages that have added to the session and
    about which which the client may need to be told. The returned
    list may be empty, but is never a null pointer.

*/

List<Message> * Session::newMessages() const
{
    return &d->newMessages;
}


/*! Records that there's been a change of \a type involving \a m, so
    that the client can be informed of the change. Only types New and
    Deleted may be used with this function.
*/

void Session::recordChange( List<Message> * m, ResponseType type )
{
    List<Session>::Iterator s( mailbox()->sessions() );
    while ( s ) {
        List<Message>::Iterator i( m );
        List<Message>::Iterator j;
        List<Message> * l = 0;
        if ( type == New )
            l = &s->d->newMessages;
        else
            l = &s->d->modifiedMessages;
        uint prev = 0;
        while ( i ) {
            if ( !prev || i->uid() < prev )
                j = l->first();
            while ( j && j->uid() < i->uid() )
                ++j;
            if ( j && j->uid() == i->uid() && j->modSeq() < i->modSeq() )
                l->take( j );
            if ( !j || j->uid() > i->uid() ) {
                l->insert( j, i );
                prev = i->uid();
            }
            ++i;
        }
        s->emitResponses();
        ++s;
    }
}


/*! Returns what setNextModSeq() set. The initial value is 0. */

int64 Session::nextModSeq() const
{
    return d->nextModSeq;
}


/*! Records that the next possible modseq for a message in this
    session is \a ms or higher.
*/

void Session::setNextModSeq( int64 ms ) const
{
    d->nextModSeq = ms;
}


/*! Returns true if this session can notify its client of a \a type
    events.
*/

bool Session::responsesPermitted( ResponseType type ) const
{
    type = type; // for the warnings
    return true;
}


/*! This virtual function emits whatever data is necessary and
    appropriate to inform the client that \a m has changed. The
    default implementation does nothing.
*/

void Session::emitModification( Message * m )
{
    m = m;
}
