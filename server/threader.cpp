// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "threader.h"

#include "messageset.h"
#include "mailbox.h"
#include "message.h"
#include "field.h"
#include "query.h"
#include "dict.h"


class ThreaderData
    : public Garbage
{
public:
    ThreaderData()
        : state( 0 ), mailbox( 0 ), largestUid( 0 ), users( 0 ),
          complete( 0 ), findnew( 0 ), findthreads( 0 ) {}

    uint state;
    const Mailbox * mailbox;
    uint largestUid;
    List<EventHandler> * users;
    Dict<Thread> threads;
    List<Thread> threadList;
    
    class ThreadInserter
        : public EventHandler
    {
    public:
        ThreadInserter(): t( 0 ), i( 0 ), s( 0 ), m( 0 ) {}
        Thread * t;
        Query * i;
        Query * s;
        const Mailbox * m;
        MessageSet uids;

        void execute();
    };

    List<ThreadInserter> inserters;
    Query * complete;
    Query * findnew;
    Query * findthreads;
};


/*! \class Threader threader.h

    The Threader class looks at a mailbox, builds an in-memory
    structure of the messages based on a table, and if necessary
    updates that table.
*/



/*! Constructs a threader for \a mailbox, which must not be null. */

Threader::Threader( const Mailbox * mailbox )
    : EventHandler(), d( new ThreaderData )
{
    d->mailbox = mailbox;
}


void Threader::execute()
{
    if ( d->state == 0 &&
         d->largestUid + 1 < d->mailbox->uidnext() )
        d->state = 1;

    // we need to do something. what?
    Row * r = 0;
    // state 1: find any new thread_members rows for this mailbox
    if ( d->state == 1 ) {
        if ( !d->complete ) {
            d->complete
                = new Query( "select tm.uid, tm.thread, "
                             " t.subject "
                             "from thread_members tm "
                             "join threads t on (t.id=tm.thread) "
                             "where tm.mailbox=$1 and tm.uid>$2",
                             this );
            d->complete->bind( 1, d->mailbox->id() );
            d->complete->bind( 2, d->largestUid );
            d->complete->execute();
        }
        while ( (r=d->complete->nextRow()) ) {
            uint uid = r->getInt( "uid" );
            uint tid = r->getInt( "thread" );
            String subject = r->getString( "subject" );
            Thread * t = d->threads.find( subject );
            if ( !t ) {
                t = new Thread;
                t->setId( tid );
                t->setSubject( subject );
                d->threads.insert( subject, t );
                d->threadList.append( t );
            }
            t->add( uid );
            if ( uid > d->largestUid )
                d->largestUid = uid;
        }
        if ( !d->complete->done() )
            return;
        d->complete = 0;
        d->state = 2;
    }

    // state 2: find the base subjects of new messages and construct
    // the in-ram threads.
    if ( d->state == 2 ) {
        if ( !d->findnew ) {
            d->findnew
                = new Query( "select hf.uid, hf.value "
                             "from header_fields hf "
                             "left join thread_members tm using (mailbox,uid) "
                             "where hf.mailbox=$1 and hf.field=$2 "
                             " and hf.part='' and tm.thread is null", this );
            d->findnew->bind( 1, d->mailbox->id() );
            d->findnew->bind( 2, HeaderField::Subject );
            d->findnew->execute();
        }
        while ( (r=d->findnew->nextRow()) ) {
            String subject = Message::baseSubject( r->getString( "value" ) );
            uint uid = r->getInt( "uid" );
            Thread * t = d->threads.find( subject );
            if ( !t ) {
                t = new Thread;
                t->setSubject( subject );
                d->threads.insert( subject, t );
                d->threadList.append( t );
            }
            t->add( uid );
            if ( uid > d->largestUid )
                d->largestUid = uid;
            List<ThreaderData::ThreadInserter>::Iterator i( d->inserters );
            while ( i && i->t != t )
                ++i;
            if ( !i ) {
                ThreaderData::ThreadInserter * ti
                    = new ThreaderData::ThreadInserter;
                d->inserters.append( ti );
                i = d->inserters.last();
                i->t = t;
                i->m = d->mailbox;
            }
            i->uids.add( uid );
        }
        if ( !d->findnew->done() )
            return;
        d->findnew = 0;
        d->state = 3;
    }

    // state 3: notify the users. the database can be updated later.

    if ( d->state == 3 ) {
        if ( !updated() )
            return;

        if ( d->inserters.isEmpty() )
            d->state = 0;
        else
            d->state = 4;

        List<EventHandler>::Iterator o( d->users );
        d->users = 0;
        while ( o ) {
            o->execute();
            ++o;
        }
    }
    

    // state 4: have a preparatory look for the threads where we need
    // to insert something. in theory this isn't necessary, but
    // without this step, there will be an awful lot of errors in the
    // pg log file when 'insert into threads' fails.
    if ( d->state == 4 ) {
        bool done = false;
        if ( d->findthreads && d->findthreads->done() )
            done = true;
        if ( !d->findthreads ) {
            List<ThreaderData::ThreadInserter>::Iterator i( d->inserters );
            while ( i && i->t->id() )
                ++i;
            if ( !i ) {
                done = true;
            }
            else {
                d->findthreads = new Query( "select id, subject from threads "
                                            "where mailbox=$1", this );
                d->findthreads->bind( 1, d->mailbox->id() );
                d->findthreads->execute();
            }
        }
        if ( d->findthreads ) {
            Row * r = 0;
            while ( (r=d->findthreads->nextRow()) ) {
                Thread * t = d->threads.find( r->getString( "subject" ) );
                if ( t )
                    t->setId( r->getInt( "id" ) );
            }
        }
        if ( done ) {
            d->findthreads = 0;
            d->state = 0;
            List<ThreaderData::ThreadInserter>::Iterator i( d->inserters );
            while ( i ) {
                i->execute();
                ++i;
            }
            d->inserters.clear();
        }
    }
}


void ThreaderData::ThreadInserter::execute()
{
    if ( !t->id() && !i ) {
        i = new Query( "insert into threads (subject, mailbox) "
                       "values ($1, $2)",
                       this );
        i->bind( 1, t->subject() );
        i->bind( 2, m->id() );
        i->allowFailure();
        i->execute();
    }

    if ( i && !i->done() )
        return;

    if ( !t->id() && !s ) {
        s = new Query( "select id from threads "
                       "where subject=$1 and mailbox=$2",
                       this );
        s->bind( 1, t->subject() );
        s->bind( 2, m->id() );
        s->execute();
    }

    if ( s ) {
        Row * r = s->nextRow();
        if ( r )
            t->setId( r->getInt( "id" ) );
    }

    if ( !t->id() )
        return;

    // we could use a copy for this, but we'd have to fall back to
    // multiple inserts if the copy fails (it can in a cluster
    // configuration) so for the moment I don't bother implementing
    // the copy at all.

    while ( !uids.isEmpty() ) {
        uint uid = uids.smallest();
        uids.remove( uid );
        Query * q = new Query( "insert into thread_members "
                               "(thread,mailbox,uid) "
                               "values ($1,$2,$3)", 0 );
        q->bind( 1, t->id() );
        q->bind( 2, m->id() );
        q->bind( 3, uid );
        q->allowFailure();
        q->execute();
    }
}


/*! Returns true if this Threader has complete data for mailbox(), and
    false if refresh() needs to be called or is working.
*/

bool Threader::updated() const
{
    if ( d->largestUid + 1 >= d->mailbox->uidnext() )
        return true;
    return false;
}


/*! Returns a pointer to the Mailbox mapped by this Threader. This
    cannot be a null pointer in a valid object.
*/

const Mailbox * Threader::mailbox() const
{
    return d->mailbox;
}


/*! Starts updating the thread data for mailbox(), if that's
    necessary. If refresh() causes any work to be done, the \a user
    will be notified of completion using EventHandler::execute().
*/

void Threader::refresh( EventHandler * user )
{
    if ( updated() )
        return;
    if ( !d->users )
        d->users = new List<EventHandler>;
    if ( !d->users->find( user ) )
        d->users->append( user );
    if ( d->state == 0 )
        execute();
}


class ThreadData
    : public Garbage
{
public:
    ThreadData(): id( 0 ) {}

    uint id;
    String subject;
    MessageSet members;
};


/*! \class Thread threader.h

    The Thread class models a simple thread. Not a pretty tree or even
    DAG, just a set of messages and a subject.

    The Thread class is meant to be small, small and small: Sometimes
    (perhaps often) we need to keep Thread objects for an entire
    Mailbox in RAM. Size is more important than functionality.
    
    If an IMAP THREAD command needs to return a tree, it has to
    compute the tree itself. This class can help make that simpler,
    that's all.

    If an ArchiveThread needs to display information about some/all
    threads, this class can help make it simpler, but it isn't
    sufficient in and of itself.

    The Threader creates, owns and updates Thread objects.
*/



/*! Constructs an empty Thread. */

Thread::Thread()
    : d( new ThreadData )
{
}


/*! Returns all the members of this thread. This may include deleted
    messages. */

MessageSet Thread::members() const
{
    return d->members;
}


/*! Records that \a uid is a member of this thread. */

void Thread::add( uint uid )
{
    d->members.add( uid );
}


/*! Records that \a subject is the base subject of this thread
    (ie. without "re", "fwd" or similar).
*/

void Thread::setSubject( const String & subject )
{
    d->subject = subject;
}


/*! Returns whatever was set by setSubject(), or an empty string
    initially.
*/

String Thread::subject() const
{
    return d->subject;
}


/*! Returns the database ID of this thread, or 0 if the thread still
    isn't recorded in the database. 0 is perfectly possible - Threader
    will notify its users as soon as it can, even if the thread IDs
    aren't known yet.
*/

uint Thread::id() const
{
    return d->id;
}


/*! Records that \a id is the database ID of this thread. */

void Thread::setId( uint id )
{
    d->id = id;
}


/*! Returns a pointer to an unsorted list of all threads. Never
    returns a null pointer. The returned list should not be modified.
*/

List<Thread> * Threader::allThreads() const
{
    return &d->threadList;
}
