// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "threader.h"


class ThreaderData
    : public Garbage
{
public:
    ThreaderData()
        : session( 0 ), largestUid( 0 ) {}

    Session * session;
    uint largestUid;

    class ThreadSelect
        : public Garbage
    {
    public:
        ThreadSelect: t( 0 ), q( 0 ) {}
        Thread * t;
        Query * q;
        MessageSet m;
    };

    List<Query> threadInserts;
    List<ThreadSelect> threadSelects;
};


/*! \class Threader threader.h

    The Threader class looks at a mailbox, builds an in-memory
    structure of the messages based on a table, and if necessary
    updates that table.
*/



/*!  Constructs a threader for \a mailbox and notifies \a owner when
     done.
*/

Threader::Threader( Mailbox * mailbox, EventHandler * owner )
    : EventHandler(), d( new ThreaderData )
{
    d->mailbox = mailbox;
    d->owner = owner;
    execute();
}


/*!

*/

void Threader::execute()
{
    uint largestUid = d->session->messages().largest();
    if ( largestUid <= d->largestUid )
        return;

    // we need to do something. what?
    Row * r = 0;
    // state 0: find any new thread_members rows for this mailbox
    if ( d->state == 0 ) {
        if ( !d->complete ) {
            d->complete =
                = new Query( "select tm.uid, tm.thread, "
                             " t.subject "
                             "from thread_members tm "
                             "join threads t on (t.id=tm.thread) "
                             "where mailbox=$1 and uid>=$2",
                             this );
            d->complete->bind( 1, d->session->mailbox() );
            d->complete->bind( 2, d->largestUid+1 );
            d->complete->bind( 3, HeaderField::fieldType( "Subject" ) );
            d->complete->execute();
        }
        while ( (r=d->complete->nextRow()) ) {
            uint uid = r->getInt( "uid" );
            uint tid = r->getInt( "thread" );
            String subject = r->getString( "subject" );
            Thread * t = d->threads->find( subject );
            if ( !t ) {
                t = new Thread;
                t->setId( tid );
                t->setMailbox( d->session->mailbox() )
                d->setSubject( subject );
                d->threads->insert( subject, t );
            }
            t->add( new ThreadMember( uid ) );
            if ( uid > d->largestUid )
                d->largestUid = uid;
        }
        if ( !d->complete->done() )
            return;
        d->complete = 0;

        // did that supply all the data we need?
        if ( d->largestUid >= largestUid ) {
            if ( d->owner )
                d->owner->execute();
            return;
        }

        d->state = 1;
    }

    // state 1: find the base subjects of new messages, add relevant
    // base subjects to threads and look up threads.id.
    if ( d->state == 1 ) {
        if ( !d->findnew ) {
            d->findnew
                = new Query( "select m.uid, hf.value "
                             "from messages m "
                             "join header_fields hf on " 
                             " (m.mailbox=hf.mailbox and m.uid=hf.uid) "
                             "left join thread_members tm on "
                             " (m.mailbox=tm.mailbox and m.uid=tm.uid) "
                             "where mailbox=$1 and tm.thread is null and "
                             " hf.field=$3 and hf.part=''",
                             this );
            d->findnew->bind( 1, d->session->mailbox() );
            d->findnew->bind( 2, d->largestUid+1 );
            d->findnew->bind( 3, HeaderField::fieldType( "Subject" ) );
            d->findnew->execute();
        }
        while ( (r=d->findnew->nextRow()) ) {
            String subject = Message::baseSubject( r->getString( "subject" ) );
            uint uid = r->getInt( "uid" );
            Thread * t = d->treads->find( subject );
            if ( !t ) {
                t = new Thread;
                t->setMailbox( d->session->mailbox() )
                d->setSubject( subject );
                d->threads->insert( subject, t );
                Query * q;
                q = new Query( "insert into threads (subject) values ($1)",
                               this );
                q->bind( 1, subject );
                q->allowFailure();
                q->execute();
                d->threadInserts.append( q );
                q = new Query( "select id,subject "
                               "from threads where subject=$1",
                               this );
                q->bind( 1, subject );
                ThreadData::ThreadSelect * ts 
                    = new ThreadData::ThreadSelect;
                ts->q = q;
                ts->t = t;
                d->threadSelects.append( ts );
            }
            
        }
        if ( !d->findnew->done() )
            return;
        d->findnew = 0;
        d->state = 2;
        // at this point we can notify our owner. we're not done, but
        // we have the necessary results.
        if ( d->owner )
            d->owner->execute();
    }

    // state 2: wait for threads to be updated, and as soon as that
    // happens, find the created IDs.
    if ( d->state == 2 ) {
        List<Query>::Iterator q( d->threadInserts );
        while ( q ) {
            if ( !q->done() )
                return;
            d->threadInserts.take( q ); // moves q as a side effect
        }
        d->state = 3;
        List<ThreadData::ThreadSelect>::Iterator i( d->threadSelects );
        while ( i ) {
            i->q->execute();
            ++i;
        }
    }

    // state 3: insert thread_members rows using the IDs.
    if ( d->state == 3 ) {
        List<ThreadData::ThreadSelect>::Iterator i( d->threadSelects );
        while ( i && i->q->done() ) {
            Query * q = d->threadSelects.take( i ); // moves i
            r = i->q->nextRow();
            if ( r ) {
                String subject = r->getString( "subject" );
                Thread * t = d->threads->find( subject );
                if ( t ) {
                    t->setId( r->getInt( "id" ) );
                    Query * q;
                    uint n = 1;
                    while ( n < i->m.count() ) {
                        q = new Query( "insert into thread_members "
                                       "(thread,mailbox,uid) "
                                       "values ($1,$2,$3)", 0 );
                        q->bind( 1, t->id() );
                        q->bind( 2, d->session->mailbox()->id() );
                        q->bind( 3, i->m.value( n ) );
                        q->allowFailure();
                        q->execute();
                        n++;
                    }
                }
            }
        }
        if ( i )
            return;

        d->state = 0;
    }
}
