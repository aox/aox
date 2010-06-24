// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "thread.h"

#include "imapsession.h"
#include "imapparser.h"
#include "message.h"
#include "address.h"
#include "field.h"
#include "query.h"
#include "dict.h"
#include "list.h"
#include "map.h"


class ThreadData
    : public Garbage
{
public:
    ThreadData(): Garbage(), uid( true ), s( 0 ),
                  session( 0 ),
                  find( 0 ) {}

    bool uid;
    enum Algorithm { OrderedSubject, Refs, References };
    Algorithm threadAlg;
    Selector * s;

    ImapSession * session;
    Query * find;

    class Node
        : public Garbage
    {
    public:
        Node()
            : Garbage(),
              uid( 0 ), threadRoot( 0 ),
              idate( 0 ),
              reported( false ), added( false ),
              parent( 0 ) {}

        uint uid;
        uint threadRoot;
        UString subject;
        uint idate;
        EString references;
        EString messageId;

        bool reported;
        bool added;

        class Node * parent;
        List<Node> children;
    };

    Dict<Node> nodes;
    List<Node> roots;

    List<Node> result;

    void splice( List<Node> * );
    void append( EString &, List<Node> *, bool );
};


/*! \class Thread thread.h

    The Thread class implements the IMAP THREAD command, specified in
    RFC 5256 section BASE.6.4.THREAD.
*/



/*! Constructs an empty Thread command. Will return UIDs if \a u is
    true, otherwise MSNs.
*/

Thread::Thread( bool u )
    : Search( u ), d( new ThreadData )
{
    d->uid = u;
}


void Thread::parse()
{
    // thread = ["UID" SP] "THREAD" SP thread-alg SP search-criteria
    // thread-alg = "ORDEREDSUBJECT" / "REFERENCES" / thread-alg-ext
    // thread-alg-ext = atom
    // search-criteria = charset 1*(SP search-key)
    // charset = atom / quoted

    space();
    EString threadAlg = atom();
    if ( threadAlg == "orderedsubject" )
        d->threadAlg = ThreadData::OrderedSubject;
    else if ( threadAlg == "refs" )
        d->threadAlg = ThreadData::Refs;
    else if ( threadAlg == "references" )
        d->threadAlg = ThreadData::References;
    else
        error( Bad, "Unsupported thread algorithm" );
    space();
    setCharset( astring() );
    space();
    d->s = new Selector;
    d->s->add( parseKey() );
    while ( ok() && !parser()->atEnd() ) {
        space();
        d->s->add( parseKey() );
    }
    d->s->simplify();
    end();
}


/*! This reimplementation of Search::execute() does not call
    Search. It does the entire job itself.

*/

void Thread::execute()
{
    if ( state() != Executing )
        return;

    if ( !d->session )
        d->session = session();

    if ( !d->find ) {
        EStringList * want = new EStringList;
        want->append( "uid" );
        want->append( "message" );
        want->append( "m.idate" );
        want->append( "m.thread_root" );
        want->append( "tmid.value as messageid" );
        want->append( "tref.value as references" );
        EString ts;
        if ( d->threadAlg == ThreadData::References ) {
            want->append( "tsubj.value as subject" );
            ts = "left join header_fields tsubj on"
                 " (m.id=tsubj.message and"
                 " tsubj.field=" + fn( HeaderField::Subject ) +
                 " and tsubj.part='') ";
        }

        d->find = d->s->query( imap()->user(),
                               d->session->mailbox(), d->session,
                               this, false, want );
        EString j = d->find->string();

        // we need to get the References and Message-Id fields as well
        const char * x = "left join";
        if ( !j.contains( x ) )
            x = "where";
        j.replace( x,
                   "left join header_fields tref on"
                   " (m.id=tref.message and"
                   " tref.field=" + fn( HeaderField::References ) +
                   " and tref.part='') "
                   "left join header_fields tmid on"
                   " (m.id=tmid.message and"
                   " tmid.field=" + fn( HeaderField::MessageId ) +
                   " and tmid.part='') " + ts + x );

        d->find->setString( j );

        d->find->execute();
        return;
    }

    while ( d->find->hasResults() ) {
        Row * r = d->find->nextRow();
        ThreadData::Node * n = new ThreadData::Node;
        n->uid = r->getInt( "uid" );
        n->idate = r->getInt( "idate" );
        if ( !r->isNull( "thread_root" ) )
            n->threadRoot = r->getInt( "thread_root" );
        if ( !r->isNull( "references" ) )
            n->references = r->getEString( "references" );
        if ( !r->isNull( "messageid" ) )
            n->messageId = r->getEString( "messageid" );
        if ( !r->isNull( "subject" ) )
            n->subject = Message::baseSubject( r->getUString( "subject" ) );

        d->result.append( n );
        if ( !n->messageId.isEmpty() )
            d->nodes.insert( n->messageId, n );
    }

    if ( !d->find->done() )
        return;

    List<ThreadData::Node>::Iterator ri( d->result );
    if ( d->threadAlg == ThreadData::OrderedSubject ) {
        ThreadData::Node * prev = 0;
        while ( ri ) {
            ThreadData::Node * n = ri;
            ++ri;

            if ( !prev || prev->subject != n->subject )
                d->roots.append( n );
            else
                prev->children.append( n );
            prev = n;
        }
    }
    else {
        while ( ri ) {
            ThreadData::Node * n = ri;
            ++ri;

            EStringList l;
            AddressParser * ap = AddressParser::references( n->references );
            List<Address>::Iterator a( ap->addresses() );
            while ( a ) {
                l.append( a->lpdomain() );
                ++a;
            }
            l.append( n->messageId );

            EStringList::Iterator s( l );
            ThreadData::Node * parent = 0;
            while ( s ) {
                if ( !s->isEmpty() ) {
                    ThreadData::Node * n = d->nodes.find( *s );
                    if ( !n ) {
                        n = new ThreadData::Node;
                        n->messageId = *s;
                        d->nodes.insert( *s, n );
                    }
                    if ( parent ) {
                        // if we have a parent, and the parent is a child
                        // of the supposed child, then
                        ThreadData::Node * p = parent;
                        while ( p && p != n )
                            p = p->parent;
                        if ( p == n )
                            parent = 0; // then don't use that parent
                    }
                    if ( n == parent ) {
                        // evil case. let's not do anything
                    }
                    else if ( parent && n->parent == parent ) {
                        // nice case, hopefully common. no need to act.
                    }
                    else if ( parent && n->parent ) {
                        // the DAG disagrees with the references chain
                        // we're processing. go up to both roots, and
                        // merge them if they differ.
                        ThreadData::Node * p = parent;
                        while ( p->parent )
                            p = p->parent;
                        ThreadData::Node * f = n;
                        while ( f->parent )
                            f = f->parent;
                        if ( p != f )
                            p->parent = f;
                    }
                    else if ( parent ) {
                        // we didn't know about a parent for this
                        // message-id, now we do. record it.
                        n->parent = parent;
                    }
                    parent = n;
                }
                ++s;
            };
        }
    }

    // if thread=references is used, we need to jump through extra hoops
    if ( d->threadAlg == ThreadData::References ) {
        Dict<ThreadData::Node>::Iterator i( d->nodes );
        UDict<ThreadData::Node> subjects;
        while ( i ) {
            if ( !i->parent ) {
                ThreadData::Node * potential = subjects.find( i->subject );
                if ( potential )
                    i->parent = potential;
                else
                    subjects.insert( i->subject, i );
            }
            ++i;
        }
    }

    // set up child lists and the root list
    Dict<ThreadData::Node>::Iterator i( d->nodes );
    while ( i ) {
        ThreadData::Node * n = i;
        ++i;
        while ( n ) {
            if ( !n->added ) {
                n->added = true;
                if ( n->parent )
                    n->parent->children.append( n );
                else
                    d->roots.append( n );
            }
            n = n->parent;
        }
    }

    // we need to sort root nodes (and children) by idate, so we
    // extend the definition until sorting works: a non-message's
    // idate is the oldest idate of a direct descendant.
    i = Dict<ThreadData::Node>::Iterator( d->nodes );
    while ( i ) {
        ThreadData::Node * n = i;
        ++i;

        uint idate = n->idate;
        while ( n ) {
            if ( n->uid )
                idate = n->idate;
            else if ( !n->idate || n->idate > idate )
                n->idate = idate;
            n = n->parent;
        }
    }

    waitFor( new ThreadResponse( d ) );
    finish();
}


/*! \class ThreadResponse thread.h

    The Thread class formats the IMAP THREAD response, as specified in
    RFC 5256 section BASE.6.4.THREAD.

    There's a question of who's to do more... at present Thread and
    ThreadResponse can't do very good thread reporting. Either Thread
    or ThreadResponse has to grow better. Think.
*/


/*! Constructs a THREAD response that'll look at \a threadData and
    send the relevant response when possible.
*/

ThreadResponse::ThreadResponse( ThreadData * threadData )
    : ImapResponse( threadData->session ), d( threadData )
{
}


EString ThreadResponse::text() const
{
    d->splice( &d->roots );
    EString result = "THREAD ";
    d->append( result, &d->roots, true );
    return result;
}

void ThreadData::splice( List<ThreadData::Node> * l )
{
    List<Node>::Iterator i ( l );
    while ( i ) {
        Node * n = i;
        ++i;
        if ( !n->children.isEmpty() )
            splice( &n->children );
        if ( !n->uid ) {
            l->remove( n );
            List<Node>::Iterator c( n->children );
            while ( c ) {
                l->insert( i, c );
                ++c;
            }
        }
    }
}

void ThreadData::append( EString & r, List<ThreadData::Node> * l, bool t )
{
    if ( l->isEmpty() ) {

    }
    else if ( l->count() == 1 && !t ) {
        r.append( " " );
        r.appendNumber( l->first()->uid );
    }
    else {
        r.append( " " );
        List<Node>::Iterator c( l );
        while ( c ) {
            r.append( "(" );
            r.appendNumber( c->uid );
            append( r, &c->children, false );
            r.append( ")" );
            ++c;
        }
    }
}
