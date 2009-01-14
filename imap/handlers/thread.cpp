// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "thread.h"

#include "imapparser.h"
#include "threader.h"
#include "imapsession.h"
#include "query.h"


using namespace Imap;


class Imap::ThreadData
    : public Garbage
{
public:
    ThreadData(): Garbage(), uid( true ), s( 0 ),
                  session( 0 ), threader( 0 ),
                  find( 0 ) {}

    bool uid;
    enum Algorithm { OrderedSubject };
    Algorithm threadAlg;
    Selector * s;

    ImapSession * session;
    Threader * threader;
    Query * find;
    IntegerSet result;
};


/*! \class Thread thread.h

    The Thread class implements the IMAP THREAD command, specified in
    RFC 5256 section BASE.6.4.THREAD.
*/



/*! Constructs an empty Thread command. Will return UIDs if \a u is
    true, otherwise MSNs.
*/

Imap::Thread::Thread( bool u )
    : Search( u ), d( new ThreadData )
{
    d->uid = u;
}


void Imap::Thread::parse()
{
    // thread = ["UID" SP] "THREAD" SP thread-alg SP search-criteria
    // thread-alg = "ORDEREDSUBJECT" / "REFERENCES" / thread-alg-ext
    // thread-alg-ext = atom
    // search-criteria = charset 1*(SP search-key)
    // charset = atom / quoted

    space();
    String threadAlg = atom();
    if ( threadAlg == "orderedsubject" )
        d->threadAlg = ThreadData::OrderedSubject;
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

void Imap::Thread::execute()
{
    if ( !d->threader ) {
        d->session = session();
        d->threader = new Threader( d->session->mailbox() );
    }
    if ( !d->find ) {
        d->find = d->s->query( imap()->user(),
                                d->session->mailbox(), d->session,
                                this );
        d->find->execute();
        return;
    }

    while ( d->find->hasResults() ) {
        Row * r = d->find->nextRow();
        d->result.add( r->getInt( "uid" ) );
    }

    if ( !d->threader->updated() ) {
        d->threader->refresh( this );
        return;
    }

    if ( !d->find->done() )
        return;

    waitFor( new Imap::ThreadResponse( d ) );
    finish();
}


/*!  Constructs a THREAD response that'll send either \s set as UIDs
     (if \a uid is true) or MSNs (if \a uid is false) within \a
     session, threaded as specified by \a threader.
*/

Imap::ThreadResponse::ThreadResponse( ThreadData * threadData )
    : ImapResponse( threadData->session ), d( threadData )
{
}


String Imap::ThreadResponse::text() const
{
    String result = "THREAD ";
    if ( d->threadAlg == Imap::ThreadData::OrderedSubject ) {
        List<SubjectThread>::Iterator t( d->threader->subjectThreads() );
        while ( t ) {
            IntegerSet members = t->members().intersection( d->result );
            t++;
            switch ( members.count() ) {
            case 0:
                break;
            case 1:
                result.append( "(" );
                result.appendNumber( members.smallest() );
                result.append( ")" );
                break;
            case 2:
                result.append( "(" );
                result.appendNumber( members.smallest() );
                result.append( " " );
                result.appendNumber( members.largest() );
                result.append( ")" );
                break;
            default:
                result.append( "(" );
                result.appendNumber( members.smallest() );
                result.append( " " );
                uint i = 2;
                while ( i < members.count() ) {
                    result.append( "(" );
                    result.appendNumber( members.value( i ) );
                    result.append( ")" );
                    i++;
                }
                result.append( ")" );
                break;
            }
        }
    }

    return result;
}
