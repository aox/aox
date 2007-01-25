// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpdata.h"

#include "imapurlfetcher.h"
#include "configuration.h"
#include "addressfield.h"
#include "smtpmailrcpt.h"
#include "smtpparser.h"
#include "injector.h"
#include "address.h"
#include "imapurl.h"
#include "mailbox.h"
#include "message.h"
#include "buffer.h"
#include "sieve.h"
#include "list.h"
#include "date.h"
#include "smtp.h"
#include "user.h"
#include "md5.h"

// getpid()
#include <sys/types.h>
#include <unistd.h>

class SmtpDataData
    : public Garbage
{
public:
    SmtpDataData()
        : state( 2 ), message( 0 ), injector( 0 ), now( 0 ), ok( "OK" ) {}
    String id;
    String body;
    uint state;
    Message * message;
    Injector * injector;
    Date * now;
    String ok;
};


/*! \class SmtpData smtpdata.h
  
    This is also the superclass for SmtpBdat and SmtpBurl, and does
    the injection.
*/



/*! Constructs a SMTP DATA handler. \a s must be the SMTP server, as
    usual, and \a p may be either null or a parser to be used for
    parsing DATA. If it's null, this function assumes it's really
    working on a BDAT/BURL command.
*/

SmtpData::SmtpData( SMTP * s, SmtpParser * p )
    : SmtpCommand( s ), d( new SmtpDataData )
{
    if ( !p )
        return;

    p->end();
    d->state = 0;
    // d->state starts at 2 for bdat/burl, and at 0 for data.
}


/*! Does input for DATA and injection for DATA, BDAT and BURL.

*/

void SmtpData::execute()
{
    // we can't do anything until all older commands have completed.
    if ( !server()->isFirstCommand( this ) )
        return;

    // state 0: not yet sent 354
    if ( d->state == 0 ) {
        d->id = id();

        uint local = 0;
        uint remote = 0;
        List<SmtpRcptTo>::Iterator i( server()->rcptTo() );
        while ( i ) {
            if ( i->remote() )
                remote++;
            else
                local++;
            ++i;
        }

        if ( !local && !remote ) {
            respond( 503, "No valid recipients" );
            finish();
            return;
        }

        String r = "354 Go ahead";
        if ( local || remote )
            r.append( " (" );
        if ( local ) {
            r.append( fn( local ) );
            r.append( " local recipients" );
            if ( remote )
                r.append( ", " );
        }
        if ( remote ) {
            r.append( fn( remote ) );
            r.append( " remote recipients" );
        }
        r.append( ")\r\n" );
        server()->enqueue( r );
        server()->setInputState( SMTP::Data );
        d->state = 1;
    }

    // state 1: have sent 354, have not yet received CR LF "." CR LF.
    while ( d->state == 1 ) {
        Buffer * r = server()->readBuffer();
        String * line = r->removeLine( 262144 );
        if ( !line && r->size() > 262144 ) {
            respond( 500, "Line too long (legal maximum is 998 bytes)" );
            finish();
            server()->setState( Connection::Closing );
        }
        if ( !line )
            return;

        if ( *line == "." ) {
            d->state = 2;
            server()->setInputState( SMTP::Command );
            server()->setBody( d->body );
        }
        else if ( (*line)[0] == '.' ) {
            d->body.append( line->mid( 1 ) );
            d->body.append( "\r\n" );
        }
        else {
            d->body.append( *line );
            d->body.append( "\r\n" );
        }
    }

    // bdat/burl start at state 2.

    // state 2: have received CR LF "." CR LF, have not started injection
    if ( d->state == 2 ) {
        server()->sieve()->setMessage( message( d->body ) );
        if ( d->message->error().isEmpty() ) {
            // the common case: all ok
        }
        else if ( server()->dialect() == SMTP::Submit ) {
            // for Submit, we reject the message at once, since we
            // have the sender there.
            respond( 554, "Syntax error: " + d->message->error() );
            finish();
            return;
        }
        else {
            // for SMTP/LMTP, we wrap the unparsable message
            Message * m = Message::wrapUnparsableMessage( d->body,
                                                          d->message->error(),
                                                          "Message arrived "
                                                          "but could not be "
                                                          "stored",
                                                          id() );
            // the next line changes the SMTP/LMTP response
            d->ok = "Worked around: " + d->message->error();
            // the next line means that what we store is the wrapper
            d->message = m;
            // the next line means that what we sieve is the wrapper
            server()->sieve()->setMessage( m );
        }
        server()->sieve()->evaluate();
        d->injector = new Injector( d->message, this );

        SortedList<Mailbox> * l = new SortedList<Mailbox>;
        List<Mailbox>::Iterator i( server()->sieve()->mailboxes() );
        while ( i ) {
            if ( !l->find( i ) )
                l->insert( i );
            ++i;
        }

        List<Address> * f = server()->sieve()->forwarded();
        if ( !f->isEmpty() ) {
            l->insert( Mailbox::find( "/archiveopteryx/spool" ) );
            d->injector->setDeliveryAddresses( f );
        }
        d->injector->setMailboxes( l );
        if ( server()->user() )
            d->injector->setSender( server()->user()->address() );

        if ( l->isEmpty() ) {
            // we don't want to inject at all. what do we want to do?
            // the sieve should know.
            d->state = 4;
        }
        else {
            d->injector->execute();
            d->state = 3;
        }
    }

    // state 3: the injector is working, we're waiting for it to finish.
    if ( d->state == 3 ) {
        if ( !d->injector->done() )
            return;
        if ( d->injector->error().isEmpty() ) {
            d->injector->announce();
            d->state = 4;
        }
        else {
            respond( 451, "Injection error: " + d->injector->error() );
            finish();
        }
    }

    // state 4: we're done. give the report suggested by the sieve.
    if ( d->state == 4 ) {
        if ( server()->dialect() == SMTP::Lmtp ) {
            Sieve * s = server()->sieve();
            List<SmtpRcptTo>::Iterator i( server()->rcptTo() );
            while ( i ) {
                String prefix = i->address()->toString();
                if ( s->rejected( i->address() ) )
                    respond( 551, prefix + ": Rejected" );
                else
                    respond( 250, prefix + ": " + d->ok );
                ++i;
            }
        }
        else {
            if ( server()->sieve()->rejected() )
                respond( 551, "Rejected by all recipients" );
            else
                respond( 250, d->ok );
        }
        finish();
        server()->reset();
    }
}


/*! Parses \a body and returns a pointer to the parsed message,
    including a prepended Received field.

    This may also do some of the submission-time changes suggested by
    RFC 4409.
*/

Message * SmtpData::message( const String & body )
{
    if ( d->message )
        return d->message;

    String received( "Received: from " );
    received.append( server()->peer().address() );
    received.append( " (HELO " );
    received.append( server()->heloName() );
    received.append( ") by " );
    received.append( Configuration::hostname() );
    received.append( " with " );
    switch ( server()->dialect() ) {
    case SMTP::Smtp:
        received.append( " esmtp " );
        break;
    case SMTP::Lmtp:
        received.append( " lmtp " );
        break;
    case SMTP::Submit:
        received.append( " esmtpa " );
        break;
    }
    received.append( " id " );
    received.append( id() );
    // XXX: if the number of receivers is one, add a 'for' clause. if
    // it's greater, add a comment with the count. but don't do this
    // until the new code passes the existing tests.
    received.append( "; " );
    received.append( now()->rfc822() );
    received.append( "\r\n" );

    String rp;
    if ( server()->sieve()->sender() )
        rp = "Return-Path: " +
             server()->sieve()->sender()->toString() +
             "\r\n";

    d->body = rp + received + body;
    Message * m = new Message( d->body );
    m->setInternalDate( now()->unixTime() );
    // if the sender is another dickhead specifying <> in From to
    // evade replies, let's try harder.
    if ( !m->error().isEmpty() &&
         server()->sieve()->sender() &&
         server()->sieve()->sender()->type() == Address::Normal ) {
        List<Address> * from = m->header()->addresses( HeaderField::From );
        if ( from->count() == 1 && from->first()->type() == Address::Bounce ) {
            Header * h = m->header();
            AddressField * old = h->addressField( HeaderField::From );
            Address * f = server()->sieve()->sender();
            Address * a = new Address( from->first()->name(),
                                       f->localpart(),
                                       f->domain() );
            HeaderField * hf = HeaderField::create( "From", a->toString() );
            hf->setPosition( old->position() );
            h->removeField( HeaderField::From );
            h->add( hf );
            h->repair( m );
            m->recomputeError();
        }
    }
    // if we're delivering remotely, we'd better do some of the
    // chores from RFC 4409.
    if ( server()->dialect() != SMTP::Lmtp ) {
        Header * h = m->header();
        // remove bcc if present
        h->removeField( HeaderField::Bcc );
        // add a message-id if there isn't any
        if ( !h->field( HeaderField::MessageId ) ) {
            MD5 x;
            x.add( d->body );
            h->add( "Message-Id",
                    "<" + x.hash().e64().mid( 0, 21 ) + ".md5@" +
                    Configuration::hostname() + ">" );
        }
        // specify a sender if a) we know who the sender is, b) from
        // doesn't name the sender and c) the sender did not specify
        // anything.
        if ( server()->user() && !h->field( HeaderField::Sender ) ) {
            List<Address> * from = h->addresses( HeaderField::From );
            Address * s = server()->user()->address();
            if ( !from || from->count() != 1 ||
                 from->first()->localpart().lower() !=s->localpart().lower() ||
                 from->first()->domain().lower() != s->domain().lower() )
                h->add( "Sender", s->toString() );
        }
    }
    d->message = m;
    return m;
}


static uint sequence = 0;


/*! Return an ESMTP id, either based on an internal algorithm or on
    something the client specified. There is some ESMTP extension we
    can use to let the client specify the ID, and we want to do that,
    for easier tracking.

    id() returns the same ID even if called several times (for the
    same object, that is).
*/

String SmtpData::id()
{
    if ( !d->id.isEmpty() )
        return d->id;

    d->id = fn( now()->unixTime() );
    d->id.append( '-' );
    d->id.append( fn( getpid() ) );
    d->id.append( '-' );
    d->id.append( fn( ++sequence ) );
    return d->id;
}


/*! Returns the current time and date, except that if you call it
    more than once for the same object, it returns the same value.
*/

Date * SmtpData::now()
{
    if ( d->now )
        return d->now;

    d->now = new Date;
    d->now->setCurrentTime();
    return d->now;
}


class SmtpBdatData
    : public Garbage
{
public:
    SmtpBdatData()
        : size( 0 ), read( false ), last( false ) {}
    uint size;
    bool read;
    String chunk;
    bool last;
};


/*! \class SmtpBdat smtpdata.h

    The BDAT command is an alternative to DATA, defined by RFC
    3030. It doesn't seem to have much point on its own, but together
    with BURL (RFC 4468) and URLAUTH (RFC 4467) it allows
    forward-without-download.
*/


SmtpBdat::SmtpBdat( SMTP * s, SmtpParser * p )
    : SmtpData( s, 0 ), d( new SmtpBdatData )
{
    p->whitespace();
    d->size = p->number();
    if ( !p->atEnd() ) {
        p->whitespace();
        p->require( "last" );
        d->last = true;
    }
    p->end();
    server()->setInputState( SMTP::Chunk );
}


void SmtpBdat::execute()
{
    if ( !d->read ) {
        Buffer * r = server()->readBuffer();
        if ( r->size() < d->size )
            return;
        d->chunk = r->string( d->size );
        r->remove( d->size );
        server()->setInputState( SMTP::Command );
        d->read = true;
    }

    if ( !server()->isFirstCommand( this ) )
        return;

    String b = server()->body();
    b.append( d->chunk );
    server()->setBody( b );
    if ( d->last ) {
        SmtpData::execute();
    }
    else {
        respond( 250, "OK" );
        finish();
    }
}


class SmtpBurlData
    : public Garbage
{
public:
    SmtpBurlData() : last( false ), url( 0 ), fetcher( 0 ) {}

    bool last;
    ImapUrl * url;
    ImapUrlFetcher * fetcher;
};


SmtpBurl::SmtpBurl( SMTP * s, SmtpParser * p )
    : SmtpData( s, 0 ), d( new SmtpBurlData )
{
    p->whitespace();
    String u;
    while ( !p->atEnd() && p->nextChar() != ' ' ) {
        u.append( p->nextChar() );
        p->step();
    }
    d->url = new ImapUrl( u );
    if ( !d->url->valid() ) {
        respond( 501, "Can't parse that URL" );
        finish();
        return;
    }
    String a = d->url->access().lower();
    u.truncate();
    if ( server()->user() )
        u = server()->user()->login().lower();
    if ( !( a == "anonymous" ||
            ( server()->user() && ( a == "authuser" ||
                                    a == "user+" + u ||
                                    a == "submit+" + u ) ) ) ) {
        respond( 554, "Do not have permission to read that URL" );
        finish();
        return;
    }
    if ( !p->atEnd() ) {
        p->whitespace();
        p->require( "last" );
        d->last = true;
    }
    p->end();

    List<ImapUrl> * l = new List<ImapUrl>;
    l->append( d->url );
    d->fetcher = new ImapUrlFetcher( l, this );
    d->fetcher->execute();
}


void SmtpBurl::execute()
{
    if ( !d->fetcher )
        return;
    if ( !d->fetcher->done() )
        return;
    if ( d->fetcher->failed() ) {
        respond( 554, "URL resolution problem: " + d->fetcher->error() );
        finish();
        return;
    }
    if ( !server()->isFirstCommand( this ) )
        return;
    
    String b( server()->body() );
    b.append( d->url->text() );
    server()->setBody( b );
    if ( d->last ) {
        SmtpData::execute();
    }
    else {
        respond( 250, "OK" );
        finish();
    }
}
