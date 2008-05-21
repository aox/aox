// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpdata.h"

#include "imapurlfetcher.h"
#include "configuration.h"
#include "addressfield.h"
#include "smtpmailrcpt.h"
#include "spoolmanager.h"
#include "sieveaction.h"
#include "smtpparser.h"
#include "address.h"
#include "imapurl.h"
#include "mailbox.h"
#include "message.h"
#include "buffer.h"
#include "graph.h"
#include "scope.h"
#include "sieve.h"
#include "file.h"
#include "list.h"
#include "date.h"
#include "smtp.h"
#include "user.h"


class SmtpDataData
    : public Garbage
{
public:
    SmtpDataData()
        : state( 2 ), message( 0 ), ok( "OK" )
    {}

    String body;
    uint state;
    Message * message;
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

    Scope x( log() );
    p->end();
    d->state = 0;
    // d->state starts at 2 for bdat/burl, and at 0 for data.
}


static GraphableCounter * messagesWrapped = 0;
static GraphableCounter * messagesSubmitted = 0;


/*! Does input for DATA and injection for DATA, BDAT and BURL. */

void SmtpData::execute()
{
    if ( !::messagesWrapped )
        ::messagesWrapped
              = new GraphableCounter( "unparsed-messages" );
    if ( !::messagesSubmitted )
        ::messagesSubmitted
              = new GraphableCounter( "messages-submitted" );

    // we can't do anything until all older commands have completed.
    if ( !server()->isFirstCommand( this ) )
        return;

    // state 0: not yet sent 354
    if ( d->state == 0 ) {
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
            respond( 503, "No valid recipients", "5.5.1" );
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
            respond( 500, "Line too long (legal maximum is 998 bytes)",
                     "5.5.2" );
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
        server()->sieve()->setMessage( message( server()->body() ),
                                       server()->transactionTime() );
        if ( server()->dialect() == SMTP::Submit &&
             d->message->error().isEmpty() ) {
            // a syntactically acceptable message has been submitted.
            // does it use the right addresses?
            checkField( HeaderField::From );
            checkField( HeaderField::ResentFrom );
            checkField( HeaderField::Sender );
            checkField( HeaderField::ReturnPath );
            checkField( HeaderField::ReplyTo ); // <-- even reply-to? hm?
            String e = d->message->error();
            if ( e.isEmpty() &&
                 !addressPermitted( server()->sieve()->sender() ) )
                e = "Not authorised to use this SMTP sender address: " +
                    server()->sieve()->sender()->lpdomain();
            if ( !e.isEmpty() ) {
                respond( 554, e, "5.7.0" );
                finish();
                return;
            }
        }
        if ( d->message->error().isEmpty() ) {
            // the common case: all ok
        }
        else if ( server()->dialect() == SMTP::Submit ) {
            // for Submit, we reject the message at once, since we
            // have the sender there.
            respond( 554,
                     "Syntax error: " + d->message->error(), "5.6.0" );
            finish();
            return;
        }
        else {
            // for SMTP/LMTP, we wrap the unparsable message
            Message * m
                = Message::wrapUnparsableMessage( d->body, d->message->error(),
                                                  "Message arrived "
                                                  "but could not be "
                                                  "stored",
                                                  server()->transactionId() );
            // the next line changes the SMTP/LMTP response
            d->ok = "Worked around: " + d->message->error();
            // the next line means that what we store is the wrapper
            d->message = m;
            // the next line means that what we sieve is the wrapper
            server()->sieve()->setMessage( m, server()->transactionTime() );
            server()->sieve()->setWrapped();
            ::messagesWrapped->tick();
        }
        server()->sieve()->evaluate();

        // we tell the sieve that our remote recipients are "immediate
        // redirects". strange concept, but...
        bool remotes = false;
        List<SmtpRcptTo>::Iterator it( server()->rcptTo() );
        while ( it ) {
            if ( server()->dialect() == SMTP::Submit ||
                 it->remote() ) {
                SieveAction * a = new SieveAction( SieveAction::Redirect );
                a->setSenderAddress( server()->sieve()->sender() );
                a->setRecipientAddress( it->address() );
                a->setMessage( d->message );
                server()->sieve()->addAction( a );
                remotes = true;
            }
            ++it;
        }
        if ( remotes )
            ::messagesSubmitted->tick();

        server()->sieve()->act( this );
        d->state = 3;
    }

    // state 3: the injector is working, we're waiting for it to finish.
    if ( d->state == 3 ) {
        if ( !server()->sieve()->injected() )
            return;
        String mc = Configuration::text( Configuration::MessageCopy ).lower();
        if ( mc == "all" )
            makeCopy();
        else if ( mc == "delivered" && server()->sieve()->error().isEmpty() )
            makeCopy();
        else if ( mc == "errors" && !server()->sieve()->error().isEmpty() )
            makeCopy();
        if ( server()->sieve()->error().isEmpty() ) {
            d->state = 4;
        }
        else {
            if ( Configuration::toggle( Configuration::SoftBounce ) )
                respond( 451, "Injection error: " + server()->sieve()->error(),
                         "4.6.0" );
            else
                respond( 551, "Injection error: " + server()->sieve()->error(),
                         "5.6.0" );
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
                    respond( 551, prefix + ": Rejected", "5.7.1" );
                else if ( s->error( i->address() ).isEmpty() )
                    respond( 250, prefix + ": " + d->ok, "2.1.5" );
                else if ( Configuration::toggle( Configuration::SoftBounce ) )
                    respond( 450, prefix + ": " + s->error( i->address() ),
                             "4.0.0" );
                else
                    respond( 550, prefix + ": " + s->error( i->address() ),
                             "5.0.0" );
                emitResponses();
                ++i;
            }
        }
        else {
            if ( server()->sieve()->rejected() )
                respond( 551, "Rejected by all recipients", "5.7.1" );
            if ( !server()->sieve()->error().isEmpty() )
                respond( 451, "Sieve runtime error: " +
                         server()->sieve()->error(), "4.0.0" );
            else
                respond( 250, d->ok, "2.0.0" );
        }

        SpoolManager::run();

        finish();
        server()->reset();
    }
}


/*! Returns true if the authenticated User is permitted to send mail
    from \a a (for almost any definition of send mail from).
*/

bool SmtpData::addressPermitted( Address * a ) const
{
    if ( !a )
        return false;

    if ( a->type() == Address::Local || a->type() == Address::Invalid )
        return false;

    if ( a->type() ==  Address::Normal ) {
        String ad = a->domain().lower();
        String al = a->localpart().lower();
        List<Address>::Iterator p( server()->permittedAddresses() );
        while ( p &&
                al != p->localpart().lower() &&
                ad != p->domain().lower() )
                ++p;
        if ( !p )
            return false;
    }
    return true;
}


/*! Checks that the HeaderField with type \a t contains only addresses
    which the authenticated user is explicitly permitted to use. This
    has to return at once, so we need the complete list of addresses
    in RAM. We can obtain that list as soon as authentication
    succeeds, so that should be okay.

    This function demands that EVERY address in (e.g.) From is
    authorised, not that at least one address is OK. Is that what we
    want? I think so.
*/

void SmtpData::checkField( HeaderField::Type t )
{
    List<Address>::Iterator a( d->message->header()->addresses( t ) );
    while ( a && addressPermitted( a ) )
        ++a;
    if ( !a )
        return;
    HeaderField * hf = d->message->header()->field( t );
    if ( hf )
        hf->setError( "Not authorised to use this address: " + a->lpdomain() );
    d->message->recomputeError();
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
    switch ( server()->dialect() ) {
    case SMTP::Smtp:
        received.append( " with esmtp" );
        break;
    case SMTP::Lmtp:
        received.append( " with lmtp" );
        break;
    case SMTP::Submit:
        received.append( " with esmtp" );
        break;
    }
    received.append( " id " );
    received.append( server()->transactionId() );
    // XXX: if the number of receivers is one, add a 'for' clause. if
    // it's greater, add a comment with the count. but don't do this
    // until the new code passes the existing tests.
    received.append( "; " );
    received.append( server()->transactionTime()->rfc822() );
    received.append( "\r\n" );

    String rp;
    if ( server()->sieve()->sender() )
        rp = "Return-Path: " +
             server()->sieve()->sender()->toString() +
             "\r\n";

    d->body = rp + received + body;
    Message * m = new Message( d->body );
    // if the sender is another dickhead specifying <> in From to
    // evade replies, let's try harder.
    if ( !m->error().isEmpty() &&
         server()->sieve()->sender() &&
         server()->sieve()->sender()->type() == Address::Normal ) {
        List<Address> * from = m->header()->addresses( HeaderField::From );
        if ( from && from->count() == 1 &&
             from->first()->type() == Address::Bounce ) {
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
            h->repair();
            h->repair( m, "" );
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
        m->addMessageId();
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
    Scope x( log() );
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
        respond( 250, "OK", "2.0.0" );
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


/*! \class SmtpBurl smtpdata.h

    The BURL command is defined in RFC 4468, and allows a client to
    instruct a submit server to include content from an IMAP server
    (using a URLAUTH-authorized URL).
*/

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
        respond( 501, "Can't parse that URL", "5.5.4" );
        finish();
        return;
    }
    String a = d->url->access().lower();
    u.truncate();
    if ( server()->user() )
        u = server()->user()->login().utf8().lower();
    if ( !( a == "anonymous" ||
            ( server()->user() && ( a == "authuser" ||
                                    a == "user+" + u ||
                                    a == "submit+" + u ) ) ) ) {
        respond( 554, "Do not have permission to read that URL", "5.7.0" );
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
        respond( 554, "URL resolution problem: " + d->fetcher->error(),
                 "5.5.0" );
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
        respond( 250, "OK", "2.0.0" );
        finish();
    }
}


/*! Writes a copy of the incoming message to the file system. */

void SmtpData::makeCopy() const
{
    String copy = Configuration::text( Configuration::MessageCopyDir );
    copy.append( '/' );
    copy.append( server()->transactionId() );

    File f( copy, File::ExclusiveWrite );
    if ( !f.valid() ) {
        log( "Could not open " + copy + " for writing", Log::Disaster );
        return;
    }

    f.write( "From: " );
    f.write( server()->sieve()->sender()->toString() );
    f.write( "\n" );

    List<SmtpRcptTo>::Iterator it( server()->rcptTo() );
    while ( it ) {
        f.write( "To: " );
        f.write( it->address()->toString() );
        f.write( "\n" );
        ++it;
    }

    if ( !server()->sieve()->error().isEmpty() ||
         d->ok.startsWith( "Worked around: " ) ) {
        copy.append( "-err" );
        String e;
        if ( !server()->sieve()->error().isEmpty() ) {
            f.write( "Error: Sieve/Injector: " );
            f.write( server()->sieve()->error().simplified() );
        }
        else {
            f.write( "Parser: " );
            f.write( d->ok.simplified() );
        }
        f.write( "\n" );
    }

    f.write( "\n" );

    f.write( d->body );
}
