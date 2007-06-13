// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "dsn.h"

#include "date.h"
#include "address.h"
#include "message.h"
#include "bodypart.h"
#include "stringlist.h"
#include "configuration.h"


class DSNData
    : public Garbage
{
public:
    DSNData()
        : message( 0 ),
          full( true ),
          arrivalDate( 0 ),
          resultDate( 0 ),
          sender( 0 )
        {}
    Message * message;
    String envid;
    bool full;
    String receivedFrom;
    Date * arrivalDate;
    Date * resultDate;
    Address * sender;
    List<Recipient> recipients;
};


/*! \class DSN dsn.h

    The DSN class builds a bounce (a well-formed DSN message) based
    on a Message and other data. It's a typical single-function class:
    Call setMessage() and more, then call result(), then discard the
    DSN.
*/

/*!  Constructs an empty DSN message, for nothing, sent to noone,
     etc.
*/

DSN::DSN()
    : d( new DSNData )
{
}


/*! Records that the message which bounced (or was delivered) is \a m. */

void DSN::setMessage( Message * m )
{
    d->message = m;
}


/*! Returns the value recorded by setMessage(), or a null pointer if
    setMessage() has not been called.
*/

Message * DSN::message() const
{
    return d->message;
}


/*! Records that the envelope-id (see RFC 3461) of this delivery is \a
    envid.
*/

void DSN::setEnvelopeId( const String & envid )
{
    d->envid = envid;
}


/*! Returns the envelope-id recorded by setEnvelopeId(), or a null
    string if none has been recorded.
*/

String DSN::envelopeId() const
{
    return d->envid;
}


/*! Records that the resulting DSN should include the entire message()
    if \a full is true, and just its top-level header if \a full is
    false. The initial value is true (this may change in a future
    version).
*/

void DSN::setFullReport( bool full )
{
    d->full = full;
}


/*! Returns whatever setFullReport() set. */

bool DSN::fullReport() const
{
    return d->full;
}


/*! Records that message() was received from \a mta. The initial
    value, an empty string, means that message() was received from
    some unknown origin, or wasn't really received at all.
*/

void DSN::setReceivedFrom( const String & mta )
{
    d->receivedFrom = mta;
}


/*! Returns the name of the MTA that sent us message(), or an empty
    string if none did or we don't know who did.
*/

String DSN::receivedFrom() const
{
    return d->receivedFrom;
}


/*! Records that message() was received at \a date. The initial value,
    null, means that the message wasn't received at any known date.
*/

void DSN::setArrivalDate( class Date * date )
{
    d->arrivalDate = date;
}


/*! Returns the arrival date of message(), or a null pointer if the
    date isn't known.
*/

Date * DSN::arrivalDate() const
{
    return d->arrivalDate;
}


/*! Returns a list of the recipients for message(). The return value
    may point to an empty list, but is never a null pointer.
*/

List<Recipient> * DSN::recipients() const
{
    return &d->recipients;
}


/*! Records that message() should be/was/was not delivered to \a r. */

void DSN::addRecipient( Recipient * r )
{
    d->recipients.append( r );
}


// finally, the meat.


/*! Generates a multipart/report for message(), recipients() etc. and
    returns a pointer to the generated Message object.

    If you call this twice, you get two Message objets, each generated
    with much effort.
*/

Message * DSN::result() const
{
    Message * r = new Message;
    Bodypart * plainText = new Bodypart( 1, r );
    Bodypart * dsn = new Bodypart( 2, r );
    Bodypart * original = new Bodypart( 3, r );


    plainText->setParent( r );
    dsn->setParent( r );
    original->setParent( r );
    r->children()->append( plainText );
    r->children()->append( dsn );
    r->children()->append( original );

    // set up the original message, either full or header-only
    if ( fullReport() ) {
        original->header()->add( "Content-Type", "message/rfc822" );
        original->setMessage( message() );
    }
    else {
        // nasty mime name there
        original->header()->add( "Content-Type", "text/rfc822-headers" );
        original->setData( message()->header()->asText() );
    }

    // the from field has to contain... what? let's try this for now.
    Address * from = new Address( Configuration::hostname(),
                                  "postmaster",
                                  Configuration::hostname() );
    // set up the top-level header
    Header * h = r->header();
    if ( resultDate() ) {
        h->add( "Date", resultDate()->rfc822() );
    }
    else {
        Date * now = new Date;
        now->setCurrentTime();
        h->add( "Date", now->rfc822() );
    }
    h->add( "From", from->toString() );
    if ( sender() )
        h->add( "To", sender()->toString() );
    if ( allOk() )
        h->add( "Subject", "Message delivered" );
    else if ( allFailed() )
        h->add( "Subject", "Message delivery failed" );
    else
        h->add( "Subject", "Message delivery reports" );
    h->add( "Mime-Version", "1.0" );
    h->add( "Content-Type", "multipart/report; boundary=" +
            Message::acceptableBoundary( message()->rfc822() ) );

    // set up the plaintext and DSN parts
    // what charset should we use for plainText?
    plainText->header()->add( "Content-Type", "text/plain; format=flowed" );
    dsn->header()->add( "Content-Type", "message/delivery-status" );

    plainText->setData( plainBody() );
    dsn->setData( dsnBody() );

    return r;
}


/*! Returns true if all recipients() were delivered successfully, and
    false in any other case.

    If there aren't any recipients(), this function returns true.

    Recipient::Delivered, Recipient::Relayed and Recipient::Expanded
    are considered to indicate success.
*/

bool DSN::allOk() const
{
    List<Recipient>::Iterator recipient( recipients() );
    while ( recipient ) {
        if ( recipient->action() != Recipient::Delivered &&
             recipient->action() != Recipient::Relayed &&
             recipient->action() != Recipient::Expanded )
            return false;
        ++recipient;
    }
    return true;
}


/*! Returns true if delivery to all recipients() failed, and false in
    any other case.

    If there aren't any recipients(), this function returns true.
*/

bool DSN::allFailed() const
{
    List<Recipient>::Iterator recipient( recipients() );
    while ( recipient ) {
        if ( recipient->action() != Recipient::Failed )
            return false;
        ++recipient;
    }
    return true;
}


/*! Returns true if delivery to some of the recipients() is still
    pending (i.e. their Recipient::action() is still Unknown), and
    false if they have all been attempted.
*/

bool DSN::deliveriesPending() const
{
    List<Recipient>::Iterator recipient( recipients() );
    while ( recipient ) {
        if ( recipient->action() == Recipient::Unknown )
            return true;
        ++recipient;
    }
    return false;
}


/*! Returns the body text for this bounce's plain-text body. */

String DSN::plainBody() const
{
    String r;
    List<Recipient>::Iterator recipient( recipients() );
    while ( recipient ) {
        String tmp = recipient->plainTextParagraph();
        if ( !tmp.isEmpty() ) {
            r.append( tmp.wrapped( 72, "", "", true ).crlf() );
            r.append( "\r\n" );
        }
        ++recipient;
    }

    // this code sneakily ensures that the ideal line wrap point is
    // just before the server name, almost independent of the server
    // name's length. fine for testing.
    r.append( "This message was generated by Archiveopteryx " );
    r.append( Configuration::compiledIn( Configuration::Version ) );
    r.append( ", running on mail server \r\n" );
    r.append( Configuration::hostname() );
    r.append( ".\r\n" );

    if ( arrivalDate() && !receivedFrom().isEmpty() ) {
        String tmp = "\nThe message arrived at ";
        tmp.append( arrivalDate()->isoDate() );
        tmp.append( ", " );
        tmp.append( arrivalDate()->isoTime() );
        tmp.append( " from host " );
        tmp.append( receivedFrom() );
        tmp.append( "." );
        r.append( tmp.wrapped( 72, "", "", true ).crlf() );
    }
    else if ( arrivalDate() ) {
        String tmp = "\nThe message arrived at ";
        tmp.append( arrivalDate()->isoDate() );
        tmp.append( "." );
        r.append( tmp.wrapped( 72, "", "", true ).crlf() );
    }
    else if ( !receivedFrom().isEmpty() ) {
        String tmp = "\nThe message was received from host ";
        tmp.append( receivedFrom() );
        tmp.append( "." );
        r.append( tmp.wrapped( 72, "", "", true ).crlf() );
    }

    return r;
}


/*! Computes and returns the DSN bodypart. */

String DSN::dsnBody() const
{
    String r;
    // [ original-envelope-id-field CRLF ]
    if ( !envelopeId().isEmpty() )
        r.append( "Original-Envelope-Id: " + envelopeId() + "\r\n" );

    // reporting-mta-field CRLF
    r.append( "Reporting-Mta: dns;" + Configuration::hostname() + "\r\n" );

    // [ received-from-mta-field CRLF ]
    if ( !receivedFrom().isEmpty() )
        r.append( "Received-From-Mta: dns;" + receivedFrom() + "\r\n" );

    // [ arrival-date-field CRLF ]
    if ( arrivalDate() )
        r.append( "Arrival-Date: " + arrivalDate()->rfc822() + "\r\n" );

    List<Recipient>::Iterator i( recipients() );
    while ( i ) {
        r.append( "\r\n" );
        r.append( i->dsnParagraph().wrapped( 72, "", "", true ).crlf() );
        ++i;
    }
    return r;
}


/*! Returns true if this DSN object has all information it needs to
    construct a valid DSN, and false if not. If valid() returns false,
    the results of dsnBody() and message() are essentially undefined.
*/

bool DSN::valid() const
{
    List<Recipient>::Iterator i( recipients() );
    while ( i ) {
        if ( !i->valid() )
            return false;
        ++i;
    }
    if ( !message() )
        return false;
    // anything else?
    return true;
}


/*! Makes subsequent calls to result() generate a message dated \a
    date.  If this function isn't called, result() uses the current
    date and time.
*/

void DSN::setResultDate( class Date * date )
{
    d->resultDate = date;
}


/*! Reports the date of the result(), or 0 if result() will use the
    current date and time.
*/

Date * DSN::resultDate() const
{
    return d->resultDate;
}


/*! Records that message() was sent by \a address. */

void DSN::setSender( Address * address )
{
    d->sender = address;
}


/*! Returns whatever setSender() set. If setSender() has not been
    called (or was called with a null pointer as argument), sender()
    looks for a Return-Path field in message(). If all else fails,
    sender() returns a null pointer.
*/

Address * DSN::sender() const
{
    if ( d->sender )
        return d->sender;
    if ( !d->message || !d->message->header() )
        return 0;
    Header * h = d->message->header();
    List<Address> * a = h->addresses( HeaderField::ReturnPath );
    if ( !a || a->isEmpty() )
        return 0;
    return a->firstElement();
}
