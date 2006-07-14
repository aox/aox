// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "dsn.h"

#include "date.h"
#include "address.h"
#include "message.h"
#include "bodypart.h"
#include "stringlist.h"
#include "configuration.h"


class RecipientData
    : public Garbage
{
public:
    RecipientData()
        : originalRecipient( 0 ),
          finalRecipient( 0 ),
          action( Recipient::Unknown ),
          lastAttemptDate( 0 ) {}
    Address * originalRecipient;
    Address * finalRecipient;
    Recipient::Action action;
    String status;
    String remoteMta;
    String diagnosticCode;
    Date * lastAttemptDate;
    String finalLogId;
};


/*! \class Recipient dsn.h

    The Recipient class holds information about a particular
    recipient, collected during a delivery attempt and optionally used
    for sending DSNs.

    It sounds as if this belongs in a file of its own, not in
    dsn.cpp. However: Which? Where? Consider that later.
*/


/*!  Constructs a Recipient containing no data. The object must
     be completed using e.g. setFinalRecipient().
*/

Recipient::Recipient()
    : d( new RecipientData )
{
    // what a pity that zero-line functions may have more than zero bugs
}


/*! Records that the message was originally sent to \a a. */

void Recipient::setOriginalRecipient( class Address * a )
{
    d->originalRecipient = a;
}


/*! Returns a pointer to the original recipient's address, or a null
    pointer if none is recorded.
*/

class Address * Recipient::originalRecipient() const
{
    return d->originalRecipient;
}


/*! Records that the message was finally sent to \a a.

    Calling both setFinalRecipient() and setOriginalRecipient() with
    the same address is discouraged.
*/

void Recipient::setFinalRecipient( class Address * a )
{
    d->finalRecipient = a;
}


/*! Returns a pointer to the final recipient's address, or a null
    pointer if none is recorded.
*/

class Address * Recipient::finalRecipient() const
{
    return d->finalRecipient;
}


/*! Records that \a a is the action taken wrt. this recipient. The
    initial value is Unknown. */

void Recipient::setAction( Action a )
{
    d->action = a;
}


/*! Returns the action recorded by setAction(). */

Recipient::Action Recipient::action() const
{
    return d->action;
}


/*! Records that \a s is the status of the final delivery attempt for
    this recipient. \a s must be a string containing three numbers
    separated by dots, e.g. "1.2.3" or "1000.2000.3000". The meaning
    of the numbers is as defined in RFC 3463.
*/

void Recipient::setStatus( const String & s )
{
    d->status = s;
}


/*! Returns the status recorded by setStatus(). */

String Recipient::status() const
{
    return d->status;
}


/*! Records that \a mta is the MTA to which we attempted to deliver
    this message the last time. The initial value is empty, which
    means that we didn't try to deliver the message to any remote MTA.
*/

void Recipient::setRemoteMTA( const String & mta )
{
    d->remoteMta = mta;
}


/*! Returns the MTA recorded by setRemoteMTA(). */

String Recipient::remoteMTA() const
{
    return d->remoteMta;
}


/*! Records that \a code is the diagnostic code resulting from the
    last delivery attempt. This must be an SMTP code (ie. the RFC 3464
    diagnostic-type is always smtp), and if empty, it means that there
    is no such code. The initial value is empty.
*/

void Recipient::setDiagnosticCode( const String & code )
{
    d->diagnosticCode = code;
}


/*! Records the diagnostic code recorded by setDiagnosticCode(). */

String Recipient::diagnosticCode() const
{
    return d->diagnosticCode;
}


/*! Records that the last delivery attempt for this recipient happened
    at \a date. The initial value, null, means that no deliveries have
    been attempted.
*/

void Recipient::setLastAttempt( class Date * date )
{
    d->lastAttemptDate = date;
}


/*! Returns the last attempt date for this recipient, or a null
    pointer if no deliveries have been attempted.
*/

Date * Recipient::lastAttempt() const
{
    return d->lastAttemptDate;
}


/*! Records that during the last delivery attempt, the remote server
    issued \a id as its final log ID. If \a id is empty, no ID was
    reported and none will be reported by Recipient.
*/

void Recipient::setFinalLogId( const String & id )
{
    d->finalLogId = id;
}


/*! Returns whatever was set by setFinalLogId(), or an empty string if
    setFinalLogId() has not been called.

*/

String Recipient::finalLogId() const
{
    return d->finalLogId;
}

class DSNData
    : public Garbage
{
public:
    DSNData()
        : message( 0 ),
          full( true ),
          arrivalDate( 0 )
        {}
    Message * message;
    String envid;
    bool full;
    String receivedFrom;
    Date * arrivalDate;
    List<Recipient> recipients;
};


/*! Returns a pararaph (as single line) describing the fate of this
    Recipient.
*/

String Recipient::plainTextParagraph() const
{
    String s;
    String a;

    if ( finalRecipient() && originalRecipient() ) {
        a.append( finalRecipient()->localpart() );
        a.append( "@" );
        a.append( finalRecipient()->domain() );
        a.append( " (forwarded from " );
        a.append( originalRecipient()->localpart() );
        a.append( "@" );
        a.append( originalRecipient()->domain() );
        a.append( ")" );
    }
    else if ( finalRecipient() ) {
        a.append( finalRecipient()->localpart() );
        a.append( "@" );
        a.append( finalRecipient()->domain() );
    }
    else if ( originalRecipient() ) {
        a.append( originalRecipient()->localpart() );
        a.append( "@" );
        a.append( originalRecipient()->domain() );
    }
    else {
        return "";
    }

    switch( action() ) {
    case Unknown:
        // we do not report on this recipient.
        return "";
        break;
    case Failed:
        s = "Your message could not be delivered to ";
        s.append( a );
        s.append( ". " );
        if ( !status().isEmpty() &&
             !remoteMTA().isEmpty() ) {
            if ( lastAttempt() ) {
                s.append( "At " );
                s.append( lastAttempt()->isoDate() );
                s.append( ", " );
                s.append( lastAttempt()->isoTime() );
                s.append( ", the " );
            }
            else {
                s.append( "The " );
            }
            s.append( "next-hop server (" );
            s.append( remoteMTA() );
            s.append( ") returned the following error code: " );
            s.append( status() );
            s.append( ". This is a fatal error. Sorry." );
        }
        break;
    case Delayed:
        s = "Delivery to ";
        s.append( a );
        s.append( " is unexpectedly delayed. Delivery attempts continue." );
        // here, we want to say "the next attempt is in 25 minutes" or
        // words to that effect. Maybe we need setNextAttempt()?
        break;
    case Delivered:
        s = "Your message was delivered to ";
        s.append( a );
        s.append( "." );
        break;
    case Relayed:
        s = "While delivering to ";
            s.append( a );
        s.append( ", your message was forwarded to " );
        if ( !remoteMTA().isEmpty() ) {
            s.append( remoteMTA() );
            s.append( "," );
        }
        else {
            s.append( "a host" );
        }
        s.append( " which cannot send reports such as this one."
                  " Unless you receive an error report, you can assume"
                  " that your message arrived safely." );
        break;
    case Expanded:
        s = "Your message was delivered to ";
        s.append( a );
        s.append( ", and resent to several other addresses from there." );
        break;
    }

    return s;
}


/*! Returns a paragraph containin the DSN for this Recipient. The
    returned string contains a series of CRLF-separated lines and a
    trailing CRLF.
*/

String Recipient::dsnParagraph() const
{
    StringList l;
    String s;

    // [ original-recipient-field CRLF ]
    if ( originalRecipient() )
        l.append( "Original-Recipient: rfc822;" +
                  originalRecipient()->localpart() + "@" +
                  originalRecipient()->domain() );

    // final-recipient-field CRLF
    if ( finalRecipient() )
        l.append( "Final-Recipient: rfc822;" +
                  finalRecipient()->localpart() + "@" +
                  finalRecipient()->domain() );

    // action-field CRLF
    switch ( action() ) {
    case Unknown:
        l.append( "Action: unknown" );
        break;
    case Failed:
        l.append( "Action: failed" );
        break;
    case Delayed:
        l.append( "Action: delayed" );
        break;
    case Delivered:
        l.append( "Action: delivered" );
        break;
    case Relayed:
        l.append( "Action: relayed" );
        break;
    case Expanded:
        l.append( "Action: expanded" );
        break;
    }

    // status-field CRLF
    if ( !status().isEmpty() )
        l.append( "Status: " + status() );
    // [ remote-mta-field CRLF ]
    if ( !remoteMTA().isEmpty() )
        l.append( "Remote-Mta: dns;" + remoteMTA() );


    // [ diagnostic-code-field CRLF ]
    if ( !diagnosticCode().isEmpty() )
        l.append( "Diagnostic-Code: smtp;" + diagnosticCode() );

    // [ last-attempt-date-field CRLF ]
    if ( lastAttempt() )
        l.append( "Last-Attempt-Date: " + lastAttempt()->rfc822() );

    // [ final-log-id-field CRLF ]
    if ( !finalLogId().isEmpty() )
        l.append( "Final-Log-Id: smtp;" + finalLogId() );

    // we don't set will-retry-until. it only applies to delay dsns,
    // which we don't send.

    return l.join( "\r\n" );
}


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

    // the time of the bounce is now... or is it? would it be better
    // to use the time of the message, so the bounce's text is a bit
    // more predictable?
    Date * now = new Date;
    now->setCurrentTime();

    // the from field has to contain... what? let's try this for now.
    Address * from = new Address( Configuration::hostname(),
                                  "postmaster",
                                  Configuration::hostname() );

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

    // set up the top-level header
    Header * h = r->header();
    h->add( "Date", now->rfc822() );
    h->add( "From", from->toString() );
    if ( allOk() )
        h->add( "Subject", "Message delivered" );
    else if ( allFailed() )
        h->add( "Subject", "Message delivery failed" );
    else
        h->add( "Subject", "Message delivery partly failed" );
    h->add( "Mime-Version", "1.0" );
    h->add( "Content-Type", "multipart/report; boundary=" +
            Message::acceptableBoundary( original->asText() ) );

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
    r.append( "This message was generated at mail server " +
              Configuration::hostname() + ", \r\nrunning Archiveopteryx " +
              Configuration::compiledIn( Configuration::Version ) +
              ".\r\n\r\n" );

    if ( arrivalDate() && !receivedFrom().isEmpty() ) {
        String tmp = "The message arrived at ";
        tmp.append( arrivalDate()->isoDate() );
        tmp.append( ", " );
        tmp.append( arrivalDate()->isoTime() );
        tmp.append( " from host " );
        tmp.append( receivedFrom() );
        tmp.append( "." );
        r.append( tmp.wrapped( 72, "", "", true ).crlf() );
    }
    else if ( arrivalDate() ) {
        String tmp = "The message arrived at ";
        tmp.append( arrivalDate()->isoDate() );
        tmp.append( "." );
        r.append( tmp.wrapped( 72, "", "", true ).crlf() );
    }
    else if ( !receivedFrom().isEmpty() ) {
        String tmp = "The message was received from host ";
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
