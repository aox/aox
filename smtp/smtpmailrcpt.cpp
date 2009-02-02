// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpmailrcpt.h"

#include "configuration.h"
#include "sievescript.h"
#include "smtpparser.h"
#include "estringlist.h"
#include "address.h"
#include "mailbox.h"
#include "query.h"
#include "scope.h"
#include "sieve.h"
#include "date.h"
#include "smtp.h"
#include "user.h"


class SmtpMailFromData
    : public Garbage
{
public:
    SmtpMailFromData(): address( 0 ) {}
    Address * address;
};



/*! \class SmtpMailFrom smtpmailrcpt.h

    The SmtpMailFrom class parses and acts on the "mail from" command,
    with whatever extensions we like. Bothersome.

    The extensions currently implemented are SIZE (see RFC 1870) and
    DSN (RFC 3461).
*/

/*! Creates a new SmtpMailFrom handler from the command issued to \a s,
    which is parsed using \a p.
*/

SmtpMailFrom::SmtpMailFrom( SMTP * s, SmtpParser * p )
    : SmtpCommand( s ), d( new SmtpMailFromData )
{
    Scope x( log() );
//      "MAIL FROM:" ("<>" / Reverse-Path)
//                       [SP Mail-parameters] CRLF
    p->whitespace();
    p->require( ":" );
    p->whitespace();
    if ( p->present( "<>" ) )
        d->address = new Address( "", "", "" );
    else
        d->address = p->address();
    p->whitespace();
    if ( server()->dialect() == SMTP::Submit &&
         d->address->type() != Address::Normal &&
         d->address->type() != Address::Bounce )
        respond( 501,
                 "Address must be <> or <localpart@domain>. "
                 "Address specied was: " + d->address->toString(),
                 "5.1.0" );

    while ( p->ok() && !p->atEnd() ) {
        EString name = p->esmtpKeyword();
        p->require( "=" );
        EString value = p->esmtpValue();
        p->whitespace();
        if ( p->ok() )
            addParam( name, value );
    }
}


/*! Parses and (partly) acts on the esmtp parameter \a name, \a value
    pair. At present we don't support any, although that surely has to
    change soon.
*/

void SmtpMailFrom::addParam( const EString & name, const EString & value )
{
    if ( name == "ret" ) {
        if ( value.lower() == "full" || value.lower() == "hdrs" ) {
            // XXX do what?
        }
        else {
            respond( 501, "RET must be FULL or HDRS", "5.5.4" );
        }
    }
    else if ( name == "envid" ) {
        // XXX do what?
    }
    else if ( name == "x-oryx-id" &&
              !Configuration::toggle( Configuration::Security ) ) {
        if ( value.boring() && !value.isEmpty() )
            server()->setTransactionId( value );
        else
            respond( 501, "Transaction ID must be boring", "5.5.4" );
    }
    else if ( name == "x-oryx-time" &&
              !Configuration::toggle( Configuration::Security ) ) {
        Date * t = new Date;
        bool ok = false;
        t->setUnixTime( value.number( &ok ) );
        if ( ok )
            server()->setTransactionTime( t );
        else
            respond( 501, "Time must be a unix time", "5.5.4" );
    }
    else if ( name == "body" ) {
        if ( value.lower() == "7bit" || value.lower() == "8bitmime" ) {
            // nothing needed
        }
        else {
            respond( 501, "BODY must be 7BIT or 8BITMIME", "5.5.4" );
        }
    }
    else if ( name == "size" ) {
        bool ok = false;
        uint n = value.number( &ok );
        if ( !ok )
            respond( 501, "SIZE must be a decimal number" );
        if ( n > 100 * 1024 * 1024 )
            respond( 501, "Cannot deliver mail larger than 100MB" );
        // a configurable limit would be nice, not? perhaps even two?
    }
    else if ( name == "auth" ) {
        // RFC 2554 page 4
        log( "Responsible sender is supposedly " + value );
    }
    else {
        respond( 501,
                 "Unknown ESMTP parameter: " + name +
                 " (value: " + value + ")", "5.5.4" );
    }
}


/*! Does everything this class needs to do. First checks that the SMTP
    object doesn't have any senders or recipients yet.
*/

void SmtpMailFrom::execute()
{
    if ( !server()->isFirstCommand( this ) )
        return;

    if ( server()->dialect() == SMTP::Submit && !server()->user() ) {
        respond( 530, "User not authenticated", "5.5.0" ); // or 5.5.1?
        finish();
        return;
    }

    if ( server()->sieve()->sender() ) {
        respond( 500, "Sender address already specified: " +
                 server()->sieve()->sender()->toString(), "5.5.1" );
        finish();
        return;
    }
    // checking rcpt to is not necessary, since it already checks mail from

    if ( server()->dialect() == SMTP::Submit &&
         Configuration::toggle( Configuration::SubmitCopyToSender ) ) {
        Address * copy = 0;
        if ( server()->user()->address()->type() == Address::Normal )
            copy = server()->user()->address();
        else if ( d->address->type() == Address::Normal )
            copy = d->address;
        if ( copy ) {
            server()->sieve()->addSubmission( copy );
            respond( 0, "Will send a copy to " + copy->toString() );
        }
    }

    log( "Sender: " + d->address->toString() );
    server()->sieve()->setSender( d->address );
    if ( d->address->type() == Address::Bounce )
        respond( 250, "Accepted message from mailer-daemon",
                 "2.1.0" );
    else
        respond( 250, "Accepted message from " + d->address->toString(),
                 "2.1.0" );
    finish();
}


class SmtpRcptToData
    : public Garbage
{
public:
    SmtpRcptToData(): address( 0 ), added( false ) {}
    Address * address;
    bool added;
};


/*! \class SmtpRcptTo smtpmailrcpt.h
    This class handles the RCPT TO command.
*/

/*! Creates a new handler for \a s, using \a p to parsed the RCPT TO
    command.
*/

SmtpRcptTo::SmtpRcptTo( SMTP * s, SmtpParser * p )
    : SmtpCommand( s ), d( new SmtpRcptToData )
{
    Scope x( log() );
    p->whitespace();
    p->require( ":" );
    p->whitespace();
    d->address = p->address();
    p->whitespace();

    while ( p->ok() && !p->atEnd() ) {
        EString name = p->esmtpKeyword();
        p->require( "=" );
        EString value = p->esmtpValue();
        p->whitespace();
        if ( p->ok() )
            addParam( name, value );
    }
}


void SmtpRcptTo::execute()
{
    if ( !d->added ) {
        if ( server()->dialect() == SMTP::Submit )
            server()->sieve()->addSubmission( d->address );
        else
            server()->sieve()->addRecipient( d->address, this );
        d->added = true;
    }

    if ( !server()->isFirstCommand( this ) )
        return;

    if ( !server()->sieve()->sender() ) {
        respond( 550, "Must send MAIL FROM before RCPT TO", "5.5.1" );
        finish();
        return;
    }

    if ( !server()->sieve()->ready() )
        return;

    if ( server()->sieve()->local( d->address ) ) {
        server()->sieve()->evaluate();
        if ( !server()->sieve()->rejected( d->address ) )
            respond( 250, "Will send to " + d->address->toString().lower(),
                     "2.1.5" );
        else if ( Configuration::toggle( Configuration::SoftBounce ) )
            respond( 450, d->address->toString().lower() + " rejects mail",
                     "4.7.1" );
        else
            respond( 550, d->address->toString().lower() + " rejects mail",
                     "5.7.1" );
    }
    else {
        if ( server()->user() )
            respond( 250, "Submission accepted for " +
                     d->address->toString(), "2.1.5" );
        else if ( Configuration::toggle( Configuration::SoftBounce ) )
            respond( 450, d->address->toString() +
                     " is not a legal destination address", "4.1.1" );
        else
            respond( 550, d->address->toString() +
                     " is not a legal destination address", "5.1.1" );
    }
    if ( ok() )
        server()->addRecipient( this );
    finish();
}


/*! Parses and (partly) acts on the esmtp parameter \a name, \a value
    pair. At present we don't support any, although that surely has to
    change soon.
*/

void SmtpRcptTo::addParam( const EString & name, const EString & value )
{
    if ( name == "notify" ) {
        if ( value.lower() == "never" ) {
        }
        else {
            EStringList::Iterator v( EStringList::split( ',', value.lower() ) );
            while ( v ) {
                if ( v->lower() == "success" ) {
                    // but what do we do with these values?
                }
                else if ( v->lower() == "delay" ) {
                }
                else if ( v->lower() == "failure" ) {
                }
                else {
                    respond( 501, "Bad NOTIFY value: " + v->quoted(),
                             "5.5.4" );
                }
                ++v;
            }
        }
    }
    else if ( name == "orcpt" ) {
        if ( value.lower().startsWith( "rfc822;" ) ) {
            // the original address may legitimately be non-822
            AddressParser p( value.mid( 7 ) );
            if ( !p.error().isEmpty() ) {
                respond( 501, "Bad ORCPT: " + p.error(), "5.5.4" ); // 5.1.0?
            } else if ( p.addresses()->count() != 1 ) {
                respond( 501, "Bad ORCPT: " + fn( p.addresses()->count() ) +
                         " addresses instead of one", "5.5.4" );
            }
            else {
                if ( d->address->toString() ==
                     p.addresses()->first()->toString() ) {
                    // unnecessary orcpt, ignore this case
                }
                else {
                    // XXX real orcpt. what to do?
                }
            }

        }
    }
    else {
        respond( 501,
                 "Unknown ESMTP parameter: " + name +
                 " (value: " + value + ")", "5.5.4" );
    }
}


/*! Returns a pointer to the recipient address. If the command was
    syntactically correct, this is never a null pointer.
*/

Address * SmtpRcptTo::address() const
{
    return d->address;
}


/*! Returns true if the recipient address is remote, false if it is
    local, and true if the command hasn't been finished yet.
*/

bool SmtpRcptTo::remote() const
{
    if ( server()->sieve()->local( d->address ) )
        return false;
    return true;
}
