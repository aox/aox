// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpmailrcpt.h"

#include "sievescript.h"
#include "smtpparser.h"
#include "address.h"
#include "mailbox.h"
#include "query.h"
#include "sieve.h"
#include "smtp.h"


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
*/

/*! Creates a new SmtpMailFrom handler from the command issued to \a s,
    which is parsed using \a p.
*/

SmtpMailFrom::SmtpMailFrom( SMTP * s, SmtpParser * p )
    : SmtpCommand( s ), d( new SmtpMailFromData )
{
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

    while ( p->ok() && !p->atEnd() ) {
        String name = p->esmtpKeyword();
        p->require( "=" );
        String value = p->esmtpValue();
        p->whitespace();
        if ( p->ok() )
            addParam( name, value );
    }
}


/*! Parses and (partly) acts on the esmtp parameter \a name, \a value
    pair. At present we don't support any, although that surely has to
    change soon.
*/

void SmtpMailFrom::addParam( const String & name, const String & value )
{
    respond( 501,
             "Unknown ESMTP parameter: " + name + " (value: " + value + ")" );
}


/*! Does everything this class needs to do. First checks that the SMTP
    object doesn't have any senders or recipients yet.
*/

void SmtpMailFrom::execute()
{
    server()->sieve()->setSender( d->address );
    if ( d->address->type() == Address::Bounce )
        respond( 250, "Accepted message from mailer-daemon" );
    else
        respond( 250, "Accepted message from " + d->address->toString() );
    finish();
}


class SmtpRcptToData
    : public Garbage
{
public:
    SmtpRcptToData(): address( 0 ), mailbox( 0 ), query( 0 ) {}
    Address * address;
    Mailbox * mailbox;
    Query * query;
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
    p->whitespace();
    p->require( ":" );
    p->whitespace();
    d->address = p->address();
    p->whitespace();

    while ( p->ok() && !p->atEnd() ) {
        String name = p->esmtpKeyword();
        p->require( "=" );
        String value = p->esmtpValue();
        p->whitespace();
        if ( p->ok() )
            addParam( name, value );
    }
}


void SmtpRcptTo::execute()
{
    if ( !d->query ) {
        d->query = new Query(
            "select al.mailbox, s.script, m.owner "
            "from aliases al "
            "join addresses a on (al.address=a.id) "
            "join mailboxes m on (al.mailbox=m.id) "
            "left join scripts s on (s.owner=m.owner and s.active='t') "
            "where m.deleted='f' and "
            "lower(a.localpart)=$1 and lower(a.domain)=$2", this );
        d->query->bind( 1, d->address->localpart().lower() );
        d->query->bind( 2, d->address->domain().lower() );
        d->query->execute();
    }

    if ( !d->mailbox ) {
        Row * r = d->query->nextRow();
        if ( r ) {
            SieveScript * script = new SieveScript;
            d->mailbox = Mailbox::find( r->getInt( "mailbox" ) );
            if ( !r->isNull( "owner" ) )
                script->parse( r->getString( "script" ) );
            server()->sieve()->addRecipient( d->address, d->mailbox, script );
        }
    }

    if ( !d->query->done() )
        return;

    if ( d->mailbox ) {
        // the recipient is local
        server()->sieve()->evaluate();
        if ( server()->sieve()->rejected( d->address ) )
            respond( 550, d->address->toString() + " rejects mail" );
        else
            respond( 250, "Will send to " + d->address->toString() );
    }
    else {
        // the recipient is remote
        if ( server()->user() )
            respond( 250, "Submission accepted for " +
                     d->address->toString() );
        else
            respond( 450, d->address->toString() +
                     " is not a legal destination address" );
    }
    finish();
    if ( ok() )
        server()->addRecipient( this );
}


/*! Parses and (partly) acts on the esmtp parameter \a name, \a value
    pair. At present we don't support any, although that surely has to
    change soon.
*/

void SmtpRcptTo::addParam( const String & name, const String & value )
{
    respond( 501,
             "Unknown ESMTP parameter: " + name + " (value: " + value + ")" );
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
    if ( d->mailbox )
        return false;
    return true;
}
