// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpauth.h"

#include "smtp.h"
#include "buffer.h"
#include "mechanism.h"
#include "smtpparser.h"


class SmtpAuthData
    : public Garbage
{
public:
    SmtpAuthData()
        : r( 0 ), m( 0 )
    {}

    String mech;
    String * r;

    SaslMechanism * m;
};


/*! \class SmtpAuth smtpauth.h
    This SmtpCommand subclass handles SMTP authentication.

    The SMTP AUTH extension is specified in RFC 2554, and is undergoing
    revision in draft-siemborski-rfc2554bis-*.
*/


/*! Creates a new SmtpAuth object for the SMTP server \a s, and uses the
    specified parser \a p to parse a single AUTH command.
*/

SmtpAuth::SmtpAuth( SMTP * s, SmtpParser * p )
    : SmtpCommand( s ), d( new SmtpAuthData )
{
    p->require( " " );

    // Accept a sasl-mech (including *gasp* lowercase letters).
    char c = p->nextChar();
    while ( ( c >= 'A' && c <= 'Z' ) ||
            ( c >= 'a' && c <= 'z' ) ||
            ( c >= '0' && c <= '9' ) ||
            ( c == '-' || c == '_' ) )
    {
        d->mech.append( c );
        p->step();
        c = p->nextChar();
    }

    // And an optional Base64-encoded initial response.
    if ( c == ' ' ) {
        p->step();
        d->r = new String;
        c = p->nextChar();
        while ( ( c >= 'A' && c <= 'Z' ) ||
                ( c >= 'a' && c <= 'z' ) ||
                ( c >= '0' && c <= '9' ) ||
                ( c == '+' || c == '/' || c == '=' ) )
        {
            p->step();
            d->r->append( c );
            c = p->nextChar();
        }
    }
    p->end();
}


/*! Conduct a SASL authentication exchange. */

void SmtpAuth::execute()
{
    if ( !d->m ) {
        if ( server()->user() ) {
            respond( 503, "Already authenticated" );
            finish();
            return;
        }

        d->m = SaslMechanism::create( d->mech, this, server()->hasTls() );
        if ( !d->m ) {
            respond( 504, "Mechanism not supported" );
            finish();
            return;
        }

        server()->setInputState( SMTP::Sasl );

        if ( d->m->state() == SaslMechanism::AwaitingInitialResponse ) {
            if ( d->r ) {
                d->m->readResponse( d->r->de64() );
                if ( !d->m->done() )
                    d->m->execute();
            }
            else {
                d->m->setState( SaslMechanism::IssuingChallenge );
            }
        }
    }

    // Now, feed the handler until it can make up its mind.

    while ( !d->m->done() &&
            ( d->m->state() == SaslMechanism::IssuingChallenge ||
              d->m->state() == SaslMechanism::AwaitingResponse ) )
    {
        if ( d->m->state() == SaslMechanism::IssuingChallenge ) {
            String c = d->m->challenge().e64();

            if ( !d->m->done() ) {
                server()->enqueue( "334 "+ c +"\r\n" );
                d->m->setState( SaslMechanism::AwaitingResponse );
                return;
            }
        }
        if ( d->m->state() == SaslMechanism::AwaitingResponse ) {
            Buffer * r = server()->readBuffer();
            String * s = r->removeLine();
            if ( !s ) {
                return;
            }
            else if ( *s == "*" ) {
                d->m->setState( SaslMechanism::Terminated );
            }
            else {
                d->m->readResponse( s->de64() );
                if ( !d->m->done() )
                    d->m->execute();
            }
        }
    }

    if ( d->m->state() == SaslMechanism::Authenticating )
        return;

    if ( !d->m->done() )
        return;

    if ( d->m->state() == SaslMechanism::Succeeded ) {
        server()->authenticated( d->m->user() );
        respond( 235, "OK" );
    }
    else if ( d->m->state() == SaslMechanism::Terminated ) {
        respond( 501, "Authentication terminated" );
    }
    else {
        respond( 535, "Authentication failed" );
    }

    server()->setInputState( SMTP::Command );
    finish();
}
