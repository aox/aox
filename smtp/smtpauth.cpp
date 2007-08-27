// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpauth.h"

#include "smtp.h"
#include "user.h"
#include "scope.h"
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
    Scope x( log() );
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
            respond( 503, "Already authenticated", "5.0.0" );
            finish();
            return;
        }

        d->m = SaslMechanism::create( d->mech, this, server() );
        if ( !d->m ) {
            respond( 504, "Mechanism " + d->mech.quoted() + " not available",
                     "5.5.4" );
            finish();
            return;
        }

        server()->setInputState( SMTP::Sasl );
        d->m->readInitialResponse( d->r );
    }

    if ( d->m )
        d->m->readResponse( server()->readBuffer()->removeLine() );

    if ( !d->m->done() )
        return;

    if ( d->m->state() == SaslMechanism::Succeeded ) {
        if ( d->m->user()->login() == "anonymous" ) {
            respond( 235, "You may not submit mail", "2.0.0"  );
        }
        else {
            server()->authenticated( d->m->user() );
            respond( 235, "OK", "2.0.0" );
        }
    }
    else if ( d->m->state() == SaslMechanism::Terminated ) {
        respond( 501, "Authentication terminated", "5.0.0" );
    }
    else {
        respond( 535, "Authentication failed", "5.0.0" );
        if ( d->m->user() &&
             !d->m->user()->login().isEmpty() )
            log( "Authentication failed for " + d->m->user()->login() );
    }

    server()->setInputState( SMTP::Command );
    finish();
}
