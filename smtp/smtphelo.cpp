// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtphelo.h"

#include "smtpparser.h"
#include "mechanism.h"
#include "scope.h"
#include "smtp.h"


/*! \class SmtpHelo smtphelo.h

    Models the three commands HELO, EHLO and LHLO, as specified by RFC
    2821 and RFC 4409. Kept in a separate file to reduce the #include
    clutter and dependency maze.
*/


/*! Parses and executes a HELO/EHLO/LHLO command of type \a t for \a
    s using \a p.
*/

SmtpHelo::SmtpHelo( SMTP * s, SmtpParser * p, Type t )
    : SmtpCommand( s )
{
    Scope x( log() );
    if ( t == Lhlo && s->dialect() != SMTP::Lmtp )
        respond( 500, "LHLO is valid only in LMTP" );
    else if ( s->dialect() == SMTP::Lmtp && t != Lhlo )
        respond( 500, "Need LHLO in LMTP" );
    p->whitespace();
    s->setHeloName( p->domain() );
    p->whitespace();
    p->end();
    if ( !p->ok() )
        return;
    respond( 250, Configuration::hostname() );
    if ( t == Ehlo || t == Lhlo ) {
        String auth( SaslMechanism::allowedMechanisms( "", s->hasTls() ) );
        respond( 0, "AUTH " + auth );
        // should we also send AUTH=?
        // respond( 0, "AUTH=" + auth );
        respond( 0, "BURL IMAP IMAP://" + Configuration::hostname() );
        respond( 0, "BINARYMIME" );
        respond( 0, "PIPELINING" );
        respond( 0, "8BITMIME" );
        respond( 0, "CHUNKING" );
        if ( !s->hasTls() )
            respond( 0, "STARTTLS" );
        respond( 0, "DSN" );
    }
    finish();
}
