#include "capability.h"

#include "configuration.h"
#include "imap.h"
#include "stringlist.h"
#include "log.h"
#include "mechanism.h"


static bool drafts = false;


/*! \class Capability capability.h
    Announces supported features (RFC 3501, §6.1.1)

    We announce the following capabilities:

    RFC 3501: IMAP4rev1, STARTTLS, LOGINDISABLED.
    RFC 2088: LITERAL+
    RFC 2177: IDLE
    RFC 2971: ID
    RFC 2342: NAMESPACE
    RFC 3691: UNSELECT
    RFC 2245: AUTH=ANONYMOUS
    RFC 2595: AUTH=PLAIN
    RFC 2195: AUTH=CRAM-MD5
    RFC 2831: AUTH=DIGEST-MD5

    If the configuration variable announce-draft-support is set, we
    additionally announce support for LISTEXT
    (draft-ietf-imapext-list-extensions) and SASL-IR
    (draft-siemborski-imap-sasl-initial-response).

    For the moment, announce-draft-support defaults to true. Before
    the 1.0 release, we'll change its default to false.

    (At some point, we must create a configuration variable,
    disable-plaintext-passwords, to announce LOGINDISABLED and refuse
    the relevant SASL mechanisms.)
*/

/*! \reimp */

void Capability::execute()
{
    respond( "CAPABILITY " + capabilities( imap() ) );
    finish();
}


/*! Returns all capabilities that are applicable to \a i.*/

String Capability::capabilities( IMAP * i )
{
    StringList c;

    c.append( "IMAP4rev1" );

    // the remainder of the capabilities are kept sorted by name

    if ( i->supports( "anonymous" ) )
        c.append( "AUTH=ANONYMOUS" );
    if ( i->supports( "cram-md5" ) )
        c.append( "AUTH=CRAM-MD5" );
    if ( i->supports( "digest-md5" ) )
        c.append( "AUTH=DIGEST-MD5" );
    if ( i->supports( "plain" ) )
        c.append( "AUTH=PLAIN" );

    c.append( "ID" );
    c.append( "IDLE" );
    if ( ::drafts )
        c.append( "LISTEXT" );
    c.append( "LITERAL+" );
    if ( !i->supports( "login" ) )
        c.append( "LOGINDISABLED" );
    c.append( "NAMESPACE" );
    if ( ::drafts )
        c.append( "SASL-IR" );
    if ( !i->hasTLS() )
        c.append( "STARTTLS" );
    c.append( "UNSELECT" );

    return c.join( " " );
}


/*! Sets up all configuration variables. */

void Capability::setup()
{
    Configuration::Toggle d( "announce-draft-support", true );
    ::drafts = d;
    if ( ::drafts )
        log( "Announcing support for draft IMAP extensions" );
}
