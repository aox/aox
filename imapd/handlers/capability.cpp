#include "capability.h"

#include "configuration.h"
#include "imap.h"
#include "list.h"
#include "log.h"


static bool drafts = false;


/*! \class Capability capability.h
    Announces supported features (RFC 3501, §6.1.1)

    We announce the following capabilities:

    RFC 3501: IMAP4rev1, STARTTLS, (LOGINDISABLED).
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
    SortedList<String> c;
    c.insert( new String( "IMAP4rev1" ) );
    c.insert( new String( "LITERAL+" ) );
    c.insert( new String( "IDLE" ) );
    c.insert( new String( "ID" ) );
    c.insert( new String( "NAMESPACE" ) );
    c.insert( new String( "UNSELECT" ) );
    c.insert( new String( "AUTH=ANONYMOUS" ) );
    c.insert( new String( "AUTH=CRAM-MD5" ) );
    c.insert( new String( "AUTH=DIGEST-MD5" ) );

    if ( ::drafts ) {
        c.insert( new String( "LISTEXT" ) );
        c.insert( new String( "SASL-IR" ) );
    }

    if ( i->hasTLS() )
        c.insert( new String( "AUTH=PLAIN" ) );
    else
        c.insert( new String( "STARTTLS" ) );

    // all this just to join... how many string lists will we need?
    String r;
    SortedList<String>::Iterator it( c.first() );
    while ( it != c.end() ) {
        r.append( *it );
        if ( it != c.last() )
            r.append( " " );
        ++it;
    }
    return r;
}


/*! Sets up all configuration variables. */

void Capability::setup()
{
    Configuration::Toggle d( "announce-draft-support", true );
    ::drafts = d;
    if ( ::drafts )
        log( "Announcing support for draft IMAP extensions" );
}
