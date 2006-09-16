// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "capability.h"

#include "scope.h"
#include "configuration.h"
#include "imap.h"
#include "stringlist.h"
#include "log.h"
#include "mechanism.h"
#include "tls.h"


/*! \class Capability capability.h
    Announces supported features (RFC 3501 section 6.1.1)

    We announce the following standard capabilities:

    RFC 3501: IMAP4rev1, STARTTLS, LOGINDISABLED.
    RFC 2086: ACL
    RFC 2088: LITERAL+
    RFC 2177: IDLE
    RFC 2971: ID
    RFC 2342: NAMESPACE
    RFC 2359: UIDPLUS
    RFC 3691: UNSELECT
    RFC 2245: AUTH=ANONYMOUS
    RFC 2595: AUTH=PLAIN
    RFC 2195: AUTH=CRAM-MD5
    RFC 2831: AUTH=DIGEST-MD5
    RFC 3516: BINARY

    We also announce a number of draft capabilities, if the
    configuration variable announce-draft-support is set to true. By
    default it's not.
*/

void Capability::execute()
{
    respond( "CAPABILITY " + capabilities( imap() ) );
    finish();
}


/*! Returns all capabilities that are applicable to \a i.*/

String Capability::capabilities( IMAP * i )
{
    bool drafts = Configuration::toggle( Configuration::AnnounceDraftSupport );
    StringList c;

    c.append( "IMAP4rev1" );

    // the remainder of the capabilities are kept sorted by name

    // ugly X-DRAFT prefixes are disregarded when sorting by name

    c.append( SaslMechanism::allowedMechanisms( "AUTH=", i->hasTls() ) );

    c.append( "ACL" );
    c.append( "ANNOTATE" );
    c.append( "BINARY" );
    c.append( "ID" );
    c.append( "IDLE" );
    if ( drafts )
        c.append( "X-DRAFT-W12-LISTEXT" );
    c.append( "LITERAL+" );
    if ( !SaslMechanism::allowed( SaslMechanism::Plain, i->hasTls() ) )
        c.append( "LOGINDISABLED" );
    c.append( "NAMESPACE" );
    if ( drafts )
        c.append( "POSTADDRESS" );
    c.append( "RIGHTS=n" );
    if ( drafts )
        c.append( "SASL-IR" );
    if ( TlsServer::available() && !i->hasTls() )
        c.append( "STARTTLS" );
    c.append( "UIDPLUS" );
    c.append( "UNSELECT" );
    if ( drafts )
        c.append( "VIEW" );

    return c.join( " " );
}
