// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "resetkey.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"


/*! \class ResetKey resetkey.h
    Implements the RESETKEY command specified in URLAUTH (RFC 4467).

    This command is used to reset the access key, either for a named
    mailbox, or for all of the user's mailboxes, thereby invalidating
    any URLAUTHs generated for those mailboxes. In either case, this
    class does nothing but delete existing keys, because GENURLAUTH
    will generate them on demand.
*/

ResetKey::ResetKey()
    : q( 0 )
{
}


void ResetKey::parse()
{
    if ( nextChar() == ' ' ) {
        space();
        name = astring();
        if ( nextChar() == ' ' ) {
            space();

            String mechanism;
            char c = nextChar();
            while ( c >= 'a' && c <= 'z' ||
                    c >= 'A' && c <= 'Z' ||
                    c >= '0' && c <= '9' ||
                    c == '-' || c == '.' )
            {
                step();
                mechanism.append( c );
                c = nextChar();
            }

            if ( mechanism.lower() != "internal" )
                error( Bad, "Unknown authorization mechanism: " + mechanism );
        }
    }

    end();
}


void ResetKey::execute()
{
    if ( !q ) {
        Mailbox * m = 0;
        String query( "delete from access_keys where userid=$1" );
        if ( !name.isEmpty() ) {
            m = mailbox( name );
            if ( !m || m->synthetic() || m->deleted() ) {
                error( No, "Can't reset keys on mailbox " + name );
                return;
            }
            query.append( " and mailbox=$2" );
        }

        q = new Query( query, this );
        q->bind( 1, imap()->user()->id() );
        if ( m )
            q->bind( 2, m->id() );
        q->execute();
    }

    if ( !q->done() )
        return;

    if ( q->failed() ) {
        error( No, "Couldn't reset key: " + q->error() );
        return;
    }

    // XXX: We're supposed to send this to every session that has the
    // mailbox selected. How? -- AMS
    setRespTextCode( "URLMECH INTERNAL" );
    finish();
}
