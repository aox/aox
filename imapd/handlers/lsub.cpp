// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "lsub.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"


/*! \class Lsub lsub.h
    LIST for subscribed mailboxes (RFC 3501, §6.3.9)

    Everyone wishes that LSUB had never existed independently of LIST,
    paving the way for horrors like RLSUB. With Listext, one can treat
    LSUB as a special case of LIST (SUBSCRIBED). But we decided not to
    do that, because Listext is still (2005-01) a moving target, and
    adding a wart of this size to such a complex class feels wrong.
*/

/*! Constructs an empty LSUB handler. */

Lsub::Lsub()
    : q( 0 )
{
}


void Lsub::parse()
{
    space();
    ref = imap()->mailboxName( astring() );
    space();
    pat = listMailbox();
    end();
}


void Lsub::execute()
{
    if ( !q ) {
        q = new Query( "select * from subscriptions where owner=$1 and "
                       "mailbox like $2 order by mailbox", this );
        q->bind( 1, imap()->user()->id() );
        String like = ref;
        if ( pat[0] == '/' ) {
            uint n = 0;
            while ( n < pat.length() &&
                    ( pat[n] != '*' && pat[n] != '%' ) )
                n++;
            like = pat.mid( 0, n-1 );
        }
        q->bind( 2, like + "%" );
        q->execute();
    }

    while ( q->hasResults() ) {
        Row *r = q->nextRow();
        String m = r->getString( "mailbox" );
        String name = m.mid( ref.length() );

        if ( match( name, pat ) ) {
            String flags = "";
            Mailbox *mbx = Mailbox::find( m );

            if ( !mbx )
                flags = "\\noselect";

            respond( "LSUB (" + flags + ") \"/\" " + name );
        }
    }

    if ( !q->done() )
        return;
    finish();
}


/*! Returns true only if \a name matches the supplied \a pattern. */

bool Lsub::match( const String &name, const String &pattern )
{
    return true;
}
