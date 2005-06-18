// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "lsub.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"


/*! \class Lsub lsub.h
    LIST for subscribed mailboxes (RFC 3501 section 6.3.9)

    Everyone wishes that LSUB had never existed independently of LIST,
    paving the way for horrors like RLSUB. With Listext, one can treat
    LSUB as a special case of LIST (SUBSCRIBED). But we decided not to
    do that, because Listext is still (2005-01) a moving target, and
    adding a wart of this size to such a complex class feels wrong.
*/

/*! Constructs an empty LSUB handler. */

Lsub::Lsub()
    : q( 0 ), ref( 0 ), pfxl( 0 )
{
}


void Lsub::parse()
{
    space();
    reference();
    space();
    pat = listMailbox();
    end();
}


void Lsub::execute()
{
    if ( !q ) {
        q = new Query( "select * from subscriptions where owner=$1 and "
                       "mailbox like $2", this );
        q->bind( 1, imap()->user()->id() );
        String like = combinedName( ref, pat );
        uint slash = 0;
        uint i = 0;
        while ( i < like.length() && like[i] != '%' && like[i] != '*' ) {
            if ( like[i] == '/' )
                slash = i;
            i++;
        }
        like = like.mid( i ) + "/%";
        q->bind( 2, like + "%" );
        q->execute();
    }

    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        String name = r->getString( "mailbox" );

        if ( match( name, 0, pat, 0 ) == 2 ) {
            String flags = "";
            Mailbox * m = Mailbox::find( name );
            if ( !m )
                flags = "\\noselect";

            respond( "LSUB (" + flags + ") \"/\" " + name.mid( pfxl ) );
        }
    }

    if ( !q->done() )
        return;
    finish();
}


/*! This copy of Listext::reference() has to die... but first we have
    to find out how to make Lsub into a thinnish wrapper around the
    Listext functionality.
*/

void Lsub::reference()
{
    String name = astring();

    pfxl = imap()->user()->home()->name().length() + 1;

    if ( name[0] == '/' ) {
        ref = Mailbox::obtain( name, false );
        pfxl = 0;
    }
    else if ( name.isEmpty() ) {
        ref = imap()->user()->home();
    }
    else {
        ref = Mailbox::obtain( imap()->user()->home()->name() + "/" + name,
                               false );
    }

    if ( !ref )
        error( No, "Cannot find reference name " + name );
}
