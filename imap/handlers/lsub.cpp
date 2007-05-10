// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "lsub.h"

#include "user.h"
#include "query.h"
#include "mailbox.h"

class LsubData
    : public Garbage
{
public:
    LsubData() : q( 0 ), top( 0 ), ref( 0 ), prefix( 0 ) {}

    Query * q;
    Mailbox * top;
    Mailbox * ref;
    String refname;
    uint prefix;
    String pat;

};


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
    : d( new LsubData )
{
}


void Lsub::parse()
{
    space();
    reference();
    space();
    d->pat = listMailbox();
    end();
    if ( ok() )
        log( "Lsub " + d->ref->name() + " " + d->pat );
}


void Lsub::execute()
{
    if ( !d->q ) {
        d->q = new Query( "select mailbox from subscriptions s "
                          "join mailboxes m on (s.mailbox=m.id) "
                          "where s.owner=$1 order by m.name",
                          this );
        d->q->bind( 1, imap()->user()->id() );
        d->q->execute();

        if ( d->pat[0] == '/' ) {
            d->top = Mailbox::root();
            d->prefix = 0;
        }
        else {
            d->top = d->ref;
            d->prefix = d->ref->name().length() + 1;
        }
    }


    Row * r = 0;
    while ( (r=d->q->nextRow()) != 0 ) {
        Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );

        Mailbox * p = m;
        while ( p && p != d->top )
            p = p->parent();
        if ( p ) {
            p = m;
            if ( !p->deleted() &&
                 match( d->pat, 0, p->name().lower(), d->prefix ) == 2 ) {
                String flags = "";
                if ( p != m || p->synthetic() || p->deleted() )
                    flags = "\\noselect";
                m = p;
                Mailbox * home = imap()->user()->home();
                while ( p && p != home )
                    p = p->parent();
                uint l = 0;
                if ( p == home )
                    l = home->name().length() + 1;
                // we quote a little too much here. we don't quote if
                // the string is 1*astring-char. we could also include
                // list-wildcards in the quote-free set.
                respond( "LSUB (" + flags + ") \"/\" " +
                         imapQuoted( m->name().mid( l ), AString ) );
            }
        }
    }

    if ( d->q->done() )
        finish();
}


/*! This copy of Listext::reference() has to die... but first we have
    to find out how to make Lsub into a thinnish wrapper around the
    Listext functionality.
*/

void Lsub::reference()
{
    d->refname = astring();

    if ( d->refname[0] == '/' )
        d->ref = Mailbox::obtain( d->refname, false );
    else if ( d->refname.isEmpty() )
        d->ref = imap()->user()->home();
    else
        d->ref = Mailbox::obtain( imap()->user()->home()->name() +
                                  "/" + d->refname,
                                  false );

    if ( !d->ref )
        error( No, "Cannot find reference name " + d->refname );
}
