// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailboxlist.h"

#include "frontmatter.h"
#include "webpage.h"
#include "mailbox.h"
#include "query.h"
#include "link.h"
#include "user.h"


class MailboxListData
    : public Garbage
{
public:
    MailboxListData()
        : q( 0 )
    {}

    Query * q;
};


/*! \class MailboxList mailboxlist.h
    A component that displays a list of mailboxes belonging to the
    currently authenticated user.
*/


/*! Creates a new MailboxList component. */

MailboxList::MailboxList()
    : PageComponent( "mailboxlist" )
{
    addFrontMatter( FrontMatter::title( "Mailboxes" ) );
}


void MailboxList::execute()
{
    if ( !d ) {
        d = new MailboxListData;
        page()->requireUser();
    }

    if ( !page()->permitted() )
        return;

    if ( !d->q ) {
        d->q = new Query(
            "select name from mailboxes where owner=$1 "
            "order by name not like '%/INBOX', name ",
            this
        );
        d->q->bind( 1, page()->user()->id() );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    String s( "<h1>Mailboxes</h1>\n" );
    s.append( "<p><ul>\n" );

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        UString name( r->getUString( "name" ) );

        Mailbox * m = Mailbox::find( name );
        if ( m ) {
            Link * link = new Link;
            link->setType( Link::Webmail );
            link->setMailbox( m );
            s.append( "<li><a href=\"" );
            s.append( link->canonical() );
            s.append( "\">" );
            s.append( quoted( name ) );
            s.append( "</a>\n" );
        }
    }

    s.append( "</ul>\n" );

    setContents( s );
}
