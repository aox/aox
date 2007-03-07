// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailboxes.h"

#include "frontmatter.h"
#include "mailbox.h"
#include "query.h"
#include "link.h"


class ArchiveMailboxesData
    : public Garbage
{
public:
    ArchiveMailboxesData()
        : q( 0 )
    {}

    Query * q;
};


/*! \class ArchiveMailboxes archivemailboxes.h
    A component that displays a list of mailboxes available for
    anonymous access via the archive server.
*/


/*! Creates a new ArchiveMailboxes component. */

ArchiveMailboxes::ArchiveMailboxes()
    : PageComponent( "archivemailboxes" ),
      d( new ArchiveMailboxesData )
{
    addFrontMatter( FrontMatter::title( "Archives" ) );
}


void ArchiveMailboxes::execute()
{
    if ( !d->q ) {
        d->q = new Query( "select name from mailboxes m join "
                          "permissions p on (p.mailbox=m.id) "
                          "where p.identifier='anonymous' and "
                          "p.rights like '%r%'", this );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    String s( "<h1>Archives</h1>\n" );
    s.append( "<p><ul>\n" );

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        String name( r->getString( "name" ) );

        Mailbox * m = Mailbox::find( name );
        if ( m ) {
            Link * link = new Link;
            link->setType( Link::Archive );
            link->setMailbox( m );
            s.append( "<li><a href=\"" );
            s.append( link->canonical() );
            s.append( "\">" );
            s.append( quoted( name ) );
            s.append( "</a>\n" );
        }
    }

    s.append( "</ul>\n" );

    if ( d->q->rows() == 0 )
        s.append( "No anonymously accessible archive mailboxes." );

    setContents( s );
}
