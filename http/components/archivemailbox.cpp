// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailbox.h"

#include "link.h"
#include "field.h"
#include "frontmatter.h"
#include "addressfield.h"
#include "mailboxview.h"
#include "webpage.h"
#include "message.h"
#include "header.h"


class ArchiveMailboxData
    : public Garbage
{
public:
    ArchiveMailboxData()
        : link( 0 ), mv( 0 )
    {}

    Link * link;
    MailboxView * mv;
};


/*! \class ArchiveMailbox archivemailbox.h
    A page component representing a view of a single mailbox.
*/


/*! Create a new ArchiveMailbox for \a link. */

ArchiveMailbox::ArchiveMailbox( Link * link )
    : PageComponent( "archivemailbox" ),
      d( new ArchiveMailboxData )
{
    d->link = link;
    addFrontMatter( FrontMatter::jsToggles() );
}


void ArchiveMailbox::execute()
{
    if ( !d->mv ) {
        Mailbox * m = d->link->mailbox();
        page()->requireRight( m, Permissions::Read );
        d->mv = MailboxView::find( m );
    }

    if ( !page()->permitted() )
        return;

    if ( !d->mv->ready() ) {
        d->mv->refresh( this );
        return;
    }

    if ( d->mv->count() == 0 ) {
        setContents( "<p>Mailbox is empty" );
        return;
    }

    String s;
    List<MailboxView::Thread>::Iterator it( d->mv->allThreads() );
    while ( it ) {
        MailboxView::Thread * t = it;
        ++it;
        Message * m = t->message( 0 );
        String url( d->link->canonical() );
        if ( !url.endsWith( "/" ) )
            url.append( "/" );
        url.append( fn( t->uid( 0 ) ) );

        HeaderField * hf = m->header()->field( HeaderField::Subject );
        String subject;
        if ( hf )
            subject = hf->data().simplified();
        if ( subject.isEmpty() )
            subject = "(No Subject)";
        s.append( "<div class=thread>\n"
                  "<div class=headerfield>Subject: " );
        s.append( quoted( subject ) );
        s.append( "</div>\n" ); // subject

        s.append( "<div class=threadcontributors>\n" );
        s.append( "<div class=headerfield>From:\n" );
        uint i = 0;
        while ( i < t->messages() ) {
            m = t->message( i );
            s.append( "<a href=\"" );
            s.append( url );
            if ( i > 0 ) {
                s.append( "#" );
                s.append( fn( t->uid( i ) ) );
            }
            s.append( "\">" );
            AddressField * af
                = m->header()->addressField( HeaderField::From );
            if ( af ) {
                List< Address >::Iterator it( af->addresses() );
                while ( it ) {
                    s.append( address( it ) );
                    ++it;
                    if ( it )
                        s.append( ", " );
                }
            }
            s.append( "</a>" );
            i++;
            if ( i < t->messages() )
                s.append( "," );
            s.append( "\n" );
        }
        s.append( "</div>\n" // headerfield
                  "</div>\n" // threadcontributors
                  "</div>\n" ); // thread
    }

    setContents( s );
}
