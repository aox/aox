// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailbox.h"

#include "dict.h"
#include "link.h"
#include "field.h"
#include "frontmatter.h"
#include "addressfield.h"
#include "mailboxview.h"
#include "ustring.h"
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

    Dict<Address> addresses;
    String s;
    List<MailboxView::Thread>::Iterator it( d->mv->allThreads() );
    while ( it ) {
        Dict<Address> contributors;
        MailboxView::Thread * t = it;
        ++it;
        Message * m = t->message( 0 );

        HeaderField * hf = m->header()->field( HeaderField::Subject );
        String subject;
        if ( hf )
            subject = hf->data().simplified();
        if ( subject.isEmpty() )
            subject = "(No Subject)";
        s.append( "<div class=thread>\n"
                  "<div class=headerfield>Subject: " );
        Link ml;
        ml.setType( d->link->type() );
        ml.setMailbox( d->link->mailbox() );
        ml.setSuffix( Link::Thread );
        ml.setUid( t->uid( 0 ) );
        s.append( "<a href=\"" );
        s.append( ml.canonical() );
        s.append( "\">" );
        s.append( quoted( subject ) );
        s.append( "</a></div>\n" ); // subject

        s.append( "<div class=threadcontributors>\n" );
        s.append( "<div class=headerfield>From:\n" );
        uint i = 0;
        StringList al;
        while ( i < t->messages() && al.count() < 5 ) {
            m = t->message( i );
            AddressField * af
                = m->header()->addressField( HeaderField::From );
            if ( af ) {
                List< Address >::Iterator it( af->addresses() );
                while ( it ) {
                    String k = it->uname().utf8().lower();
                    if ( contributors.contains( k ) ) {
                        // we don't mention the name again
                    }
                    else if ( !k.isEmpty() && addresses.contains( k ) ) {
                        // we mention the name only
                        al.append( it->uname().utf8() );
                        contributors.insert( k, it );
                    }
                    else {
                        // we mention name and address
                        al.append( address( it ) );
                        contributors.insert( k, it );
                        addresses.insert( k, it );
                    }
                    ++it;
                }
            }
            i++;
        }
        if ( i < t->messages() )
            al.append( "..." );
        s.append( al.join( ", " ) );
        s.append( "\n"
                  "</div>\n" // headerfield
                  "</div>\n" // threadcontributors
                  "</div>\n" ); // thread
    }

    setContents( s );
}
