// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivethread.h"

#include "link.h"
#include "field.h"
#include "frontmatter.h"
#include "addressfield.h"
#include "mailboxview.h"
#include "webpage.h"
#include "message.h"
#include "header.h"

#include "archivemessage.h"


class ArchiveThreadData
    : public Garbage
{
public:
    ArchiveThreadData()
        : link( 0 ), done( false )
    {}

    Link * link;
    bool done;
};


/*! \class ArchiveThread archivethread.h
    A page component representing a view of a single mailbox.
*/


/*! Create a new ArchiveThread for \a link. */

ArchiveThread::ArchiveThread( Link * link )
    : PageComponent( "archivethread" ),
      d( new ArchiveThreadData )
{
    d->link = link;
    addFrontMatter( FrontMatter::jsToggles() );
}


void ArchiveThread::execute()
{
    if ( d->done )
        return;

    MailboxView * mv = MailboxView::find( d->link->mailbox() );
    if ( !mv->ready() ) {
        mv->refresh( this );
        return;
    }

    MailboxView::Thread * thread = mv->thread( d->link->uid() );

    uint n = 0;
    while ( n < thread->messages() ) {
        uint uid = thread->uid( n );

        Link * l = new Link;
        l->setType( d->link->type() );
        l->setMailbox( d->link->mailbox() );
        l->setUid( uid );

        page()->addComponent( new ArchiveMessage( l ) );
        n++;
    }

    d->done = true;
    setContents( " " );
}
