// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivethread.h"

#include "link.h"
#include "field.h"
#include "frontmatter.h"
#include "messageset.h"
#include "threader.h"
#include "webpage.h"
#include "mailbox.h"
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

    A page component representing a view of a single mailbox. What? Is
    that really what this thing does?
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

    Mailbox * m = d->link->mailbox();
    page()->requireRight( m, Permissions::Read );

    Threader * t = m->threader();
    if ( !t->updated() ) {
        t->refresh( this );
        return;
    }

    d->done = true;

    List<Thread>::Iterator it( t->allThreads() );
    Thread * thread = 0;
    while ( it && !thread ) {
        if ( it->members().contains( d->link->uid() ) )
            thread = it;
        ++it;
    }

    if ( !page()->permitted() )
        return;

    // I wonder if it wouldn't be better to add the messages as
    // top-level components of the web page, just after this one. then
    // this could have content, which we'll want.

    MessageSet messages( thread->members() );
    while ( !messages.isEmpty() ) {
        uint uid = messages.smallest();
        messages.remove( uid );

        Link * l = new Link;
        l->setType( d->link->type() );
        l->setMailbox( d->link->mailbox() );
        l->setUid( uid );

        addSubComponent( new ArchiveMessage( l ) );
    }
}
