// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivethread.h"

#include "link.h"
#include "field.h"
#include "frontmatter.h"
#include "integerset.h"
#include "error404.h"
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

    if ( !page()->permitted() )
        return;

    d->done = true;

    List<SubjectThread>::Iterator it( t->subjectThreads() );
    SubjectThread * thread = 0;
    while ( it && !thread ) {
        if ( it->members().contains( d->link->uid() ) )
            thread = it;
        ++it;
    }

    if ( !thread ) {
        page()->addComponent( new Error404( d->link ), this );
        setContents( "<!-- Hi. There is no message with uid " +
                     fn( d->link->uid() ) + ". Really. Trust me. -->\n" );
        return;
    }

    PageComponent * after = this;
    IntegerSet messages( thread->members() );
    while ( !messages.isEmpty() ) {
        uint uid = messages.smallest();
        messages.remove( uid );

        Link * l = new Link;
        l->setType( d->link->type() );
        l->setMailbox( d->link->mailbox() );
        l->setUid( uid );

        ArchiveMessage * am = new ArchiveMessage( l );
        am->setLinkToThread( false );
        page()->addComponent( am, after );
        after = am;
        am->execute();
    }
    setContents( " " );
}
