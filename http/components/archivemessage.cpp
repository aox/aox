// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemessage.h"

#include "link.h"
#include "webpage.h"
#include "frontmatter.h"
#include "permissions.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"


class ArchiveMessageData
    : public Garbage
{
public:
    ArchiveMessageData()
        : link( 0 ), message( 0 )
    {}

    Link * link;
    Message * message;
};


/*! \class ArchiveMessage archivemessage.h
    A page component representing a view of a single message.
*/


/*! Create a new ArchiveMessage for \a link. */

ArchiveMessage::ArchiveMessage( Link * link )
    : PageComponent( "archivemessage" ),
      d( new ArchiveMessageData )
{
    d->link = link;
    addFrontMatter( FrontMatter::jsToggles() );
}


void ArchiveMessage::execute()
{
    if ( !d->message ) {
        Mailbox * m = d->link->mailbox();

        page()->requireRight( m, Permissions::Read );

        d->message = new Message;
        d->message->setUid( d->link->uid() );
        List<Message> messages;
        messages.append( d->message );

        Fetcher * f;

        f = new MessageHeaderFetcher( m, &messages, this );
        f->execute();

        f = new MessageBodyFetcher( m, &messages, this );
        f->execute();

        f = new MessageAddressFetcher( m, &messages, this );
        f->execute();
    }

    if ( !page()->permitted() )
        return;

    if ( !( d->message->hasHeaders() &&
            d->message->hasAddresses() &&
            d->message->hasBodies() ) )
        return;

    String s( "<pre>" );
    s.append( quoted( d->message->rfc822() ) );
    s.append( "</pre>" );

    setContents( s );
}
