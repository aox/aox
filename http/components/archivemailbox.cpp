// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailbox.h"

#include "map.h"
#include "dict.h"
#include "link.h"
#include "list.h"
#include "field.h"
#include "query.h"
#include "messageset.h"
#include "addressfield.h"
#include "frontmatter.h"
#include "threader.h"
#include "ustring.h"
#include "webpage.h"
#include "message.h"
#include "mailbox.h"
#include "header.h"


class ArchiveMailboxData
    : public Garbage
{
public:
    ArchiveMailboxData()
        : link( 0 ), af( 0 )
    {}

    Link * link;
    Query * af;

    class Message
        : public Garbage
    {
    public:
        Message( uint u, ArchiveMailboxData * d )
            : uid( u ) {
            d->messages.insert( u, this );
        }

        uint uid;
        List<Address> from;
    };

    Map<Message> messages;
    
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
    Threader * t = d->link->mailbox()->threader();
    if ( !t->updated() )
        t->refresh( this );

    if ( !d->af ) {
        d->af = new Query( "select af.uid, af.position, af.address, af.field, "
                           "a.name, a.localpart, a.domain "
                           "from address_fields af "
                           "join addresses a on (af.address=a.id) "
                           "left join deleted_messages dm "
                           " on (af.mailbox=dm.mailbox and af.uid=dm.uid) "
                           "where af.mailbox=$1 and af.part='' "
                           "and af.field=$2 and dm.uid is null", this );
        d->af->bind( 1, d->link->mailbox()->id() );
        d->af->bind( 2, HeaderField::From );
        d->af->execute();
    }

    if ( !d->af->done() || !t->updated() )
        return;

    if ( t->allThreads()->isEmpty() ) {
        setContents( "<p>Mailbox is empty" );
        return;
    }

    MessageSet uids;
    Row * r;
    Map<Address> addresses;
    while ( (r=d->af->nextRow()) ) {
        uint uid = r->getInt( "uid" );
        ArchiveMailboxData::Message * m = d->messages.find( uid );
        if ( !m )
            m = new ArchiveMailboxData::Message( uid, d );
        uint aid = r->getInt( "address" );
        Address * a = addresses.find( aid );
        if ( !a ) {
            a = new Address( r->getUString( "name" ),
                             r->getString( "localpart" ),
                             r->getString( "domain" ) );
            a->setId( aid );
            addresses.insert( aid, a );
        }
        m->from.append( a ); 
        uids.add( uid );
    }

    // subjects, from, to, cc and thread information is ready now.

    addresses.clear();
    String s;
    List<Thread>::Iterator it( t->allThreads() );
    while ( it ) {
        Map<Address> contributors;
        Thread * t = it;
        ++it;
        
        String subject = t->subject(); // ick! utf-8 evil here
        if ( subject.isEmpty() )
            subject = "(No Subject)";
        s.append( "<div class=thread>\n"
                  "<div class=headerfield>Subject: " );
        MessageSet from( t->members().intersection( uids ) );
        uint count = from.count();
        Link ml;
        ml.setType( d->link->type() );
        ml.setMailbox( d->link->mailbox() );
        ml.setSuffix( Link::Thread );
        ml.setUid( from.smallest() );
        s.append( "<a href=\"" );
        s.append( ml.canonical() );
        s.append( "\">" );
        s.append( quoted( subject ) );
        s.append( "</a></div>\n" ); // subject

        s.append( "<div class=threadcontributors>\n" );
        s.append( "<div class=headerfield>From:\n" );
        uint i = 0;
        StringList al;
        while ( !from.isEmpty() && al.count() < 5 ) {
            uint uid = from.smallest();
            from.remove( uid );
            ArchiveMailboxData::Message * m = d->messages.find( uid );
            if ( m ) {
                List< Address >::Iterator it( m->from );
                while ( it ) {
                    uint k = it->id();
                    if ( contributors.contains( k ) ) {
                        // we don't mention the name again
                    }
                    else if ( addresses.contains( k ) && 
                              !it->name().isEmpty() ) {
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
        if ( !from.isEmpty() )
            al.append( "..." );
        s.append( al.join( ", " ) );
        if ( !from.isEmpty() || count > al.count() ) {
            s.append( " (" );
            s.append( fn( count ) );
            s.append( " messages)" );
        }
        s.append( "\n"
                  "</div>\n" // headerfield
                  "</div>\n" // threadcontributors
                  "</div>\n" ); // thread
    }

    setContents( s );
}
