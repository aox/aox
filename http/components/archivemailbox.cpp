// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailbox.h"

#include "map.h"
#include "date.h"
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


static int byFirstYid( const Thread ** t1, const Thread ** t2 ) {
    if ( !t1 || !t2 || !*t1 || !*t2 )
        die( Memory );
    uint u1 = (*t1)->members().smallest();
    uint u2 = (*t2)->members().smallest();
    if ( u1 == u2 )
        return 0;
    else if ( u1 < u2 )
        return -1;
    return 1;
}


class ArchiveMailboxData
    : public Garbage
{
public:
    ArchiveMailboxData()
        : link( 0 ), af( 0 ), idate( 0 )
    {}

    Link * link;
    Query * af;
    Query * idate;

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
        uint idate;
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

    if ( !d->idate ) {
        d->idate = new Query( "select uid, idate "
                              "from messages where mailbox=$1",
                              this );
        d->idate->bind( 1, d->link->mailbox()->id() );
        d->idate->execute();
    }

    if ( !t->updated() ) {
        t->refresh( this );
        return;
    }

    if ( !d->af->done() )
        return;

    if ( !d->idate->done() )
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

    while ( (r=d->idate->nextRow()) ) {
        uint uid = r->getInt( "uid" );
        ArchiveMailboxData::Message * m = d->messages.find( uid );
        if ( m )
            m->idate = r->getInt( "idate" );
    }

    // subjects, from and thread information is ready now.

    addresses.clear();
    String s;
    List<Thread>::Iterator it( t->allThreads()->sorted( (Comparator*)byFirstYid ) );
    while ( it ) {
        Map<Address> contributors;
        Thread * t = it;
        ++it;

        MessageSet from( t->members().intersection( uids ) );
        uint count = from.count();
        // XXX is subject utf8 or pgutf8? change to ustring
        String subject = t->subject();
        if ( subject.isEmpty() )
            subject = "(No Subject)";
        s.append( "<div class=thread>\n" );
        s.append( "<div class=headerfield>Subject: " );
        Link ml;
        ml.setType( d->link->type() );
        ml.setMailbox( d->link->mailbox() );
        ml.setSuffix( Link::Thread );
        ml.setUid( from.smallest() );
        s.append( "<a href=\"" );
        s.append( ml.canonical() );
        s.append( "\">" );
        s.append( quoted( subject ) );
        s.append( "</a>" );
        s.append( " (" );
        s.append( timespan( from ) );
        s.append( ")</div>\n" ); // subject

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


static const char * monthnames[12] = {
    "January", "February", "March",
    "April", "May", "June",
    "July", "August", "September",
    "October", "November", "December"
};


/*! Returns a HTML string describing the time span of the messages in
    \a uids.
*/

String ArchiveMailbox::timespan( const MessageSet & uids ) const
{
    uint oidate = UINT_MAX;
    uint yidate = 0;
    uint i = 0;
    uint count = uids.count();
    while ( i++ < count ) {
        uint uid = uids.value( i );
        ArchiveMailboxData::Message * m = d->messages.find( uid );
        if ( m ) {
            if ( m->idate > yidate )
                yidate = m->idate;
            if ( m->idate < oidate )
                oidate = m->idate;
        }
    }

    Date o;
    o.setUnixTime( oidate );
    Date y;
    y.setUnixTime( yidate );
    Date n;
    n.setCurrentTime();
    
    String r;
    if ( o.year() < y.year() ) {
        // spans years
        r.append( monthnames[o.month()-1] );
        r.append( " " );
        r.append( fn( o.year() ) );
        r.append( "&#8211;" );
        r.append( monthnames[y.month()-1] );
        r.append( " " );
        r.append( fn( y.year() ) );
    }
    else if ( y.year() * 12 + y.month() + 3 >= n.year() * 12 + n.month() ) {
        // less than tree months old
        r = fn( o.day() ) + " " + monthnames[o.month()-1];
        if ( o.year() < n.year() ) {
            r.append( " " );
            r.append( fn( o.year() ) );
        }
        r.append( "&#8211;" );
        r.append( fn( y.day() ) );
        r.append( " " );
        r.append( monthnames[y.month()-1] );
        if ( y.year() < n.year() ) {
            r.append( " " );
            r.append( fn( y.year() ) );
        }
    }
    else if ( o.month() < y.month() ) {
        // same year, spans months
        r.append( monthnames[o.month()-1] );
        r.append( "&#8211;" );
        r.append( monthnames[y.month()-1] );
        if ( y.year() < n.year() ) {
            r.append( " " );
            r.append( fn( y.year() ) );
        }
    }
    else {
        // single month, some time ago
        r.append( monthnames[o.month()-1] );
        r.append( " " );
        r.append( fn( o.year() ) );
    }
    return r;
}
