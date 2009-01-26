// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailbox.h"

#include "map.h"
#include "date.h"
#include "dict.h"
#include "link.h"
#include "list.h"
#include "codec.h"
#include "field.h"
#include "query.h"
#include "integerset.h"
#include "addressfield.h"
#include "messagerendering.h"
#include "frontmatter.h"
#include "mimefields.h"
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
        return 1;
    return -1;
}


class ArchiveMailboxData
    : public Garbage
{
public:
    ArchiveMailboxData()
        : link( 0 ), af( 0 ), idate( 0 ), text( 0 )
    {}

    Link * link;
    Query * af;
    Query * idate;
    Query * text;

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
        UString text;
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
    if ( link->mailbox() )
        addFrontMatter( FrontMatter::title( link->mailbox()->name().utf8() ) );
}


void ArchiveMailbox::execute()
{
    log( "Attempting to provide archive mailbox for " +
         d->link->mailbox()->name().ascii(), Log::Debug );
    Threader * t = d->link->mailbox()->threader();

    if ( !d->af ) {
        d->af = new Query( "select mm.uid, af.position, af.address, af.field, "
                           "a.name, a.localpart, a.domain "
                           "from address_fields af "
                           "join addresses a on (af.address=a.id) "
                           "join mailbox_messages mm using (message) "
                           "where af.part='' and af.field=$2 "
                           "and mm.mailbox=$1", this );
        d->af->bind( 1, d->link->mailbox()->id() );
        d->af->bind( 2, HeaderField::From );
        d->af->execute();
    }

    if ( !d->idate ) {
        // XXX this can go into d->af now that d->af joins anyway
        d->idate = new Query( "select mm.uid, m.idate "
                              "from mailbox_messages mm "
                              "join messages m on (mm.messsage=m.id) "
                              "where mm.mailbox=$1",
                              this );
        d->idate->bind( 1, d->link->mailbox()->id() );
        d->idate->execute();
    }

    if ( !t->updated() ) {
        t->refresh( this );
        log( "Need to do threading.", Log::Debug );
        return;
    }

    log( "Mailbox contains " + fn( t->allThreads()->count() ) + " threads",
         Log::Debug );

    if ( t->allThreads()->isEmpty() ) {
        setContents( "<p>Mailbox is empty" );
        return;
    }

    if ( !d->text ) {
        List<Thread>::Iterator i( t->allThreads() );
        IntegerSet f;
        while ( i ) {
            f.add( i->members().smallest() );
            ++i;
        }
        d->text = new Query(
            "select bp.*, mm.uid, hf.value from bodyparts bp "
            "join part_numbers pn on (bp.id=pn.bodypart) "
            "join mailbox_messages mm on (mm.message=pn.message) "
            "left join header_fields hf "
            "on (hf.message=pn.message and hf.part=pn.part) "
            "where mm.mailbox=$1 "
            "and (hf.field=$2 or hf.field is null) "
            "and mm.uid=any($3) and "
            "(hf.value like 'text/html%' or "
            " hf.value like 'text/plain%' or "
            " hf.value is null) "
            "order by mm.uid, pn.part",
            this );
        d->text->bind( 1, d->link->mailbox()->id() );
        d->text->bind( 2, HeaderField::ContentType );
        d->text->bind( 3, f );
        d->text->execute();
    }

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
    }

    while ( (r=d->idate->nextRow()) ) {
        uint uid = r->getInt( "uid" );
        ArchiveMailboxData::Message * m = d->messages.find( uid );
        if ( !m )
            m = new ArchiveMailboxData::Message( uid, d );
        m->idate = r->getInt( "idate" );
    }

    while ( (r=d->text->nextRow()) ) {
        uint uid = r->getInt( "uid" );
        ContentType * ct = new ContentType;
        if ( r->isNull( "value" ) )
            ct->parse( "text/plain" );
        else
            ct->parse( r->getString( "value" ) ); // parse? is that correct?
        ArchiveMailboxData::Message * m = d->messages.find( uid );
        if ( !m )
            m = new ArchiveMailboxData::Message( uid, d );
        if ( m->text.isEmpty() ) {
            if ( ct->subtype() == "plain" ) {
                MessageRendering mr;
                mr.setTextPlain( r->getUString( "text" ) );
                m->text = mr.excerpt();
            }
            else if ( ct->subtype() == "html" ) {
                Codec * c = 0;
                if ( ct )
                    c = Codec::byName( ct->parameter( "charset" ) );
                if ( !c )
                    c = new AsciiCodec;
                MessageRendering mr;
                mr.setTextHtml( r->getString( "data" ), c );
                m->text = mr.excerpt();
            }
        }
    }

    log( String("Query doneness: ") +
         ( d->af->done() ? "af " : "" ) +
         ( d->idate->done() ? "idate " : "" ) +
         ( d->text->done() ? "text " : "" ),
         Log::Debug );

    if ( !d->af->done() )
        return;

    if ( !d->idate->done() )
        return;

    if ( !d->text->done() )
        return;

    // subjects, from and thread information is ready now.

    addresses.clear();
    String s;
    List<Thread>::Iterator
        it( t->allThreads()->sorted( (Comparator*)byFirstYid ) );
    while ( it ) {
        Thread * t = it;
        ++it;
        s.append( threadRendering( t ) );
    }

    setContents( s );
}



/*! This private helper returns a HTML rendering of \a t.
*/

String ArchiveMailbox::threadRendering( Thread * t )
{
    String s;
    List<Address> responders;
    Dict<Address> addresses;
    IntegerSet from( t->members() );
    uint i = from.count();
    while ( i ) {
        uint uid = from.value( i-- );
        if ( !d->messages.contains( uid ) )
            from.remove( uid );
    }
    if ( from.isEmpty() )
        return s;

    uint count = from.count();
    while ( i <= count ) {
        uint uid = from.value( i );
        ArchiveMailboxData::Message * m = d->messages.find( uid );
        if ( m ) {
            List< Address >::Iterator it( m->from );
            while ( it ) {
                Address * a = it;
                ++it;
                String key = a->localpart().lower();
                key.append( "@" );
                key.append( a->domain().lower() );
                if ( !addresses.contains( key ) ) {
                    addresses.insert( key, a );
                    if ( i > 1 )
                        responders.append( a );
                }
            }
        }
        i++;
    }

    ArchiveMailboxData::Message * m = d->messages.find( from.smallest() );
    Map<Address> mentioned;

    s.append( "<div class=thread>\n" );

    UString subject = t->subject();
    if ( subject.isEmpty() )
        subject.append( "(No Subject)" );
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
    if ( count > 1 ) {
        s.appendNumber( count );
        s.append( " messages, " );
    }
    else {
        s.append( "one message, " );
    }
    s.append( timespan( from ) );
    s.append( ")</div>\n" // subject
              "<div class=headerfield>From: " );
    List<Address>::Iterator it( m->from );
    while ( it ) {
        Address * a = it;
        ++it;
        s.append( address( a ) );
        if ( it )
            s.append( ", " );
        if ( !mentioned.contains( a->id() ) )
            mentioned.insert( a->id(), a );
    }
    s.append( "</div>\n" ); // from

    s.append( "<div class=messageexcerpt>\n"
              "<p>\n" );
    if ( m->text.isEmpty() ) {
        m->text.append( "(For some reason the text except isn't working. "
                        "A bug. Better fix it quickly.)" );
    }
    else {
        uint i = 0;
        while ( i < m->text.length() ) {
            uint j = i;
            while ( j < m->text.length() && m->text[j] != '\n' )
                j++;
            s.append( quoted( m->text.mid( i, j-i ) ) );
            uint k = j;
            while ( m->text[k] == '\n' )
                k++;
            if ( k == m->text.length() )
                ;
            else if ( k-j > 1 )
                s.append( "\n<p>\n" );
            else if ( k-j == 1 )
                s.append( "\n<br>\n" );
            i = k;
        }
    }
    s.append( "</div>\n" );

    if ( count > 1 ) {
        s.append( "<p><a href=\"" );
        s.append( ml.canonical() );
        s.append( "\">Read entire thread</a> (" );
        if ( from.count() > 2 ) {
            s.appendNumber( from.count() - 1 );
            s.append( " responses" );
        }
        else {
            s.append( "one response" );
        }
        if ( !responders.isEmpty() ) {
            uint r = 0;
            List<Address>::Iterator it( responders );
            uint limit = 4;
            if ( responders.count() < 7 )
                limit = 7;
            while ( it && r < limit ) {
                Address * a = it;
                ++it;
                ++r;
                if ( r == 1 )
                    s.append( ", from " );
                else if ( r == responders.count() )
                    s.append( " and " );
                else
                    s.append( ", " );
                if ( mentioned.contains( a->id() ) ) {
                    if ( a->type() == Address::Normal &&
                         !a->name().isEmpty() )
                        s.append( quoted( a->name() ) );
                    else
                        s.append( address( a ) );
                }
                else {
                    s.append( address( a ) );
                    mentioned.insert( a->id(), a );
                }
            }
            if ( limit < responders.count() ) {
                s.append( " and " );
                s.appendNumber( responders.count() - limit );
                s.append( " others" );
            }
        }
        s.append( ")." );
    }

    s.append( "</div>\n" ); // thread
    return s;
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

String ArchiveMailbox::timespan( const IntegerSet & uids ) const
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
    if ( y.year() == o.year() &&
         y.month() == o.month() &&
         y.day() == o.day() ) {
        // a single day
        r = fn( o.day() ) + " " + monthnames[o.month()-1];
        if ( o.year() < n.year() ) {
            r.append( " " );
            r.appendNumber( o.year() );
        }
    }
    else if ( o.year() < y.year() ) {
        // spans years
        r.append( monthnames[o.month()-1] );
        r.append( " " );
        r.appendNumber( o.year() );
        r.append( "&#8211;" );
        r.append( monthnames[y.month()-1] );
        r.append( " " );
        r.appendNumber( y.year() );
    }
    else if ( y.year() * 12 + y.month() + 3 >= n.year() * 12 + n.month() ) {
        // less than tree months old
        r = fn( o.day() );
        if ( o.year() != y.year() ||
             o.month() != y.month() ) {
            r.append( " " );
            r.append( monthnames[o.month()-1] );
        }
        if ( o.year() < y.year() ) {
            r.append( " " );
            r.appendNumber( o.year() );
        }
        r.append( "&#8211;" );
        r.appendNumber( y.day() );
        r.append( " " );
        r.append( monthnames[y.month()-1] );
        if ( o.year() < y.year() || y.year() < n.year() ) {
            r.append( " " );
            r.appendNumber( y.year() );
        }
    }
    else if ( o.month() < y.month() ) {
        // same year, spans months
        r.append( monthnames[o.month()-1] );
        r.append( "&#8211;" );
        r.append( monthnames[y.month()-1] );
        if ( y.year() < n.year() ) {
            r.append( " " );
            r.appendNumber( y.year() );
        }
    }
    else {
        // single month, some time ago
        r.append( monthnames[o.month()-1] );
        r.append( " " );
        r.appendNumber( o.year() );
    }
    return r;
}
