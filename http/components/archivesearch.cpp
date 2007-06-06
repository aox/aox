// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivesearch.h"

#include "link.h"
#include "field.h"
#include "mailbox.h"
#include "ustring.h"
#include "frontmatter.h"
#include "addressfield.h"
#include "messageset.h"
#include "threader.h"
#include "webpage.h"
#include "message.h"
#include "header.h"
#include "query.h"

#include "archivemessage.h"


class ArchiveSearchData
    : public Garbage
{
public:
    ArchiveSearchData()
        : link( 0 ), done( false )
    {}

    Link * link;
    List<Query> queries;
    bool done;
};


/*! \class ArchiveSearch archivesearch.h
    A page component representing the results of a search.
*/


/*! Create a new ArchiveSearch for \a link. */

ArchiveSearch::ArchiveSearch( Link * link )
    : PageComponent( "archivesearch" ),
      d( new ArchiveSearchData )
{
    d->link = link;
    addFrontMatter( FrontMatter::jsToggles() );
}


void ArchiveSearch::execute()
{
    if ( d->done )
        return;

    Mailbox * m = d->link->mailbox();
    Threader * t = m->threader();

    page()->requireRight( m, Permissions::Read );
    
    if ( !t->updated() )
        t->refresh( this );

    if ( !page()->permitted() )
        return;

    if ( d->queries.isEmpty() ) {
        Link * l = page()->link();
        UString * terms = l->arguments()->find( "query" );
        if ( !terms || terms->isEmpty() ) {
            d->done = true;
            // so is this what we ought to do? perhaps we could bring
            // up an advanced search box, or a help box? or both?
            setContents( "<p>Error: No query specified." );
            return;
        }

        StringList::Iterator term( StringList::split( ' ', terms->utf8() ) );
        while ( term ) {
            bool addressSearch = false;
            bool domainSearch = false;
            String localpart;
            String domain;
            if ( term->contains( '@' ) ) {
                StringList * l = StringList::split( '@', *term );
                if ( l->count() == 2 ) {
                    localpart = l->first()->lower();
                    domain = l->last()->lower();
                    uint i = 0;
                    bool alpha = false;
                    bool ok = true;
                    while ( ok && i < domain.length() ) {
                        char c = domain[i];
                        if ( c == '.' ) {
                            if ( i == 0 || i == domain.length() - 1 ||
                                 domain[i+1] == '.' )
                                ok = false;
                        }
                        else if ( c >= 'a' && c <= 'z' ) {
                            alpha = true;
                        }
                        else if ( c >= '0' && c <= '9' ) {
                        }
                        else if ( c == '-' ) {
                        }
                        else {
                            ok = false;
                        }
                        i++;
                    }
                    if ( ok ) {
                        if ( localpart.isEmpty() )
                            domainSearch = true;
                        else
                            addressSearch = true;
                    }
                }
            }
            Query * q = 0;
            if ( domainSearch ) {
                q = new Query( "select uid from address_fields af "
                               "left join deleted_messages dm "
                               " using (mailbox,uid) "
                               "join addresses a on (af.address=a.id) "
                               "where af.mailbox=$1 and dm.uid is null and "
                               "lower(a.domain)=$2",
                           this );
                q->bind( 2, localpart );
                q->bind( 3, domain );
            }
            else if ( addressSearch ) {
                q = new Query( "select uid from address_fields af "
                               "left join deleted_messages dm "
                               " using (mailbox,uid) "
                               "join addresses a on (af.address=a.id) "
                               "where af.mailbox=$1 and dm.uid is null and "
                               "lower(a.localpart)=$2 and lower(a.domain)=$3",
                               this );
                q->bind( 2, localpart );
                q->bind( 3, domain );
            }
            else {
                String s;
                s = "select s.uid from "
                    "(select mailbox,uid from header_fields where"
                    " mailbox=$1 and field=20 and value ilike '%'||$2||'%'"
                    " union"
                    " select pn.mailbox,pn.uid from part_numbers pn"
                    " join bodyparts b on (pn.bodypart=b.id) where"
                    " pn.mailbox=$1 and b.text ilike '%'||$2||'%') s "
                    "left join deleted_messages dm "
                    "on (s.mailbox=dm.mailbox and s.uid=dm.uid) "
                    "where dm.uid is null";

                q = new Query( s, this );
                q->bind( 2, *terms );
            }
            q->bind( 1, d->link->mailbox()->id() );
            q->execute();
            ++term;
            d->queries.append( q );
        }
    }

    List<Query>::Iterator q( d->queries );
    while ( q && q->done() )
        ++q;
    if ( q )
        return;

    MessageSet matchesAll;
    matchesAll.add( 1, UINT_MAX );
    MessageSet matchesSome;

    q = d->queries;
    while ( q ) {
        MessageSet results;
        Row * r;
        while ( (r=q->nextRow()) )
            results.add( r->getInt( "uid" ) );
        matchesSome.add( results );
        matchesAll = matchesAll.intersection( results );
        ++q;
    }

    Dict<Address> addresses;

    List<Thread> all;
    List<Thread> some;

    List<Thread>::Iterator i( t->allThreads() );
    while ( i ) {
        if ( !i->members().intersection( matchesAll ).isEmpty() )
            all.append( i );
        else if ( !i->members().intersection( matchesSome ).isEmpty() )
            some.append( i );
        ++i;
    }

    String s;

    s.append( fn( matchesSome.count() + matchesAll.count() ) +
              " results found in " +
              fn( some.count() + all.count() ) +
              " threads.\n" );

    i = all.first();
    bool stillAll = true;
    while ( i ) {
        s.append( "<div class=matchingthread>\n" );
        Link l;
        l.setType( d->link->type() );
        l.setMailbox( d->link->mailbox() );
        l.setUid( i->members().smallest() );
        l.setSuffix( Link::Thread );
        s.append( "<a href=" );
        s.append( l.canonical() );
        s.append( ">" );
        s.append( i->subject() ); // XXX ustring and encoding
        s.append( "</a><br>\n" );
        MessageSet matching( i->members() );
        s.append( "Contains " );
        s.append( fn ( matching.count() ) );
        s.append( " messages, " );
        s.append( fn ( matching.intersection( matchesSome ).count() ) );
        s.append( " matching.\n" );
        s.append( "</div>\n" ); //matchingthread
        ++i;
        if ( !i && stillAll ) {
            i = some.first();
            stillAll = false;
        }
    }

    // except that if there's just one or a very few threads, we want
    // to display that/those threads.

    // or we want to display the individual messages in twoLines mode,
    // and get the ArchiveMessage object to put the twoLines around
    // the search terms. sound good.

    setContents( s );
    d->done = true;
}
