// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivesearch.h"

#include "link.h"
#include "field.h"
#include "mailbox.h"
#include "ustring.h"
#include "frontmatter.h"
#include "addressfield.h"
#include "mailboxview.h"
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
        : link( 0 ), mv( 0 ), query( 0 ), done( false )
    {}

    Link * link;
    MailboxView * mv;
    Query * query;
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

    if ( !d->mv ) {
        Mailbox * m = d->link->mailbox();
        page()->requireRight( m, Permissions::Read );
        d->mv = MailboxView::find( m );
    }

    if ( !page()->permitted() )
        return;

    if ( !d->mv->ready() ) {
        d->mv->refresh( page() );
        return;
    }

    if ( !d->query ) {
        Link * l = page()->link();
        String * terms = l->arguments()->find( "query" );
        if ( !terms || terms->simplified().isEmpty() ) {
            d->done = true;
            setContents( "<p>Error: No query specified." );
            return;
        }

        // XXX: check that *terms not only contains @, but that the
        // domain looks more or less reasonable.
        if ( terms->find( '@' ) > 0 ) {
            d->query =
                new Query(
                    "select uid from address_fields af "
                    "left join deleted_messages dm using (mailbox,uid) "
                    "join addresses a on (af.address=a.id) "
                    "where af.mailbox=$1 and dm.uid is null and "
                    "lower(a.localpart)=$2 and lower(a.domain)=$3",
                    this
                );
            String localpart = terms->mid( 0, terms->find( '@' ) ).lower();
            String domain = terms->mid( 1 + terms->find( '@' ) ).lower();
            d->query->bind( 1, d->link->mailbox()->id() );
            d->query->bind( 2, localpart );
            d->query->bind( 3, domain );
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

            d->query = new Query( s, this );
            d->query->bind( 1, d->link->mailbox()->id() );
            d->query->bind( 2, *terms );
        }
        d->query->execute();
    }

    if ( !d->query->done() )
        return;

    Dict<Address> addresses;
    String s;

    s.append( fn( d->query->rows() ) + " results found.<br>" );

    Row * r = d->query->nextRow();
    while ( r ) {
        Dict<Address> contributors;
        uint uid = r->getInt( "uid" );

        MailboxView::Thread * t = d->mv->thread( uid );
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
        r = d->query->nextRow();
    }

    setContents( s );
    d->done = true;
}
