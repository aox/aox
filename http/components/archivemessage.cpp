// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemessage.h"

#include "link.h"
#include "webpage.h"
#include "ustring.h"
#include "stringlist.h"
#include "frontmatter.h"
#include "permissions.h"
#include "messagerendering.h"
#include "addressfield.h"
#include "mimefields.h"
#include "bodypart.h"
#include "fetcher.h"
#include "mailbox.h"
#include "message.h"
#include "header.h"
#include "date.h"
#include "utf.h"


class ArchiveMessageData
    : public Garbage
{
public:
    ArchiveMessageData()
        : link( 0 ), message( 0 ), linkToThread( true )
    {}

    Link * link;
    Message * message;
    String js;
    String buttons;
    bool linkToThread;
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

        Fetcher * f = new Fetcher( m, &messages, page() );
        f->fetch( Fetcher::OtherHeader );
        f->fetch( Fetcher::Body );
        f->fetch( Fetcher::Addresses );
        f->execute();
    }

    if ( !page()->permitted() )
        return;

    if ( !( d->message->hasHeaders() &&
            d->message->hasAddresses() &&
            d->message->hasBodies() ) )
        return;

    if ( d->link == page()->link() ) {
        FrontMatter * n = new FrontMatter( "title" );
        String subject = d->message->header()->subject(); // XXX UString
        if ( subject.length() > 20 ) {
            int space = subject.find( ' ', 15 );
            if ( space < 0 || space > 22 )
                space = 17;
            n->append( quoted( subject.mid( 0, space ) ) );
            n->append( "&#8230;" ); // ellipsis
        }
        else {
            n->append( quoted( subject ) );
        }

        List<Address>::Iterator i;
        i = d->message->header()->addresses( HeaderField::From );
        if ( i ) {
            n->append( " (" );
            while ( i ) {
                Address * a = i;
                ++i;
                if ( a->uname().isEmpty() ) {
                    n->append( quoted( a->localpart() ) );
                    n->append( "@" );
                    n->append( quoted( a->domain() ) );
                }
                else {
                    n->append( quoted( a->uname() ) );
                }
            }
            n->append( ")" );
        }
        addFrontMatter( n );
    }

    setContents( message( d->message, d->message ) );
}


/*! Returns an HTML representation of the Bodypart \a bp, which belongs
    to the Message \a first.
*/

String ArchiveMessage::bodypart( Message *first, Bodypart *bp )
{
    String s;
    Utf8Codec u;

    Link l;
    l.setType( d->link->type() );
    l.setMailbox( d->link->mailbox() );
    l.setUid( first->uid() );
    l.setPart( first->partNumber( bp ) );

    String type = "text/plain";
    ContentType *ct = bp->header()->contentType();
    if ( ct )
        type = ct->type() + "/" + ct->subtype();

    if ( type == "text/plain" ) {
        s.append( "<div class=body>\n" );
        MessageRendering r;
        r.setTextPlain( bp->text() );
        s.append( r.asHtml() );
        s.append( "</div>\n" );
    }
    else if ( type == "text/html" ) {
        s.append( "<div class=body>\n" );
        ContentType * ct = bp->contentType();
        Codec * c = 0;
        if ( ct )
            c = Codec::byName( ct->parameter( "charset" ) );
        if ( !c )
            c = new AsciiCodec;
        MessageRendering r;
        r.setTextHtml( bp->data(), c );
        s.append( r.asHtml() );
        s.append( "</div>\n" );
    }
    else if ( type == "message/rfc822" ) {
        s.append( "<div class=body>\n" );
        s.append( message( first, bp->message() ) );
        s.append( "</div>\n" );
    }
    else if ( type.startsWith( "image/" ) ) {
        s.append( "<div class=image>" );
        s.append( "<a href=\"" + l.canonical() + "\">" );
        s.append( "<img src=\"" + l.canonical() + "\">" );
        s.append( "</a></div>\n" );
    }
    else if ( type.startsWith( "multipart/" ) ) {
        s.append( "<div class=multipart>\n" );
        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            s.append( bodypart( first, it ) );
            ++it;
        }
        s.append( "</div>\n" );
    }
    else {
        s.append( "<div class=unknown>\n" );

        s.append( "<p>Unknown content type: " );
        s.append( type );
        s.append( "\n" );
        s.append( "<p><a href=\"" + l.canonical() + "\">" );
        s.append( "Save" );

        String fn;
        ContentDisposition * cd = bp->header()->contentDisposition();
        if ( cd )
            fn = cd->parameter( "filename" );
        if ( ct && fn.isEmpty() )
            fn = ct->parameter( "filename" );
        if ( !fn.isEmpty() ) {
            // XXX i18n unfriendly; enforces "verb object" order
            s.append( " " );
            s.append( quoted( fn ) );
        }

        s.append( "</a>" );
        s.append( " (size " );
        s.append( String::humanNumber( bp->numBytes() ) );
        s.append( ")</div>\n" );
    }

    return s;
}


/*! Returns an HTML representation of the Message \a m, which belongs to
    the Message \a first.
*/

String ArchiveMessage::message( Message *first, Message *m )
{
    bool topLevel = false;
    if ( first == m )
        topLevel = true;

    String s;
    String t;
    HeaderField *hf;
    bool dateShown = false;

    String h;
    h.append( addressField( m, HeaderField::From ) );
    hf = m->header()->field( HeaderField::Subject );
    if ( hf ) {
        h.append( "<div class=headerfield>Subject: " );
        h.append( quoted( hf->value() ) );
        h.append( "</div>\n" );
    }
    h.append( addressField( m, HeaderField::To ) );
    Date * messageDate = m->header()->date();
    if ( messageDate ) {
        Date now;
        now.setCurrentTime();
        if ( messageDate->unixTime() > now.unixTime() ||
             messageDate->unixTime() < now.unixTime() - 3 * 60 * 30 ) {
            dateShown = true;
            h.append( date( messageDate, "Date" ) );
        }

    }

    String o;
    o.append( "<div class=optionalheader>\n" );
    o.append( addressField( m, HeaderField::Cc ) );

    List< HeaderField >::Iterator it( m->header()->fields() );
    while ( it ) {
        hf = it;
        ++it;

        if ( hf->type() != HeaderField::Subject &&
             hf->type() != HeaderField::From &&
             hf->type() != HeaderField::To &&
             hf->type() != HeaderField::Cc &&
             ( !dateShown || hf->type() != HeaderField::Date ) )
        {
            if ( hf->type() <= HeaderField::LastAddressField ) {
                o.append( addressField( m, hf->type() ) );
            }
            else if ( hf->type() == HeaderField::Date ||
                      hf->type() == HeaderField::OrigDate ||
                      hf->type() == HeaderField::ResentDate ) {
                o.append( date( m->header()->date(), hf->name() ) );
            }
            else {
                o.append( "<div class=headerfield>" );
                o.append( quoted( hf->name() ) );
                o.append( ": " );
                o.append( quoted( hf->value().simplified() ) );
                o.append( "</div>\n" );
            }
        }

    }
    h.append( jsToggle( o, false,
                        "Show full header", "Hide full header" ) );
    if ( d->linkToThread ) {
        Link l;
        l.setType( d->link->type() );
        l.setMailbox( d->link->mailbox() );
        l.setUid( d->link->uid() );
        l.setSuffix( Link::Thread );
        d->buttons.append( "<a href=" );
        d->buttons.append( l.canonical().quoted() );
        d->buttons.append( ">Show message in context</a><br>\n" );
    }
    if ( d->link->canonical() != page()->link()->canonical() ) {
        d->buttons.append( "<a href=" );
        d->buttons.append( d->link->canonical().quoted() );
        d->buttons.append( ">Show message alone</a><br>\n" );
    }

    h.append( "</div>\n" ); // optionalHeader

    s.append( "<div class=message>\n" );
    if ( !d->js.isEmpty() ) {
        s.append( "<script language=javascript type=\"text/javascript\">\n" );
        s.append( d->js );
        s.append( "</script>\n" );
        d->js.truncate();
    }
    s.append( "<div class=header>\n" );
    if ( !d->buttons.isEmpty() ) {
        s.append( "<div class=jsonly>"
                  "<div class=buttons style=\"float:right\">\n" );
        s.append( d->buttons );
        s.append( "</div>" // buttons
                  "</div>" // jsonly
                  "\n" );
        d->buttons.truncate();
    }
    s.append( h );
    s.append( "</div>\n" ); // header

    s.append( "<div class=messagebody>" );

    List< Bodypart >::Iterator jt( m->children() );
    while ( jt ) {
        s.append( bodypart( first, jt ) );
        ++jt;
    }

    if ( topLevel )
        s.append( "</div>\n" ); // messagebody

    s.append( "</div>\n" ); // message

    return s;
}


/*! Returns an HTML representation of the address field of type \a t in
    the message \a m.
*/

String ArchiveMessage::addressField( Message *m, HeaderField::Type t )
{
    String s;

    AddressField *af = m->header()->addressField( t );
    if ( !af )
        return s;

    s.append( "<div class=headerfield>" );
    s.append( af->name() );
    s.append( ": " );

    List< Address >::Iterator it( af->addresses() );
    while ( it ) {
        s.append( address( it ) );
        ++it;
        if ( it )
            s.append( ", " );
    }

    s.append( "</div>\n" );
    return s;
}


/*! Returns a string where \a html is wrapped in javascript magic to
    show and hide it on command. \a show and \a hide are the texts to
    be used. If \a visible is true, the text is visible if javascript
    is not availble, if \a visible is false, the text is hidden in
    that case.

    At some point in the future, we probably want to have this
    function return an empty string if \a visible is false and we
    somehow know the browser does not execute javascript.
*/


String ArchiveMessage::jsToggle( const String &html,
                                 bool visible,
                                 const String &show,
                                 const String &hide )
{
    uint u = uniqueNumber();

    String v = "text" + fn( u );
    String f = "button" + fn( u );

    d->js.append(
        "var " + v + "=" + ( visible ? "true" : "false" ) + ";\n"
        "function " + f + "(){\n"
        "if(" + v + "){\n"
        "" + v + "=false;\n"
        "hide('" + v + "');\n"
        "setButtonText('" + f + "'," + quoted(show).quoted('\'') + ");\n"
        "}else{"
        "" + v + "=true;\n"
        "reveal('" + v + "');\n"
        "setButtonText('" + f + "'," + quoted(hide).quoted('\'') + ");\n"
        "}\n"
        "}\n" );

    d->buttons.append( "<a id=" + f + " onclick='" + f + "()'>" );
    if ( visible )
        d->buttons.append( quoted( hide ) );
    else
        d->buttons.append( quoted( show ) );
    d->buttons.append( "</a><br>\n" );

    String s;
    s.append( "<div id=" + v );
    if ( visible )
        s.append( " class=njsvisible>\n" );
    else
        s.append( " class=njshidden>\n" );

    s.append( html );

    s.append( "</div>\n" );

    return s;
}


#if 0
/* Returns a HTML-formatted string containing the first two lines or
    so of \a m.

    This function heuristically picks the "first" bodypart and even
    more heuristically looks for the "first" text in that bodypart.

    If no bodyparts can be used, this function returns an empty string.
*/

String ArchiveMessage::twoLines( Message * m )
{
    List<Bodypart>::Iterator bp( m->allBodyparts() );
    String type;
    while ( bp && type != "text/plain" && type != "text/html" ) {
        type = "text/plain";
        ContentType * ct = bp->header()->contentType();
        if ( ct )
            type = ct->type() + "/" + ct->subtype();
    }

    if ( !bp )
        return;

    if ( type == "text/html" )
        return;

    String r;
    Utf8Codec u; // XXX UString needs find() and more.
    String b = u.fromUnicode( bp->text() );
    int i = 0;
    while ( i >= 0 && b[i] == '>' && b[i] > ' ' ) {
        i = b.find( '\n', i + 1 );
        if ( i >= 0 )
            i++;
    }
    int e = b.find( '\n', i + 1 );
    if ( e < i )
        e = b.length();
    r = textPlain( b.mid( i, e-i ) );
}
#endif


/*! Instructs this component to include a link to the surrounding
    thread if \a l is true, and to omit it if \a l is false. The
    default is to include the link.
*/

void ArchiveMessage::setLinkToThread( bool l )
{
    d->linkToThread = l;
}


/*! Returns whatever setLinkToThread() set. */

bool ArchiveMessage::linkToThread() const
{
    return d->linkToThread;
}


/*! Returns HTML to describe a \a name field with value \a date. \a
    name is typically Date, but can also be Resent-Date or
    Original-Date.
*/

String ArchiveMessage::date( class Date * date, const String & name ) const
{
    String s;
    s.append( "<div class=headerfield>" );
    s.append( quoted( name ) );
    s.append( ": " );
    s.append( quoted( date->rfc822() ) );
    s.append( "</div>\n" );
    return s;
}
