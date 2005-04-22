#include "link.h"

#include "page.h"
#include "mailbox.h"
#include "message.h"


class LinkData
{
public:
    LinkData()
        : type( Link::Error ),
          mailbox( 0 ), uid( 0 ),
          js( Link::Uncertain )
        {}
    String s;
    Link::Type type;
    Mailbox * mailbox;
    uint uid;
    Link::Javascript js;
    String error;
};


/*! \class Link page.h

    The Link class is the basic Oryx web page class. It decides what
    needs to be done based on URL path components and tells a Page to
    do it, or makes a path based on other data.
*/


/*! Constructs an empty Link. */

Link::Link()
    : d( new LinkData )
{
    
}


/*! Parses \a s as a http path. \a s must begin with a slash and
    cannot contain any escape sequences.
*/

void Link::parse( const String & s )
{
    d->s = s;
    if ( pick( "/archive" ) ) {
        d->type = ArchiveMailbox;
        mailbox();
        uid();
    }
    else if ( pick( "/webmail/folder" ) ) {
        d->type = WebmailMailbox;
        mailbox();
        uid();
    }
    else if ( pick( "/webmail" ) ) {
        d->type = Webmail;
    }

    if ( pick( "/js" ) ) {
        d->js = Enabled;
    }
    else if ( pick( "/njs" ) ) {
        d->js = Disabled;
    }
    if ( d->s.isEmpty() || d->s == "/" )
        return;
    error( "Garbage at end of URL: " + d->s );
}


/*!

*/

String Link::generate()
{
    String s;
    switch( d->type ) {
    case ArchiveMailbox:
        s = "/archive" + d->mailbox->name();
        break;
    case WebmailMailbox:
        s = "/webmail/folder" + d->mailbox->name();
        break;
    case Webmail:
        s = "/webmail";
        break;
    case ArchiveMessage:
        s = "/archive/" + d->mailbox->name() + "/" + fn( d->uid );
        break;
    case WebmailMessage:
        s = "/webmail/folder" + d->mailbox->name() + "/" + fn( d->uid );
        break;
    case Error:
        break;
    }
    return s;
}


/*!

*/

void Link::uid()
{
    if ( d->s[0] != '/' )
        return;
    uint i = 1;
    while ( d->s[i] >= '0' && d->s[i] <= '9' )
        i++;
    if ( i > 0 ) {
        bool ok = false;
        d->uid =  d->s.mid( 1, i-1 ).number( &ok );
        if ( ok ) {
            if ( d->type == ArchiveMailbox )
                d->type = ArchiveMessage;
            else if ( d->type == WebmailMailbox )
                d->type = WebmailMessage;
            d->s = d->s.mid( i );
        }
    }
}


/*! If the link's string starts with \a prefix and a slash, or if it
    is equal to \a prefix, this function returns true. In all other
    cases it returns false.
*/

bool Link::pick( const char * prefix )
{
    if ( !d->s.startsWith( prefix ) )
        return false;
    String s = d->s.mid( s.length() );
    if ( !s.isEmpty() && s[0] != '/' )
        return false;
    d->s = s;
    return true;
}


/*! Parses a mailbox name. If there isn't any, registers an error. */

void Link::mailbox()
{
    if ( d->s[0] != '/' ) {
        error( "No mailbox name present" );
        return;
    }
    Mailbox * m = Mailbox::root();
    uint s = 0;
    bool more = false;
    do {
        uint i = s + 1;
        while ( i < d->s.length() && d->s[i] != '/' )
            i++;
        String component = d->s.mid( s, i-s );
        List<Mailbox> * children = m->children();
        List<Mailbox>::Iterator it( children->first() );
        Mailbox * c = 0;
        while ( it && !c ) {
            if ( it->name() == d->s.mid( 0, i ) )
                c = it;
            ++it;
        }
        if ( c ) {
            more = true;
            m = c;
            s = i;
        }
    } while ( more );
    if ( !m ) {
        error( "Could not find valid mailbox: " + d->s );
        return;
    }
    d->s = d->s.mid( s );
    d->mailbox = m;
}



/*! Records \a msg as a parse error, assuming that no other error has
    been recorded yet. Only the first error is recorded/reported.
*/

void Link::error( const String & msg )
{
    if ( d->error.isEmpty() )
        d->error = msg;
}


/*! Returns the error message corresponding to the first error seen
    while parsing the link, or an empty string if all is well.
*/

String Link::errorMessage() const
{
    return d->error;
}
