// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "message.h"

#include "mailbox.h"
#include "address.h"
#include "bodypart.h"
#include "mimefields.h"
#include "annotation.h"
#include "allocator.h"
#include "codec.h"
#include "flag.h"


static const char * crlf = "\015\012";


class MessageData
    : public Garbage
{
public:
    MessageData()
        : strict( false ), uid( 0 ), mailbox( 0 ), annotations( 0 ),
          rfc822Size( 0 ), internalDate( 0 ),
          hasFlags( false ), hasHeaders( false ),
          hasBodies( false ), hasAnnotations( false )

    {}

    // we have to split this in two, so a Message object can represent
    // a database message and be close to 8 bytes in size.

    String rfc2822;
    bool strict;
    String error;

    uint uid;
    const Mailbox * mailbox;

    List<Annotation> * annotations;

    uint rfc822Size;
    uint internalDate;

    List<Flag> flags;
    bool hasFlags;
    bool hasHeaders;
    bool hasBodies;
    bool hasAnnotations;
};


/*! \class Message message.h
    The Message class is the top-level RFC822 message parser and generator.

    Its core is an email message, and its two duties are conversion to
    and from RFC822 format.

    I'm writing it towards this: It can parse messages, with the aid of
    Header and HeaderField, and split them into MIME bodyparts. It can
    verify the validity of any single message.

    This may not be what we really need. In particular, constructing
    Messages (partially) from Cache needs consideration. We'll see.

    This class also provides the utility function baseSubject(), which
    strips extras such as "Re:" and "(fwd)" off a string to find the
    presumed base subject of the message.
*/


/*! Constructs an empty Message. */

Message::Message()
    : d( new MessageData )
{
    setHeader( new Header( Header::Rfc2822 ) );
}


/*! Constructs a message by parsing the supplied \a rfc2822 text. */

Message::Message( const String & rfc2822 )
    : d( new MessageData )
{
    d->rfc2822 = rfc2822;
    d->rfc822Size = rfc2822.length();

    uint i = 0;

    setHeader( parseHeader( i, d->rfc822Size, rfc2822, Header::Rfc2822 ) );
    header()->repair();
    if ( !header()->valid() ) {
        d->error = header()->error();
        return;
    }

    HeaderField * mv = header()->field( HeaderField::MimeVersion );
    ContentType * ct = header()->contentType();
    if ( mv && ct && ct->type() == "multipart" ) {
        Bodypart::parseMultipart( i, rfc2822.length(), rfc2822,
                                  ct->parameter( "boundary" ),
                                  ct->subtype() == "digest",
                                  children(), 0, d->error );
    }
    else {
        Bodypart * bp =
            Bodypart::parseBodypart( i, rfc2822.length(), rfc2822,
                                     header(), d->error );
        children()->append( bp );
    }

    header()->simplify();

    fix8BitHeaderFields();

    List< HeaderField >::Iterator it( header()->fields() );
    while ( it && d->error.isEmpty() ) {
        if ( !it->parsed() )
            d->error = "Unable to parse header field " + it->name();
        ++it;
    }

    d->rfc822Size = rfc822().length();
}


/*! Creates and returns a Header in mode \a m by parsing the part of
    \a rfc2822 from index \a i to index \a end, not including \a
    end. \a i is changed to the index of the first unparsed character.
*/

Header * Message::parseHeader( uint & i, uint end,
                               const String & rfc2822,
                               Header::Mode m )
{
    Header * h = new Header( m );
    bool done = false;
    while ( !done ) {
        if ( i >= end )
            done = true;
        uint j = i;
        while ( rfc2822[j] >=  33 &&
                rfc2822[j] <= 127 &&
                rfc2822[j] != ':' )
            j++;
        if ( j > i && rfc2822[j] == ':' ) {
            String name = rfc2822.mid( i, j-i );
            i = j;
            i++;
            while ( rfc2822[i] == ' ' || rfc2822[i] == '\t' )
                i++;
            j = i;
            // this isn't at all pretty, is it...
            while ( j < rfc2822.length() &&
                    ( rfc2822[j] != '\n' ||
                      ( rfc2822[j] == '\n' &&
                        ( rfc2822[j+1] == ' ' || rfc2822[j+1] == '\t' ) ) ) )
                j++;
            if ( j && rfc2822[j-1] == '\r' )
                j--;
            h->add( name, rfc2822.mid( i, j-i ) );
            i = j;
            if ( rfc2822[i] == '\r' && rfc2822[i+1] == '\n' )
                i++;
            i++;
        }
        else {
            done = true;
        }
    }
    return h;
}


/*! Returns true if this message is a valid RFC2822 message, and false
    if it has known/detected errors. Returns true if the message is
    known to be incomplete.
*/

bool Message::valid() const
{
    return d->error.isEmpty();
}


/*! Returns a message describing the first detected syntax error in
    this message, or an empty string if no error has been detected.
*/

String Message::error() const
{
    return d->error;
}


/*! Returns the message formatted in RFC822 (actually 2822) format.
    The return value is a canonical expression of the message, not
    whatever was parsed.
*/

String Message::rfc822() const
{
    String r;

    r.append( header()->asText() );
    r.append( crlf );
    r.append( body() );

    return r;
}


/*! Returns the text representation of the body of this message. */

String Message::body() const
{
    String r;

    ContentType *ct = header()->contentType();
    if ( ct && ct->type() == "multipart" ) {
        appendMultipart( r );
    }
    else {
        // XXX: Is this the right place to restore this linkage?
        Bodypart * firstChild = children()->first();
        if ( firstChild ) {
            firstChild->setHeader( header() );
            appendAnyPart( r, firstChild, ct );
        }
    }

    return r;
}


static void appendChildren(List<Bodypart> *l, Bodypart *bp )
{
    l->append( bp );
    List<Bodypart>::Iterator it( bp->children() );
    while ( it ) {
        appendChildren( l, it );
        ++it;
    }
}


/*! Returns a list of all Bodypart objects within this Message. The List
    is allocated on the current Arena; the pointers point to within this
    Message and should not be changed.

    The Injector relies on children()->first() being first in the list.
*/

List<Bodypart> *Message::allBodyparts() const
{
    List< Bodypart > * l = new List< Bodypart >;
    List<Bodypart>::Iterator it( children() );
    while ( it ) {
        appendChildren( l, it );
        ++it;
    }
    return l;
}


/*! Returns a pointer to the Bodypart whose IMAP part number is \a s
    and possibly create it. Creates Bodypart objects if \a create is
    true. Returns null pointer if \a s is not valid and \a create is
    false.
*/

class Bodypart * Message::bodypart( const String & s, bool create )
{
    uint b = 0;
    Bodypart * bp = 0;
    while ( b < s.length() ) {
        uint e = b;
        while ( s[e] >= '0' && s[e] <= '9' )
            e++;
        if ( e < s.length() && s[e] != '.' )
            return 0;
        bool inrange = false;
        uint n = s.mid( b, e-b ).number( &inrange );
        b = e + 1;
        if ( !inrange || n == 0 )
            return 0;
        List<Bodypart> * c = children();
        if ( bp )
            c = bp->children();
        List<Bodypart>::Iterator i( c );
        while ( i && i->number() < n )
            ++i;
        if ( i && i->number() == n ) {
            bp = i;
        }
        else if ( create ) {
            Bodypart * child = 0;
            if ( bp )
                child = new Bodypart( n, bp );
            else
                child = new Bodypart( n, this );
            c->insert( i, child );
            bp = child;
        }
        else {
            return 0;
        }
    }
    return bp;
}


/*! Returns the IMAP part number of \a bp, which must be a part of this
    Multipart.
*/

String Message::partNumber( Bodypart * bp ) const
{
    Multipart *m = bp;

    String r;
    while( m ) {
        if ( !r.isEmpty() )
            r = "." + r;
        Multipart * parent = m->parent();
        List<Bodypart>::Iterator i;
        if ( parent )
            i = parent->children()->first();
        else
            i = children()->first();
        uint n = 1;
        while ( i && i != m ) {
            ++i;
            ++n;
        }
        if ( !i )
            return "";
        r = fn( n ) + r;
        m = parent;
    }
    return r;
}


/*! Notifies this Message that its UID is \a u, which should be
    returned by uid().

    The initial value is 0, which is not a legal UID.
*/

void Message::setUid( uint u )
{
    d->uid = u;
}


/*! Returns the UID of this Message, as set by setUid(). */

uint Message::uid() const
{
    return d->uid;
}


/*! Notifies this Message that it lives in \a m, which should be
    returned by mailbox(). The initial value is null, meaning that the
    Message does not belong to any particular Mailbox.
*/

void Message::setMailbox( const Mailbox * m )
{
    d->mailbox = m;
}


/*! Returns the Mailbox in which this Message lives, or null in case
    this Message is independent of mailboxes (e.g. a Message being
    delivered by smtpd.)
*/

const Mailbox * Message::mailbox() const
{
    return d->mailbox;
}


/*! Notifies this Message that its internaldate is \a id. The Message
    will remember \a id and internalDate() will return it.
*/

void Message::setInternalDate( uint id )
{
    d->internalDate = id;
}


/*! Returns the message's internaldate, which is meant to be the time
    when Archiveopteryx first saw it, although it actually is whatever
    was set using setInternalDate().

    If the messages comes from the database, this function's return
    value is valid only if hasTrivia();
*/

uint Message::internalDate() const
{
    return d->internalDate;
}


/*! Notifies the Message that its size is \a s bytes. The Message will
    believe and report this.
*/

void Message::setRfc822Size( uint s )
{
    d->rfc822Size = s;
}


/*! Reports the Message's size, as set using setRfc822Size() or the
    constructor. Valid only if hasTrivia();
*/

uint Message::rfc822Size() const
{
    return d->rfc822Size;
}


/*! Returns a pointer to list of extension flags for this message,
    representing all flags that are currently set.
*/

List<Flag> * Message::flags() const
{
    return &d->flags;
}


/*! Returns true if the extension flags have been loaded for this
    message, and false if not.
*/

bool Message::hasFlags() const
{
    return d->hasFlags;
}


/*! Returns true if this message has read its headers from the
    database, and false it it has not.
*/

bool Message::hasHeaders() const
{
    return d->hasHeaders;
}


/*! Returns true if this message has read its bodyparts from the
    database, and false if it has not.
*/

bool Message::hasBodies() const
{
    return d->hasBodies;
}


/*! Returns true if this message has read its annotations from the
    database, and false if it has not.
*/

bool Message::hasAnnotations() const
{
    return d->hasAnnotations;
}


/*! Records that all the message flags in this Message have been
    fetched if \a ok is true and if that they no longer are valid if
    \a ok is false.
*/

void Message::setFlagsFetched( bool ok )
{
    d->hasFlags = ok;
    if ( !ok )
        d->flags.clear();
}


/*! Records that all the bodies in this Message have been fetched. */


void Message::setHeadersFetched()
{
    d->hasHeaders = true;
}


/*! Records that all the bodies in this Message have been fetched. */

void Message::setBodiesFetched()
{
    d->hasBodies = true;
}


/*! Records that all the annotations on this Message have been
    fetched. */

void Message::setAnnotationsFetched()
{
    d->hasAnnotations = true;
}


/*! Returns true if this message knows where its towel is, and false
    if it's hopeless clueless.
*/

bool Message::hasTrivia() const
{
    return d->rfc822Size > 0;
}


/*! Tries to remove the prefixes and suffixes used by MUAs from \a subject
    to find a base subject that can be used to tie threads together
    linearly.
*/

String Message::baseSubject( const String & subject )
{
    String s( subject.simplified() );
    uint b = 0;
    uint e = s.length();

    // try to get rid of leading Re:, Fwd:, Re[2]: and similar.
    bool done = false;
    while ( !done ) {
        done = true;
        uint i = b;
        if ( s[i] == '(' ) {
            i++;
            while ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                    ( s[i] >= 'a' && s[i] <= 'z' ) )
                i++;
            if ( i - b > 2 && i - b < 5 && s[i] == ')' ) {
                done = false;
                b = i + 1;
            }
        }
        else if ( s[i] == '[' ) {
            uint j = i;
            i++;
            while ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                    ( s[i] >= 'a' && s[i] <= 'z' ) ||
                    ( s[i] >= '0' && s[i] <= '9' ) ||
                    s[i] == '-' )
                i++;
            if ( s[i] == ']' ) {
                i++;
                done = false;
                b = i;
            }
            else {
                i = j;
            }
        }
        else if ( s[i] >= 'A' && s[i] <= 'Z' ) {
            while ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                    ( s[i] >= 'a' && s[i] <= 'z' ) )
                i++;
            uint l = i - b;
            if ( s[i] == '[' ) {
                uint j = i;
                i++;
                while ( ( s[i] >= '0' && s[i] <= '9' ) )
                    i++;
                if ( s[i] == ']' )
                    i++;
                else
                    i = j;
            }
            if ( l >= 2 && l < 4 && s[i] == ':' && s[i+1] == ' ' ) {
                i++;
                b = i;
                done = false;
            }
        }
        if ( !done && s[b] == 32 )
            b++;
    }

    // try to get rid of trailing (Fwd) etc.
    done = false;
    while ( !done ) {
        done = true;
        uint i = e;
        if ( i > 2 && s[i-1] == ')' ) {
            i = i - 2;
            while ( i > 0 &&
                    ( ( s[i] >= 'A' && s[i] <= 'Z' ) ||
                      ( s[i] >= 'a' && s[i] <= 'z' ) ) )
                i--;
            if ( e - i >= 4 && e - i < 6 && s[i] == '(' ) {
                if ( i >0 && s[i-1] == ' ' )
                    i--;
                e = i;
                done = false;
            }
        }
    }

    return s.mid( b, e-b );
}


/*! Returns true. */

bool Message::isMessage() const
{
    return true;
}


/*! Adds \a a to the list of known annotations for this message,
    forgetting any previous annotation with the same
    Annotation::ownerId() and Annotation::entryName().
*/

void Message::replaceAnnotation( class Annotation * a )
{
    if ( !d->annotations )
        d->annotations = new List<Annotation>;
    List<Annotation>::Iterator it( *d->annotations );
    while ( it && ( it->ownerId() != a->ownerId() ||
                    it->entryName() != a->entryName() ) )
        ++it;
    if ( it )
        d->annotations->take( it );
    d->annotations->append( a );
}


/*! Returns a pointer to the list of annotations belonging to this
    message, or 0 if there are none.
*/

List< Annotation > * Message::annotations() const
{
    return d->annotations;
}


/*! Tries to handle unlabelled 8-bit content in header fields, in
    cooperation with Header::fix8BitFields().

    The idea is that if we know which encodings are used for the text
    bodies, and all bodies agree, then any unlabelled header fields
    probably use that encoding, too. At least if they're legal
    according to the relevant codec.

    If we can't get charset information from any body, we try to see
    if a single codec can encode the entire header, and if so, use
    that.
*/

void Message::fix8BitHeaderFields()
{
    String charset;
    String fallback = "us-ascii";
    List<Bodypart>::Iterator i( allBodyparts() );
    while ( i ) {
        ContentType * ct = 0;
        if ( i->header() )
            ct = i->header()->contentType();
        if ( ct && ct->type() == "text" ) {
            String cs = ct->parameter( "charset" ).lower();
            if ( cs.isEmpty() )
                ; // no conclusion from this part
            else if ( charset.isEmpty() )
                charset = cs; // use this charset...?
            else if ( cs != charset )
                return; // multiple charsets specified
            if ( ct && ct->subtype() == "html" )
                fallback = "iso-8859-1";
        }
        i++;
    }
    Codec * c = 0;
    if ( !charset.isEmpty() )
        c = Codec::byName( charset );
    else
        c = Codec::byString( header()->asText() );
    if ( !c )
        c = Codec::byName( fallback );
    if ( c )
        header()->fix8BitFields( c );
}
