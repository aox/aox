// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "message.h"

#include "mailbox.h"
#include "address.h"
#include "bodypart.h"
#include "mimefields.h"
#include "configuration.h"
#include "annotation.h"
#include "allocator.h"
#include "entropy.h"
#include "codec.h"
#include "date.h"
#include "dict.h"
#include "md5.h"


static const char * crlf = "\015\012";


class MessageData
    : public Garbage
{
public:
    MessageData()
        : strict( false ), mailboxes( 0 ), databaseId( 0 ),
          wrapped( false ), rfc822Size( 0 ),
          hasHeaders( false ), hasAddresses( false ), hasBodies( false ),
          hasBytesAndLines( false )
    {}

    bool strict;
    String error;

    uint uid;
    class Mailbox
        : public Garbage
    {
    public:
        Mailbox()
            : Garbage(),
              mailbox( 0 ), uid( 0 ), modseq( 0 ), internalDate( 0 ),
              annotations( 0 ),
              hasFlags( false ), hasAnnotations( false ) {}
        ::Mailbox * mailbox;
        uint uid;
        int64 modseq;
        uint internalDate;
        StringList flags;
        List<Annotation> * annotations;
        bool hasFlags;
        bool hasAnnotations;
    };

    List<Mailbox> * mailboxes;
    Mailbox * mailbox( ::Mailbox * mb, bool create = false ) {
        if ( mailboxes && !mailboxes->isEmpty() &&
             mb == mailboxes->firstElement()->mailbox )
            return mailboxes->firstElement();

        List<Mailbox>::Iterator m( mailboxes );
        while ( m && m->mailbox != mb )
            ++m;
        if ( m )
            return m;
        if ( !create )
            return 0;
        if ( !mailboxes )
            mailboxes = new List<Mailbox>;
        Mailbox * n = new Mailbox;
        n->mailbox = mb;
        mailboxes->append( n );
        return n;
    }

    uint databaseId;
    bool wrapped;

    uint rfc822Size;

    bool hasHeaders: 1;
    bool hasAddresses: 1;
    bool hasBodies: 1;
    bool hasBytesAndLines : 1;
};


/*! \class Message message.h
    The Message class is the top-level RFC 822 message parser and generator.

    Its core is an email message, and its two duties are conversion to
    and from RFC 822 format.

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


/*! Constructs a message by parsing the supplied \a rfc2822 text,
    which will be set to have parent() \a p. */

Message::Message( const String & rfc2822, Multipart * p )
    : d( new MessageData )
{
    uint i = 0;

    setParent( p );
    setHeader( parseHeader( i, rfc2822.length(), rfc2822, Header::Rfc2822 ) );
    header()->repair();
    header()->repair( this, rfc2822.mid( i ) );

    ContentType * ct = header()->contentType();
    if ( ct && ct->type() == "multipart" ) {
        Bodypart::parseMultipart( i, rfc2822.length(), rfc2822,
                                  ct->parameter( "boundary" ),
                                  ct->subtype() == "digest",
                                  children(), this );
    }
    else {
        Bodypart * bp = Bodypart::parseBodypart( i, rfc2822.length(), rfc2822,
                                                 header(), this );
        children()->append( bp );
    }

    fix8BitHeaderFields();
    header()->simplify();

    String e = d->error;
    recomputeError();
    if ( d->error.isEmpty() )
        d->error = e;

    if ( !d->error.isEmpty() )
        return;
    setAddressesFetched();
    setHeadersFetched();
    setBodiesFetched();
}


/*! Asks each Header and Bodypart for error information, and sets a
    suitable error() message for the entire Message. Clears error() if
    no Header or Bodypart has an error.
*/

void Message::recomputeError()
{
    d->error.truncate();
    if ( !header()->valid() ) {
        d->error = header()->error();
        return;
    }

    List<Bodypart>::Iterator b( allBodyparts() );
    while ( b && d->error.isEmpty() ) {
        if ( b->header() && b->header() != header() ) {
            if ( !b->header()->error().isEmpty() ) {
                d->error = "In header of bodypart " + partNumber( b ) + ": " +
                           b->header()->error();
            }
            List<HeaderField>::Iterator it( b->header()->fields() );
            while ( it && d->error.isEmpty() ) {
                if ( !it->valid() )
                    d->error = "In bodypart " + partNumber( b ) +
                               ": Unable to parse header field " + it->name();
                ++it;
            }
            if ( b->message() && b->message()->header() ) {
                if ( !b->message()->header()->error().isEmpty() )
                    d->error = "In header of bodypart " + partNumber( b ) +
                               ".1: " + b->message()->header()->error();
                it = b->message()->header()->fields()->first();
                while ( it && d->error.isEmpty() ) {
                    if ( !it->valid() )
                        d->error = "In bodypart " + partNumber( b ) +
                                   ".1: Unable to parse header field " +
                                   it->name();
                    ++it;
                }
            }
        }
        if ( d->error.isEmpty() && !b->error().isEmpty() )
            d->error = "In bodypart " + partNumber( b ) + ": " + b->error();
        ++b;
    }

    // do this at the very end, so we prefer to give error messages
    // about anything else
    List<HeaderField>::Iterator it( header()->fields() );
    while ( it && d->error.isEmpty() ) {
        if ( !it->valid() )
            d->error = "Unable to parse header field " + it->name();
        ++it;
    }
}


/*! Creates and returns a Header in mode \a m by parsing the part of
    \a rfc2822 from index \a i to index \a end, not including \a
    end. \a i is changed to the index of the first unparsed character.

    If there is a leading From-space line, parseHeader() skips it and
    discards its content. Skipping is fine, but should we discard?

    Some messages copied from Courier start with a line like " Feb 12
    12:12:12 2012". This code skips that, too.
*/

Header * Message::parseHeader( uint & i, uint end,
                               const String & rfc2822,
                               Header::Mode m )
{
    if ( m == Header::Rfc2822 &&
         ( rfc2822[0] == 'F' || rfc2822[0] == ' ' ) ) {
        String beginning = rfc2822.mid( i, 5 ).lower();
        if ( beginning == "from " ||
             beginning == " jan " || beginning == " feb " ||
             beginning == " mar " || beginning == " apr " ||
             beginning == " may " || beginning == " jun " ||
             beginning == " jul " || beginning == " aug " ||
             beginning == " sep " || beginning == " oct " ||
             beginning == " nov " || beginning == " dec " ) {
            uint j = i + 5;
            while ( j < end && rfc2822[j] != '\r' && rfc2822[j] != '\n' )
                j++;
            while ( j < end && rfc2822[j] == '\r' )
                j++;
            while ( j < end && rfc2822[j] == '\n' )
                j++;
            if ( j < end )
                i = j;
        }
    }
    Header * h = new Header( m );
    bool done = false;
    uint pos = 1;
    while ( !done ) {
        if ( i >= end )
            done = true;
        if ( rfc2822[i] == 0xEF &&
             rfc2822[i+1] == 0xBB &&
             rfc2822[i+2] == 0xBF )
            i += 3;
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
            String value = rfc2822.mid( i, j-i );
            if ( !value.simplified().isEmpty() ||
                 name.lower().startsWith( "x-" ) ) {
                HeaderField * f = HeaderField::create( name, value );
                f->setPosition( pos++ );
                h->add( f );
            }
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


/*! Returns true if this message is a valid RFC 2822 message, and false
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


/*! Returns the message formatted in RFC 822 (actually 2822) format.
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


/*! Returns a list of all Bodypart objects within this Message. The
    returned pointer is never null, but may point to an empty list.

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
    Multipart * m = bp;

    String r;
    while ( m && m->isBodypart() ) {
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


/*! Notifies this Message that its UID in \a mb is \a u, which should
    be returned by uid( \a mb ).
*/

void Message::setUid( Mailbox * mb, uint u )
{
    MessageData::Mailbox * m = d->mailbox( mb, true );
    m->uid = u;
}


/*! Returns the UID of this Message in a\ mb, as set by
    setUid(). Returns 0 if setUid() has not been called for \a mb.
 */

uint Message::uid( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return m->uid;
    return 0;
}


/*! Returns true if this message is in the given mailbox \a mb, i.e. it
    was added to the mailbox using addMailbox() or addMailboxes().
*/

bool Message::inMailbox( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return true;
    return false;
}


/*! Allocates and return a sorted list of all Mailbox objects to which
    this Message belongs. addMailboxes(), setUid() and friends cause the
    Message to belong to one or more Mailbox objects.

    This may return an empty list, but it never returns a null pointer.
*/

List<Mailbox> * Message::mailboxes() const
{
    List<Mailbox> * m = new List<Mailbox>;
    List<MessageData::Mailbox>::Iterator i( d->mailboxes );
    while ( i ) {
        m->append( i->mailbox );
        ++i;
    }
    return m;
}


/*! Records that this object belongs to each of \a mailboxes.
*/

void Message::addMailboxes( List<Mailbox> * mailboxes )
{
    List<Mailbox>::Iterator i( mailboxes );
    while ( i ) {
        (void)d->mailbox( i, true );
        ++i;
    }
}


/*! Records that this Message belongs to \a mb. */

void Message::addMailbox( Mailbox * mb )
{
    d->mailbox( mb, true );
}


/*! Notifies this Message that its internaldate in \a mb is \a id. The
    Message will remember \a id and internalDate() will return it.
*/

void Message::setInternalDate( Mailbox * mb, uint id )
{
    MessageData::Mailbox * m = d->mailbox( mb, true );
    m->internalDate = id;
}


/*! Returns the message's internaldate in \a mb, which is meant to be
    the time when Archiveopteryx first saw it, although it actually is
    whatever was set using setInternalDate().

    If the messages comes from the database, this function's return
    value is valid only if hasTrivia();
*/

uint Message::internalDate( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return m->internalDate;
    return 0;
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


/*! Returns a pointer to list of flags for this message in \a mb,
    representing all flags that are currently set.

    This may return an empty list, but never a null pointer.
*/

StringList * Message::flags( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return &m->flags;
    return new StringList;
}


/*! Sets this message's flags for the mailbox \a mb to those specified
    in \a l. Duplicates are ignored. */

void Message::setFlags( Mailbox * mb, const StringList * l )
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( !m )
        return;

    Dict<void> uniq;
    StringList::Iterator it( l );
    while ( it ) {
        String f( *it );
        if ( !uniq.contains( f.lower() ) ) {
            m->flags.append( f );
            uniq.insert( f.lower(), (void *)1 );
        }
        ++it;
    }
}


/*! Sets the specified flag \a f on this message for the given mailbox
    \a mb. Does nothing if the flag is already set. */

void Message::setFlag( Mailbox * mb, const String & f )
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( !m )
        return;

    StringList::Iterator it( m->flags );
    while ( it && *it != f )
        ++it;
    if ( !it )
        m->flags.append( f );
}


/*! Returns true if the flags have been loaded for \a mb, and false if
    not.
*/

bool Message::hasFlags( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return m->hasFlags;
    return false;
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

    Messages may have different annotations in different mailboxes;
    this function's return value applies to \a mb.
*/

bool Message::hasAnnotations( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return m->hasAnnotations;
    return false;
}


/*! Records that all the message flags in \a mb have been
    fetched if \a ok is true and if that they no longer are valid if
    \a ok is false.
*/

void Message::setFlagsFetched( Mailbox * mb, bool ok )
{
    MessageData::Mailbox * m = d->mailbox( mb, ok );
    if ( m && !ok )
        m->flags.clear();
    if ( m )
        m->hasFlags = ok;
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


/*! Records that all the annotations on this Message in \a mb have
    been fetched if \a ok is true and that they haven't if \a ok is
    false.
*/

void Message::setAnnotationsFetched( Mailbox * mb, bool ok )
{
    MessageData::Mailbox * m = d->mailbox( mb, ok );
    if ( m && !ok )
        m->annotations = 0;
    if ( m )
        m->hasAnnotations = ok;
}


/*! Returns true if this message knows where its towel is, and false
    if it's hopeless and clueless.
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


/*! Adds \a a to the list of known annotations for this Message in \a
    mb, forgetting any previous annotation with the same
    Annotation::ownerId() and Annotation::entryName().
*/

void Message::replaceAnnotation( Mailbox * mb, class Annotation * a )
{
    MessageData::Mailbox * m = d->mailbox( mb, true );
    if ( !m->annotations )
        m->annotations = new List<Annotation>;
    List<Annotation>::Iterator it( m->annotations );
    while ( it && ( it->ownerId() != a->ownerId() ||
                    it->entryName() != a->entryName() ) )
        ++it;
    if ( it )
        m->annotations->take( it );
    m->annotations->append( a );
}


/*! Returns a pointer to the list of annotations in \a mb belonging to
    this message, or 0 if there are none.
*/

List<Annotation> * Message::annotations( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return m->annotations;
    return 0;
}


/*! Sets this message's annotations to \a l in the mailbox \a mb. */

void Message::setAnnotations( Mailbox * mb, List<Annotation> * l )
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( !m )
        return;
    m->annotations = l;
}


static String badFields( Header * h )
{
    StringList bad;
    List<HeaderField>::Iterator hf( h->fields() );
    while ( hf ) {
        if ( !hf->valid() )
            bad.append( hf->unparsedValue() );
        ++hf;
    }
    return bad.join( "\n" );
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
    bool conflict = false;
    List<Bodypart>::Iterator i( allBodyparts() );
    while ( i ) {
        ContentType * ct = 0;
        if ( i->header() )
            ct = i->header()->contentType();
        if ( ct && ct->type() == "text" ) {
            String cs = ct->parameter( "charset" ).lower();
            if ( cs == "windows-1252" )
                cs = "iso-8859-1";
            if ( cs.isEmpty() )
                ; // no conclusion from this part
            else if ( charset.isEmpty() )
                charset = cs; // use this charset...?
            else if ( cs != charset )
                conflict = true;
            if ( ct && ct->subtype() == "html" )
                fallback = "iso-8859-1";
        }
        i++;
    }
    Codec * c = 0;
    if ( !charset.isEmpty() )
        c = Codec::byName( charset );
    else
        c = Codec::byString( badFields( header() ) );
    if ( !c )
        c = Codec::byName( fallback );
    if ( conflict || !c )
        c = new AsciiCodec;

    header()->fix8BitFields( c );
    i = allBodyparts()->first();
    while ( i ) {
        if ( i->header() )
            i->header()->fix8BitFields( c );
        if ( i->message() && i->message()->header() )
            i->message()->header()->fix8BitFields( c );
        ++i;
    }
}


/*! Returns a short string, e.g. "c", which can be used as a mime
    boundary surrounding \a parts without causing problems.

    \a parts may be one bodypart, or several separated by CRLF. The
    important thing is that all the lines which might conflict with
    the boundary are lines in \a parts.
*/

String Message::acceptableBoundary( const String & parts )
{
    uint i = 0;
    uint boundaries = 0;
    static char boundaryChars[33] = "0123456789abcdefghijklmnopqrstuv";
    while ( i < parts.length() ) {
        if ( parts[i] == '-' && parts[i+1] == '-' ) {
            uint j = 0;
            while ( j < 32 && boundaryChars[j] != parts[i+2] )
                j++;
            if ( j < 32 )
                boundaries |= ( 1 << j );
        }
        while ( i < parts.length() && parts[i] != 10 )
            i++;
        while ( i < parts.length() && ( parts[i] == 13 || parts[i] == 10 ) )
            i++;
    }

    i = 0;
    while ( i < 32 && ( boundaries & ( 1 << i ) ) != 0 )
        i++;
    if ( i < 32 ) {
        String r;
        r.append( boundaryChars[i] );
        return r;
    }

    // in the all too likely case that some unfriendly soul tries
    // to attack us, we'd better have some alternative plan,
    // e.g. a string containing eight random base64 characters.
    String r = Entropy::asString( 6 ).e64();
    while ( parts.contains( r ) )
        // if at first you don't succeed, try again with a bigger hammer!
        r = Entropy::asString( 36 ).e64();
    return r;
}


// scans the message for a header field of the appropriate name, and
// returns the field value. The name must not contain the trailing ':'.

static String invalidField( const String & message, const String & name )
{
    uint i = 0;
    while ( i < message.length() ) {
        uint j = i;
        while ( i < message.length() &&
                message[i] != '\n' && message[i] != ':' )
            i++;
        if ( message[i] != ':' )
            return "";
        String h = message.mid( j, i-j ).headerCased();
        i++;
        j = i;
        while ( i < message.length() &&
                ( message[i] != '\n' ||
                  ( message[i] == '\n' &&
                    ( message[i+1] == ' ' || message[i+1] == '\t' ) ) ) )
            i++;
        if ( h == name )
            return message.mid( j, i-j );
        i++;
        if ( message[i] == 10 || message[i] == 13 )
            return "";
    }
    return "";
}


// looks for field in message and adds it to wrapper, if valid.

static void addField( String & wrapper,
                      const String & field, const String & message,
                      const String & dflt = "" )
{
    String value = invalidField( message, field );
    HeaderField * hf = 0;
    if ( !value.isEmpty() )
        hf = HeaderField::create( field, value );
    if ( hf && hf->valid() ) {
        wrapper.append( field );
        wrapper.append( ": " );
        wrapper.append( hf->rfc822() );
        wrapper.append( "\r\n" );
    }
    else if ( !dflt.isEmpty() ) {
        wrapper.append( field );
        wrapper.append( ": " );
        wrapper.append( dflt );
        wrapper.append( "\r\n" );
    }
}



/*! Wraps an unparsable \a message up in another, which contains a short
    \a error message, a little helpful text (or so one hopes), and the
    original message in a blob.

    \a defaultSubject is the subject text to use if no halfway
    sensible text can be extracted from \a message. \a id is used as
    content-disposition filename if supplied and nonempty.
*/

Message * Message::wrapUnparsableMessage( const String & message,
                                          const String & error,
                                          const String & defaultSubject,
                                          const String & id )
{
    String boundary = acceptableBoundary( message );
    String wrapper;

    addField( wrapper, "From", message,
              "Mail Storage Database <invalid@invalid.invalid>" );

    String subject = invalidField( message, "Subject" );
    HeaderField * hf = 0;
    if ( !subject.isEmpty() )
        hf = HeaderField::create( "Subject", subject );
    uint n = 0;
    while ( n < subject.length() && subject[n] < 127 && subject[n] >= 32 )
        n++;
    if ( hf && hf->valid() && n >= subject.length() )
        subject = "Unparsable message: " + hf->rfc822();
    else
        subject = defaultSubject;
    if ( !subject.isEmpty() )
        wrapper.append( "Subject: " + subject + "\r\n" );

    Date now;
    now.setCurrentTime();
    addField( wrapper, "Date", message, now.rfc822() );
    addField( wrapper, "To", message, "Unknown-Recipients:;" );
    addField( wrapper, "Cc", message );
    addField( wrapper, "References", message );
    addField( wrapper, "In-Reply-To", message );

    wrapper.append( "MIME-Version: 1.0\r\n"
                    "Content-Type: multipart/mixed; boundary=\"" +
                    boundary + "\"\r\n"
                    "\r\n\r\nYou are looking at an easter egg\r\n"
                    "--" + boundary + "\r\n"
                    "Content-Type: text/plain; format=flowed" ); // contd..

    String report = "The appended message was received, "
                    "but could not be stored in the mail \r\n"
                    "database on " + Configuration::hostname() +
                    ".\r\n\r\nThe error detected was: \r\n";
    report.append( error );
    report.append( "\r\n\r\n"
                   "Here are a few header fields from the message "
                   "(possibly corrupted due \r\nto syntax errors):\r\n"
                   "\r\n" );
    if ( !invalidField( message, "From" ).isEmpty() ) {
        report.append( "From:" );
        report.append( invalidField( message, "From" ) );
        report.append( "\r\n" );
    }
    if ( !invalidField( message, "Subject" ).isEmpty() ) {
        report.append( "Subject:" );
        report.append( invalidField( message, "Subject" ) );
        report.append( "\r\n" );
    }
    if ( !invalidField( message, "To" ).isEmpty() ) {
        report.append( "To:" );
        report.append( invalidField( message, "To" ) );
        report.append( "\r\n" );
    }
    report.append( "\r\n"
                   "The complete message as received is appended." );

    // but which charset does the report use?
    n = 0;
    while ( n < report.length() && report[n] < 128 )
        n++;
    if ( n < report.length() )
        wrapper.append( "; charset=unknown-8bit" ); // ... continues c-t
    wrapper.append( "\r\n\r\n" );
    wrapper.append( report );
    wrapper.append( "\r\n\r\n--" + boundary + "\r\n" );
    n = 0;
    while ( n < message.length() &&
            message[n] < 128 &&
            ( message[n] >= 32 ||
              message[n] == 10 ||
              message[n] == 13 ) )
        n++;
    if ( n < message.length() )
        wrapper.append( "Content-Type: application/octet-stream\r\n"
                        "Content-Transfer-Encoding: 8bit\r\n" );
    else
        wrapper.append( "Content-Type: text/plain\r\n" );
    wrapper.append( "Content-Disposition: attachment" );
    if ( !id.isEmpty() ) {
        wrapper.append( "; filename=" );
        if ( id.boring() )
            wrapper.append( id );
        else
            wrapper.append( id.quoted() );
    }
    wrapper.append( "\r\n\r\n" );
    wrapper.append( message );
    wrapper.append( "\r\n--" + boundary + "--\r\n" );

    Message * m = new Message( wrapper );
    m->setWrapped( true );
    return m;
}


/*! Records that this message's modseq (see RFC 4551) in \a mb is \a n. The
    initial value is 0, which is not a legal modseq. */

void Message::setModSeq( Mailbox * mb, uint n )
{
    MessageData::Mailbox * m = d->mailbox( mb, true );
    m->modseq = n;
}


/*! Returns the RFC 4551 modseq set by setModSeq( \a mb ). */

uint Message::modSeq( Mailbox * mb ) const
{
    MessageData::Mailbox * m = d->mailbox( mb );
    if ( m )
        return m->modseq;
    return 0;
}


/*! Returns true if this message has read its headers fields from the
    database, and false it it has not.
*/

bool Message::hasAddresses() const
{
    return d->hasAddresses;
}


/*! Notifies this message that it knows what addresses its address
    fields contain.
*/

void Message::setAddressesFetched()
{
    d->hasAddresses = true;
}


/*! Returns true if setBytesAndLinesFetched() has been called, false
    otherwise.
*/

bool Message::hasBytesAndLines() const
{
    return d->hasBytesAndLines;
}


/*! Notifies this message that its Bodypart objects know their
    Bodypart::numEncodedBytes() and Bodypart::numEncodedLines().
*/

void Message::setBytesAndLinesFetched()
{
    d->hasBytesAndLines = true;
}


/*! Adds a message-id header unless this message already has one. The
    message-id is based on the contents of the message, so if
    possible, addMessageId() should be called late (or better yet,
    never).
*/

void Message::addMessageId()
{
    if ( header()->field( HeaderField::MessageId ) )
        return;

    MD5 x;
    x.add( rfc822() );
    header()->add( "Message-Id",
                   "<" + x.hash().e64().mid( 0, 21 ) + ".md5@" +
                   Configuration::hostname() + ">" );
}


/*! Records that this message's database ID is \a id. This corresponds
    to the id column in the messages row.

*/

void Message::setDatabaseId( uint id )
{
    d->databaseId = id;
}


/*! Records what setDatabaseId() recorded, or 0 if setDatabaseId() has
    not been called for this object.
*/

uint Message::databaseId() const
{
    return d->databaseId;
}


/*! Records that this message is a wrapper message if \a w is true,
    and that it it's an ordinary message if not. Wrapper message (in
    this context) are those which wrap an unparsable message.

    The initial value is false, of course.
*/

void Message::setWrapped( bool w ) const
{
    d->wrapped = w;
}


/*! Returns what setWrapped() set. */

bool Message::isWrapped() const
{
    return d->wrapped;
}
