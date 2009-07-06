// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
#include "flag.h"
#include "md5.h"


static const char * crlf = "\015\012";


class MessageData
    : public Garbage
{
public:
    MessageData()
        : databaseId( 0 ),
          wrapped( false ), rfc822Size( 0 ), internalDate( 0 ),
          hasHeaders( false ), hasAddresses( false ), hasBodies( false ),
          hasTrivia( false ), hasBytesAndLines( false )
    {}

    EString error;

    uint databaseId;
    bool wrapped;

    uint rfc822Size;
    uint internalDate;

    bool hasHeaders: 1;
    bool hasAddresses: 1;
    bool hasBodies: 1;
    bool hasTrivia : 1;
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


/*! Wipes out old message content and replaces it with a parse tree
    based on \a rfc2822.
*/

void Message::parse( const EString & rfc2822 )
{
    uint i = 0;

    children()->clear();

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

    EString e = d->error;
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
                               const EString & rfc2822,
                               Header::Mode m )
{
    Header * h = new Header( m );
    bool done = false;
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
        if ( j == i + 4 && m == Header::Rfc2822 &&
             rfc2822.mid( i, j-i+1 ).lower() == "from " ) {
            while ( i < end && rfc2822[i] != '\r' && rfc2822[i] != '\n' )
                i++;
            while ( rfc2822[i] == '\r' )
                i++;
            if ( rfc2822[i] == '\n' )
                i++;
        }
        else if ( j > i && rfc2822[j] == ':' ) {
            EString name = rfc2822.mid( i, j-i );
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
            EString value = rfc2822.mid( i, j-i );
            if ( !value.simplified().isEmpty() ||
                 name.lower().startsWith( "x-" ) ) {
                HeaderField * f = HeaderField::create( name, value );
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

EString Message::error() const
{
    return d->error;
}


/*! Returns the message formatted in RFC 822 (actually 2822) format.
    The return value is a canonical expression of the message, not
    whatever was parsed.
*/

EString Message::rfc822() const
{
    EString r;
    if ( d->rfc822Size )
        r.reserve( d->rfc822Size );
    else
        r.reserve( 50000 );

    r.append( header()->asText() );
    r.append( crlf );
    r.append( body() );

    return r;
}


/*! Returns the text representation of the body of this message. */

EString Message::body() const
{
    EString r;

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

class Bodypart * Message::bodypart( const EString & s, bool create )
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
            if ( n == 1 && !i->header() ) {
                // it's possible that i doesn't have a header of its
                // own, and that the parent message's header functions
                // as such. link it in if that's the case.
                Header * h = header();
                if ( bp && bp->message() )
                    h = bp->message()->header();
                if ( h && ( !h->contentType() ||
                            h->contentType()->type() != "multipart" ) )
                    i->setHeader( h );
            }
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

EString Message::partNumber( Bodypart * bp ) const
{
    Multipart * m = bp;

    EString r;
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


/*! Notifies this Message that its internaldate is \a id. The Message
    will remember \a id and internalDate() will return it.
*/

void Message::setInternalDate( uint id )
{
    d->internalDate = id;
}


/*! Returns the message's internaldate mb, which is meant to be the
    time when Archiveopteryx first saw it, although it actually is
    whatever was set using setInternalDate().

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


/*! Records that all the bodies in this Message have been fetched. */


void Message::setHeadersFetched()
{
    d->hasHeaders = true;
}


/*! Records that all the bodies in this Message have been fetched. */

void Message::setBodiesFetched()
{
    setBytesAndLinesFetched();
    d->hasBodies = true;
}


/*! Returns true if this message knows its internalDate() and
    rfc822Size(), and false if not.
*/

bool Message::hasTrivia() const
{
    return d->hasTrivia;
}


/*! Records that the message now has correct values for internalDate()
    and rfc822Size() if \a ok is true, and that it doesn't if \a ok is
    false.
*/

void Message::setTriviaFetched( bool ok )
{
    d->hasTrivia = ok;
}


/*! Tries to remove the prefixes and suffixes used by MUAs from \a subject
    to find a base subject that can be used to tie threads together
    linearly.
*/

UString Message::baseSubject( const UString & subject )
{
    // Comments and syntax mostly quoted on RFC 5256.

    // The basic algorithm here is: Loop for (only) as long as the
    // string grows shorter.

    // (1) Convert any RFC 2047 encoded-words in the subject to
    //     [UTF-8] as described in "Internationalization
    //     Considerations".  Convert all tabs and continuations to
    //     space.  Convert all multiple spaces to a single space.

    // We also convert other space characters than SP to space, and
    // convert to titlecase here.

    UString s( subject.simplified().titlecased() );

    // step 5 starts here
    uint l6 = UINT_MAX;
    do {
        l6 = s.length();

        // from this point on, s must be simplified at the end of each
        // step.

        // (2) Remove all trailing text of the subject that matches
        //     the subj-trailer ABNF; repeat until no more matches are
        //     possible.

        // subj-trailer    = "(fwd)" / WSP

        while ( s.endsWith( "(FWD)" ) )
            s = s.mid( 0, s.length() - 5 ).simplified();

        // step 5 starts here.
        uint l5 = UINT_MAX;
        do {
            l5 = s.length();

            // (3) Remove all prefix text of the subject that matches
            //     the subj-leader ABNF.

            // subj-refwd      = ("re" / ("fw" ["d"])) *WSP [subj-blob] ":"
            // subj-blob       = "[" *BLOBCHAR "]" *WSP
            // subj-leader     = (*subj-blob subj-refwd) / WSP

            uint l3 = UINT_MAX;
            while ( s.length() < l3 ) {
                l3 = s.length();
                uint i = 0;
                bool blob = true;
                while ( blob && s[i] == '[' ) {
                    uint j = i+1;
                    while ( j < s.length() && s[j] != '[' && s[j] != ']' )
                        j++;
                    if ( s[j] == ']' ) {
                        j++;
                        if ( s[j] == ' ' )
                            j++;
                    }
                    else {
                        blob = false;
                    }
                    if ( blob )
                        i = j;
                }
                if ( s[i] == 'R' && s[i+1] == 'E' ) {
                    i += 2;
                }
                else if ( s[i] == 'F' && s[i+1] == 'W' ) {
                    i += 2;
                    if ( s[i] == 'D' )
                        i++;
                }
                else {
                    i = 0;
                }
                if ( i ) {
                    if ( s[i] == ' ' )
                        i++;
                    blob = true;
                    while ( blob && s[i] == '[' ) {
                        uint j = i+1;
                        while ( j < s.length() && s[j] != '[' && s[j] != ']' )
                            j++;
                        if ( s[j] == ']' ) {
                            j++;
                            if ( s[j] == ' ' )
                                j++;
                        }
                        else {
                            blob = false;
                        }
                        if ( blob )
                            i = j;
                    }
                    if ( s[i] == ':' )
                        s = s.mid( i+1 ).simplified();
                }
            }

            // (4) If there is prefix text of the subject that matches
            //     the subj-blob ABNF, and removing that prefix leaves
            //     a non-empty subj-base, then remove the prefix text.

            // subj-blob       = "[" *BLOBCHAR "]" *WSP

            uint i = 0;
            if ( s[0] == '[' ) {
                i++;
                while ( i < s.length() && s[i] != '[' && s[i] != ']' )
                    i++;
                if ( s[i] == ']' ) {
                    i++;
                    if ( s[i] == ' ' )
                        i++;
                }
                else {
                    i = 0;
                }
            }
            if ( i ) {
                UString rest = s.mid( i ).simplified();
                if ( !rest.isEmpty() )
                    s = rest;
            }

            // (5) Repeat (3) and (4) until no matches remain.
        } while ( s.length() < l5 );

        // (6) If the resulting text begins with the subj-fwd-hdr ABNF
        //     and ends with the subj-fwd-trl ABNF, remove the
        //     subj-fwd-hdr and subj-fwd-trl and repeat from step (2).

        // subj-fwd-hdr    = "[fwd:"
        // subj-fwd-trl    = "]"

        if ( s.startsWith( "[FWD:" ) && s.endsWith( "]" ) )
            s = s.mid( 5, s.length() - 6 ).simplified();
        else
            l6 = 0;
    } while ( s.length() < l6 );

    return s;
}


/*! Returns true. */

bool Message::isMessage() const
{
    return true;
}


static EString badFields( Header * h )
{
    EStringList bad;
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
    EString charset;
    EString fallback = "us-ascii";
    bool conflict = false;
    List<Bodypart>::Iterator i( allBodyparts() );
    while ( i ) {
        ContentType * ct = 0;
        if ( i->header() )
            ct = i->header()->contentType();
        if ( ct && ct->type() == "text" ) {
            EString cs = ct->parameter( "charset" ).lower();
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
        ++i;
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

EString Message::acceptableBoundary( const EString & parts )
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
        EString r;
        r.append( boundaryChars[i] );
        return r;
    }

    // in the all too likely case that some unfriendly soul tries
    // to attack us, we'd better have some alternative plan,
    // e.g. a string containing eight random base64 characters.
    EString r = Entropy::asString( 6 ).e64();
    while ( parts.contains( r ) )
        // if at first you don't succeed, try again with a bigger hammer!
        r = Entropy::asString( 36 ).e64();
    return r;
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
