// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "multipart.h"

#include "message.h"
#include "bodypart.h"
#include "estringlist.h"
#include "mimefields.h"
#include "ustring.h"
#include "codec.h"
#include "log.h"

#include <stdio.h>


static const char * crlf = "\015\012";


/*! \class Multipart multipart.h
    This class represents the common characteristics of Messages and
    Bodyparts, namely that they have a header() and children().
*/

/*! Constructs an empty Multipart object.
*/

Multipart::Multipart()
    : h( 0 ), p( 0 ), parts( new List< Bodypart > )
{
}


/*! Exists only to avoid compiler warnings. */

Multipart::~Multipart()
{
}


/*! Returns a pointer to the Header for this Multipart object, or 0 if
    none has been set with setHeader().

    Both Message and Bodypart always create a Header at construction.
*/

Header * Multipart::header() const
{
    return h;
}


/*! Sets the header of this Multipart object to \a hdr. */

void Multipart::setHeader( Header * hdr )
{
    h = hdr;
}


/*! Returns a pointer to the parent of this Multipart, or 0 if this is a
    top-level MIME object.
*/

Multipart * Multipart::parent() const
{
    return p;
}


/*! Sets the parent of this Multipart object to \a pt. */

void Multipart::setParent( Multipart * pt )
{
    p = pt;
}


/*! Returns a pointer to a list of Bodyparts belonging to this object.
    May return an empty list, but never returns a null pointer.
*/

List< Bodypart > * Multipart::children() const
{
    return parts;
}


/*! Appends the text of this multipart MIME entity to the string \a r.
*/

void Multipart::appendMultipart( EString &r, bool avoidUtf8, bool isPgpSigned ) const
{
    ::log( "Multipart::appendMultipart - starting with text:" + r, Log::Debug );
    ContentType * ct = header()->contentType();
    EString delim = ct->parameter( "boundary" );
    ::log( "Multipart::appendMultipart - ct:" + ct->type() + "/" + ct->subtype(), Log::Debug );
    bool isSigned = false;
    if ( ct->subtype() == "signed" || isPgpSigned ) {
        isSigned = true;
    }
    List<Bodypart>::Iterator it( children() );
    r.append( "--" + delim );
    while ( it ) {
        r.append( crlf );

        Bodypart * bp = it;
        ++it;
        
        if ( isSigned ) {
            if ( isPgpSigned )
                ::log( "**** Multipart::appendMultipart - deep in signed part", Log::Debug );
            else
                ::log( "**** Multipart::appendMultipart - signed, skipping to next bodypart", Log::Debug );
            ++it;
            // we do not want our simple header, just append our raw text
            appendAnyPart( r, bp, ct, avoidUtf8, true );
            ::log( "**** Multipart::appendMultipart - signed, raw(?) text was appended", Log::Debug );
            isSigned = false;
        } else {
            r.append( bp->header()->asText( avoidUtf8 ) );
            r.append( crlf );
            ::log( "Multipart::appendMultipart - header was appended:" +  bp->header()->asText( avoidUtf8 ), Log::Debug );
            appendAnyPart( r, bp, ct, avoidUtf8, false );
            ::log( "Multipart::appendMultipart - NOT signed, appendAnyPart finished", Log::Debug );
        }
        r.append( crlf );
        r.append( "--" );
        r.append( delim );
    }
    r.append( "--" );
    r.append( crlf );
    ::log( "Multipart::appendMultipart - returning text:" + r, Log::Debug );
}


/*! This function appends the text of the MIME bodypart \a bp with
    Content-type \a ct to the string \a r.

    The details of this function are certain to change.
*/

void Multipart::appendAnyPart( EString &r, const Bodypart * bp,
                               ContentType * ct, bool avoidUtf8, bool isPgpSigned ) const
{
    ContentType * childct = bp->header()->contentType();
    EString::Encoding e = EString::Binary;
    ContentTransferEncoding * cte
        = bp->header()->contentTransferEncoding();
    ::log( "Multipart::appendAnypart", Log::Debug );
    if ( cte )
        e = cte->encoding();

    if ( ( childct && childct->type() == "message" ) ||
         ( ct && ct->type() == "multipart" && ct->subtype() == "digest" &&
           !childct ) )
    {
        if ( childct && childct->subtype() != "rfc822" ) {
            ::log( "Multipart::appendAnypart - will appendTextPart 1", Log::Debug );
            appendTextPart( r, bp, childct, isPgpSigned );
        }
        else {
            ::log( "Multipart::appendAnypart - will append rfc822", Log::Debug );
            r.append( bp->message()->rfc822( avoidUtf8 ) );
        }
    }
    else if ( !childct || childct->type().lower() == "text" ) {
        ::log( "Multipart::appendAnypart - will appendTextPart 2", Log::Debug );
        appendTextPart( r, bp, childct, isPgpSigned );
    }
    else if ( childct->type() == "multipart" ) {
        ::log( "Multipart::appendAnypart - will appendMultipart", Log::Debug );
        bp->appendMultipart( r, avoidUtf8, isPgpSigned );
    }
    else {
        ::log( "Multipart::appendAnypart - will append data", Log::Debug );
        r.append( bp->data().encoded( e, 72 ) );
    }
}


/*! This function appends the text of the MIME bodypart \a bp with
    Content-type \a ct to the string \a r.

    The details of this function are certain to change.
*/

void Multipart::appendTextPart( EString & r, const Bodypart * bp,
                                ContentType * ct, bool isPgpSigned ) const
{
    Codec * c = 0;

    ::log( "Multipart::appendTextPart - text, we will append to:" + r, Log::Debug );
    EString::Encoding e = EString::Binary;
    ContentTransferEncoding * cte
        = bp->header()->contentTransferEncoding();
    if ( cte )
        e = cte->encoding();

    if ( ct && !ct->parameter( "charset" ).isEmpty() )
        c = Codec::byName( ct->parameter( "charset" ) );
    if ( !c )
        c = Codec::byString( bp->text() );

    EString body = c->fromUnicode( bp->text() );

    ::log( "Multipart::appendTextPart - text:" + body, Log::Debug );
    r.append( body.encoded( e, 72 ) );
}


/* Debugging aids. */


static void spaces( int );
static void headerSummary( Header *, int );
static void dumpBodypart( Message *, Bodypart *, int );
static void dumpMultipart( Multipart *, int );


static void dumpMessage( Message * m, int n = 0 )
{
    dumpMultipart( m, n );

    List< Bodypart >::Iterator it( m->children() );
    while ( it ) {
        dumpBodypart( m, it, n+2 );
        ++it;
    }
}


static void dumpBodypart( Message * m, Bodypart * bp, int n )
{
    dumpMultipart( bp, n );

    if ( bp->message() ) {
        dumpMessage( bp->message(), n+4 );
    }
    else {
        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            dumpBodypart( m, it, n+2 );
            ++it;
        }
    }
}


static void dumpMultipart( Multipart * m, int n )
{
    spaces( n );
    fprintf( stderr, "%p = {h=%p, p=%p, c=%p [", m, m->header(),
             m->parent(), m->children() );
    List< Bodypart >::Iterator it( m->children() );
    while ( it ) {
        Bodypart * bp = it;
        fprintf( stderr, "%p", bp );
        ++it;
        if ( it )
            fprintf( stderr, "," );
    }
    fprintf( stderr, "]}\n" );
    headerSummary( m->header(), n );
}


static void headerSummary( Header * h, int n )
{
    EStringList l;

    ContentType * ct = h->contentType();
    if ( ct )
        l.append( ct->type() + "/" + ct->subtype() );

    ContentTransferEncoding * cte = h->contentTransferEncoding();
    if ( cte ) {
        EString s;
        switch ( cte->encoding() ) {
        case EString::QP:
            s = "quoted-printable";
            break;
        case EString::Base64:
            s = "base64";
            break;
        case EString::Uuencode:
            s = "x-uuencode";
            break;
        case EString::Binary:
            s = "7bit";
            break;
        }
        l.append( s );
    }

    HeaderField * cd = h->field( HeaderField::ContentDescription );
    if ( cd )
        l.append( cd->rfc822( false ) );

    if ( !l.isEmpty() ) {
        spaces( n );
        fprintf( stderr, "%s\n", l.join( ";" ).cstr() );
    }
}


static void spaces( int n )
{
    while ( n-- > 0 )
        fprintf( stderr, " " );
}


/*! This virtual function returns true if the object is a Message,
    false if not.
*/

bool Multipart::isMessage() const
{
    return false;
}


/*! This virtual function returns true if the object is a Bodypart,
    false if not.
*/

bool Multipart::isBodypart() const
{
    return false;
}


/*! Simplifies unnecessarily complex MIME structure, corrects mime
    types, etc. This is only called when a message is submitted; RFC
    6409 more or less suggests that we might want do it.

    Doing this when we receive other people's mail or are copying old
    mail into the archive would be impermissible.
*/

void Multipart::simplifyMimeStructure()
{
    // If we're looking at a multipart with just a single part, change
    // the mime type to avoid the middle multipart. This affects
    // Kaiten Mail.
    ::log( "Multipart::simplifyMimeStructure", Log::Debug );
    if ( header()->contentType() &&
         header()->contentType()->type() == "multipart" &&
         parts->count() == 1 &&
         ( !parts->firstElement()->header()->contentType() ||
           parts->firstElement()->header()->contentType()->type() != "multipart" ) ) {
        Header * me = header();
        Header * sub = parts->firstElement()->header();

        me->removeField( HeaderField::ContentType );
        ContentType * ct = sub->contentType();
        if ( ct )
            me->add( ct );

        me->removeField( HeaderField::ContentTransferEncoding );
        ContentTransferEncoding * cte = sub->contentTransferEncoding();
        if ( cte )
            me->add( cte );

        me->removeField( HeaderField::ContentDisposition );
        ContentDisposition * cd = sub->contentDisposition();
        if ( cd )
            me->add( cd );

        if ( !ct && !cte && !cd )
            me->removeField( HeaderField::MimeVersion );
    }
}


/*! Returns true if any part of this Multipart needs Unicode
    capability to be porperly transmitted, and false if MIME-enhanced
    ASCII will do.
*/

bool Multipart::needsUnicode() const
{
    ::log( "Multipart::needsUnicode", Log::Debug );
    if ( h->needsUnicode() )
        return true;

    List<Bodypart>::Iterator it( children() );
    while ( it ) {
        if ( it->needsUnicode() )
            return true;
        ++it;
    }

    ::log( "Multipart::needsUnicode - false", Log::Debug );
    return false;
}
