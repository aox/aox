// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "header.h"

#include "field.h"
#include "message.h"
#include "mailbox.h"
#include "datefield.h"
#include "mimefields.h"
#include "configuration.h"
#include "addressfield.h"
#include "ustringlist.h"
#include "multipart.h"
#include "bodypart.h"
#include "address.h"
#include "unknown.h"
#include "ustring.h"
#include "parser.h"
#include "codec.h"
#include "date.h"
#include "utf.h"



static const char *crlf = "\015\012";


class HeaderData
    : public Garbage
{
public:
    HeaderData()
        : mode( Header::Rfc2822 ),
          defaultType( Header::TextPlain ),
          verified( false )
    {}

    Header::Mode mode;
    Header::DefaultType defaultType;

    bool verified;
    EString error;

    List< HeaderField > fields;
};


/*! \class Header header.h
    The Header class models an RFC 2822 or MIME header.

    Essentially, it's a container for HeaderField objects which can
    check whether its contents make sense and are legal (see RFC 2822
    page 19), and will give them to callers on demand.

    Fields are available by calling field() with the right type. This
    works well for some fields, but fields which can occur several
    times have a problem. Will have to solve that eventually.

    Some fields are also available as values, e.g. date().
*/

/*! Constructs an empty Header in \a m mode. If \a m is Rfc2822, the
    header's validity will follow RFC 2822 rules, while if \a m is
    Mime, RFC 2045-2049 rules are used.
*/

Header::Header( Mode m )
    : d( new HeaderData )
{
    d->mode = m;
}


/*! Returns the header's mode, either Mime or Rfc2822, which is set
    using the constructor and decides whether a particular header is
    valid. For example, in Rfc2822 mode a Date field is mandatory,
    while in Mime mode it's not allowed.
*/

Header::Mode Header::mode() const
{
    return d->mode;
}


/*! Returns true if this Header fills all the conditions laid out in
    RFC 2821 for validity, and false if not.
*/

bool Header::valid() const
{
    verify();
    return d->error.isEmpty();
}


/*! Returns a one-line error message describing the first error
    detected in this Header, or an empty string if there is no error.
*/

EString Header::error() const
{
    verify();
    return d->error;
}


/*! Appends the HeaderField \a hf to this Header.

    If the HeaderField::position() is -1, add() sets it one higher
    than that of the last HeaderField. This tends to make it unique
    and larger than all others, but it may not be unique.
    Unfortunately guaranteeing uniqueness is O(n).
*/

void Header::add( HeaderField * hf )
{
    HeaderField::Type t = hf->type();

    if ( t == HeaderField::To || t == HeaderField::Cc ||
         t == HeaderField::Bcc || t == HeaderField::ReplyTo ||
         t == HeaderField::From )
    {
        AddressField *first = addressField( t );
        AddressField *next = (AddressField *)hf;
        if ( first ) {
            List< Address > *old = first->addresses();
            List< Address >::Iterator it( next->addresses() );
            while ( it ) {
                old->append( it );
                ++it;
            }
            return;
        }
    }
    if ( hf->position() == (uint)-1 ) {
        if ( d->fields.isEmpty() )
            hf->setPosition( 1 );
        else
            hf->setPosition( d->fields.last()->position() + 1 );
        d->fields.append( hf );
    }
    else {
        List<HeaderField>::Iterator i( d->fields );
        while ( i && i->position() < hf->position() )
            ++i;
        d->fields.insert( i, hf );
    }
    d->verified = false;
}


/*! Creates a header field with the supplied \a name and \a value, and
    appends it to this Header, adjusting validity as necessary.
*/

void Header::add( const EString &name, const EString &value )
{
    add( HeaderField::create( name, value ) );
}


/*! Removes all fields with type \a t from the header.
*/

void Header::removeField( HeaderField::Type t )
{
    List<HeaderField>::Iterator it( d->fields );
    while ( it ) {
        if ( it->type() == t )
            d->fields.take( it );
        else
            ++it;
    }
    d->verified = false;
}


/*! Removes all fields named \a n from this header.

    Works only if \a n is header-cased (ie. this function is case-sensitive).
*/

void Header::removeField( const char * n )
{
    List<HeaderField>::Iterator it( d->fields );
    while ( it ) {
        if ( it->name() == n )
            d->fields.take( it );
        else
            ++it;
    }
    d->verified = false;
}


/*! Returns a pointer to a list containing all the HeaderField objects
    in this Header. Neither the list nor the HeaderField objects it in
    may be modified or freed by the caller - Header keeps other
    pointers to these objects.

    The return value may point to an empty list, but can not be a null
    pointer.
*/

List< HeaderField > * Header::fields() const
{
    return &d->fields;
}


/*! Returns a pointer to the header field with type \a t and index \a
    n, or a null pointer if there is no such field in this header.

    if \a n is 0, as it is by default, the first field with type \a t
    is returned. 1 refers to the second.
*/

HeaderField * Header::field( HeaderField::Type t, uint n ) const
{
    List<HeaderField>::Iterator it( d->fields );
    while ( n > 0 && it ) {
        while ( it && it->type() != t )
            ++it;
        n--;
        if ( it )
            ++it;
    }
    while ( it && it->type() != t )
        ++it;
    return it;
}


/*! Returns a pointer to the header field with type Other, name \a h
    and index n, or a null pointer if there is no such field in this
    header.

    If \a n is 0, as it is by default, the first field with the
    desired name is returned, 1 refers to the second, and so on.

*/

HeaderField * Header::field( const char * h, uint n ) const
{
    List<HeaderField>::Iterator it( d->fields );
    while ( n > 0 && it ) {
        while ( it && ( it->type() != HeaderField::Other || it->name() != h ) )
            ++it;
        n--;
        if ( it )
            ++it;
    }
    while ( it && ( it->type() != HeaderField::Other || it->name() != h ) )
        ++it;
    return it;
}


/*! Returns a pointer to the address field of type \a t at index \a n in
    this header, or a null pointer if no such field exists.
*/

AddressField *Header::addressField( HeaderField::Type t, uint n ) const
{
    switch( t ) {
    case HeaderField::From:
    case HeaderField::ResentFrom:
    case HeaderField::Sender:
    case HeaderField::ResentSender:
    case HeaderField::ReturnPath:
    case HeaderField::ReplyTo:
    case HeaderField::To:
    case HeaderField::Cc:
    case HeaderField::Bcc:
    case HeaderField::ResentTo:
    case HeaderField::ResentCc:
    case HeaderField::ResentBcc:
    case HeaderField::MessageId:
    case HeaderField::ContentId:
    case HeaderField::ResentMessageId:
    case HeaderField::References:
        return (AddressField *)field( t, n );
        break;
    default:
        break;
    }
    return 0;
}


/*! Returns the header's data \a t, which is the normal date by
    default, but can also be orig-date or resent-date. If there is no
    such field or \a t is meaningless, date() returns a null pointer.
*/

Date *Header::date( HeaderField::Type t ) const
{
    DateField *hf = (DateField *)field( t );
    if ( !hf )
        return 0;
    return hf->date();
}


/*! Returns the header's subject. For the moment, this is a simple
    string. It'll have to morph soon, to handle RFC 2047 at least.
*/

EString Header::subject() const
{
    HeaderField * s = field( HeaderField::Subject );
    if ( s )
        return s->rfc822( false ).simplified();
    return "";
}


/*! Returns the header's in-reply-to value. This comes straight from
    the RFC 2822 representation.
*/

EString Header::inReplyTo() const
{
    HeaderField * s = field( HeaderField::InReplyTo );
    if ( s )
        return s->rfc822( false ).simplified();
    return "";
}


/*! Returns the header's message-id \a t, which is the normal
    message-id by default but can also be the first resent-message-id
    or the content-id.  The returned string is in the cleanest
    possible form. If there is no such message-id, messageId() returns
    an empty string.
*/

EString Header::messageId( HeaderField::Type t ) const
{
    AddressField *af = addressField( t );
    if ( !af )
        return "";
    return af->rfc822( true );
}


/*! Returns a pointer to the addresses in the \a t header field, which
    must be an address field such as From or Bcc. If not, or if the
    field is empty, addresses() returns a null pointer.
*/

List< Address > *Header::addresses( HeaderField::Type t ) const
{
    List< Address > * a = 0;
    AddressField * af = addressField( t );
    if ( af )
        a = af->addresses();
    if ( a && a->isEmpty() )
        a = 0;
    return a;
}


/*! Returns a pointer to the Content-Type header field, or a null
    pointer if there isn't one.
*/

ContentType *Header::contentType() const
{
    return (ContentType *)
        field( HeaderField::ContentType );
}


/*! Returns a pointer to the Content-Transfer-Encoding header field,
    or a null pointer if there isn't one.
*/

ContentTransferEncoding *Header::contentTransferEncoding() const
{
    return (ContentTransferEncoding *)
        field( HeaderField::ContentTransferEncoding );
}


/*! Returns a pointer to the Content-Disposition header field, or a null
    pointer if there isn't one.
*/

ContentDisposition *Header::contentDisposition() const
{
    return (ContentDisposition *)
        field( HeaderField::ContentDisposition );
}


/*! Returns the value of the Content-Description field, or an empty
    string if there isn't one. RFC 2047 encoding is not considered -
    should it be?
*/

EString Header::contentDescription() const
{
    HeaderField *hf = field( HeaderField::ContentDescription );
    if ( !hf )
        return "";
    return hf->rfc822( false ).simplified();
}


/*! Returns the value of the Content-Location field, or an empty string
    if there isn't one. The URI is not validated in any way.
*/

EString Header::contentLocation() const
{
    HeaderField *hf = field( HeaderField::ContentLocation );
    if ( !hf )
        return "";
    return hf->rfc822( false );
}


/*! Returns a pointer to the Content-Language header field, or a null
    pointer if there isn't one.
*/

ContentLanguage *Header::contentLanguage() const
{
    return (ContentLanguage *)
        field( HeaderField::ContentLanguage );
}




static struct {
    HeaderField::Type t;
    uint min;
    uint max;
    Header::Mode m;
} conditions[] = {
    { HeaderField::Sender, 0, 1, Header::Rfc2822 },
    { HeaderField::ReplyTo, 0, 1, Header::Rfc2822 },
    { HeaderField::To, 0, 1, Header::Rfc2822 },
    { HeaderField::Cc, 0, 1, Header::Rfc2822 },
    { HeaderField::Bcc, 0, 1, Header::Rfc2822 },
    { HeaderField::MessageId, 0, 1, Header::Rfc2822 },
    { HeaderField::References, 0, 1, Header::Rfc2822 },
    { HeaderField::Subject, 0, 1, Header::Rfc2822 },
    { HeaderField::From, 1, 1, Header::Rfc2822 },
    { HeaderField::Date, 1, 1, Header::Rfc2822 },
    { HeaderField::MimeVersion, 0, 1, Header::Rfc2822 },
    { HeaderField::MimeVersion, 0, 1, Header::Mime },
    { HeaderField::ContentType, 0, 1, Header::Rfc2822 },
    { HeaderField::ContentType, 0, 1, Header::Mime },
    { HeaderField::ContentTransferEncoding, 0, 1, Header::Rfc2822 },
    { HeaderField::ContentTransferEncoding, 0, 1, Header::Mime },
    { HeaderField::ReturnPath, 0, 1, Header::Rfc2822 },
    { HeaderField::Other, 0, 0, Header::Rfc2822 } // magic end marker
};


/*! This private function verifies that the entire header is
    consistent and legal, and that each contained HeaderField is
    legal.
*/

void Header::verify() const
{
    if ( d->verified )
        return;
    d->verified = true;
    d->error.truncate( 0 );

    List<HeaderField>::Iterator it( d->fields );
    while ( it ) {
        if ( !it->valid() ) {
            d->error = it->name() + ": " + it->error();
            return;
        }
        ++it;
    }

    uint occurrences[(int)HeaderField::Other];
    int i = 0;
    while ( i < HeaderField::Other )
        occurrences[i++] = 0;
    it = d->fields.first();
    while ( it ) {
        HeaderField::Type t = it->type();
        ++it;
        if ( t < HeaderField::Other )
            occurrences[(int)t]++;
    }

    i = 0;
    while ( d->error.isEmpty() && conditions[i].t != HeaderField::Other ) {
        if ( conditions[i].m == d->mode &&
             ( occurrences[conditions[i].t] < conditions[i].min ||
               occurrences[conditions[i].t] > conditions[i].max ) ) {
            if ( conditions[i].max < occurrences[conditions[i].t] )
                d->error = fn( occurrences[conditions[i].t] ) + " " +
                           HeaderField::fieldName( conditions[i].t ) +
                           " fields seen. At most " +
                           fn( conditions[i].max ) + " may be present.";
            else
                d->error = fn( occurrences[conditions[i].t] ) + " " +
                           HeaderField::fieldName( conditions[i].t ) +
                           " fields seen. At least " +
                           fn( conditions[i].min ) + " must be present.";
        }
        i++;
    }

    // strictly speaking, if From contains more than one address,
    // sender should contain one. we don't enforce that, because it
    // causes too much spam to be rejected that would otherwise go
    // through. we'll filter spam with something that's a little less
    // accidental, and which does not clutter up the logs with so many
    // misleading error messages.

    // we graciously ignore all the Resent-This-Or-That restrictions.
}


static bool sameAddresses( AddressField *a, AddressField *b )
{
    if ( !a || !b )
        return false;

    List< Address > *l = a->addresses();
    List< Address > *m = b->addresses();

    if ( !l || !m )
        return false;

    if ( l->count() != m->count() )
        return false;

    List<Address>::Iterator it( m );
    while ( it ) {
        UString lp = it->localpart();
        UString dom = it->domain().titlecased();
        List<Address>::Iterator i( l );
        while ( i && !( i->localpart() == lp &&
                        i->domain().titlecased() == dom ) )
            ++i;
        if ( !i )
            return false;
        ++it;
    }
    return true;
}


/*! Removes any redundant header fields from this header, and
    simplifies the value of some.

    For example, if 'sender' or 'reply-to' points to the same address
    as 'from', that field can be removed, and if 'from' contains the
    same address twice, one can be removed.
*/

void Header::simplify()
{
    if ( !valid() )
        return;

    uint i = 0;
    while ( i <= HeaderField::LastAddressField ) {
        AddressField * af = addressField( (HeaderField::Type)i );
        if ( af )
            Address::uniquify( af->addresses() );
        i++;
    }

    HeaderField *cde = field( HeaderField::ContentDescription );
    if ( cde && cde->rfc822( false ).isEmpty() ) {
        removeField( HeaderField::ContentDescription );
        cde = 0;
    }

    ContentTransferEncoding *cte = contentTransferEncoding();
    if ( cte && cte->encoding() == EString::Binary )
        removeField( HeaderField::ContentTransferEncoding );

    ContentDisposition *cdi = contentDisposition();
    if ( cdi ) {
        ContentType *ct = contentType();

        if ( d->mode == Rfc2822 && ( !ct || ct->type() == "text" ) &&
             cdi->disposition() == ContentDisposition::Inline &&
             cdi->parameters()->isEmpty() )
        {
            removeField( HeaderField::ContentDisposition );
            cdi = 0;
        }
    }

    ContentType * ct = contentType();
    if ( ct ) {
        if ( ct->parameters()->isEmpty() && cte == 0 && cdi == 0 && cde == 0 &&
             d->defaultType == TextPlain &&
             ct->type() == "text" && ct->subtype() == "plain" ) {
            removeField( HeaderField::ContentType );
            ct = 0;
        }
    }
    else if ( d->defaultType == MessageRfc822 ) {
        add( "Content-Type", "message/rfc822" );
        ct = contentType();
    }

    if ( mode() == Mime ) {
        removeField( HeaderField::MimeVersion );
    }
    else if ( ct == 0 && cte == 0 && cde == 0 && cdi == 0 &&
         !field( HeaderField::ContentLocation ) &&
         !field( "Content-Base" ) ) {
        removeField( HeaderField::MimeVersion );
    }
    else {
        if ( mode() == Rfc2822 && !field( HeaderField::MimeVersion ) )
            add( "Mime-Version", "1.0" );
    }
    if ( ct &&
         ( ct->type() == "multipart" || ct->type() == "message" ||
           ct->type() == "image" || ct->type() == "audio" ||
           ct->type() == "video" ) )
        ct->removeParameter( "charset" );

    if ( field( "Errors-To" ) ) {
        EString et = field( "Errors-To" )->value().ascii();
        List<Address> * rp = addresses( HeaderField::ReturnPath );
        if ( rp && rp->count() == 1 &&
             rp->firstElement()->lpdomain().lower() == et.lower() )
            removeField( "Errors-To" );
    }

    HeaderField *m = field( HeaderField::MessageId );
    if ( m && m->rfc822( false ).isEmpty() )
        removeField( HeaderField::MessageId );

    if ( sameAddresses( addressField( HeaderField::From ),
                        addressField( HeaderField::ReplyTo ) ) )
        removeField( HeaderField::ReplyTo );

    if ( sameAddresses( addressField( HeaderField::From ),
                        addressField( HeaderField::Sender ) ) )
        removeField( HeaderField::Sender );

    if ( !addresses( HeaderField::Sender ) )
        removeField( HeaderField::Sender );
    if ( !addresses( HeaderField::ReturnPath ) )
        removeField( HeaderField::ReturnPath );
    if ( !addresses( HeaderField::To ) )
        removeField( HeaderField::To );
    if ( !addresses( HeaderField::Cc ) )
        removeField( HeaderField::Cc );
    if ( !addresses( HeaderField::Bcc ) )
        removeField( HeaderField::Bcc );
    if ( !addresses( HeaderField::ReplyTo ) )
        removeField( HeaderField::ReplyTo );
}



/*! Repairs problems that can be repaired without knowing the associated
    bodypart.
*/

void Header::repair()
{
    if ( valid() )
        return;

    // We remove duplicates of any field that may occur only once.
    // (Duplication has been observed for Date/Subject/M-V/C-T-E/C-T/M-I.)

    uint occurrences[ (int)HeaderField::Other ];
    int i = 0;
    while ( i < HeaderField::Other )
        occurrences[i++] = 0;

    List< HeaderField >::Iterator it( d->fields );
    while ( it ) {
        HeaderField::Type t = it->type();
        if ( t < HeaderField::Other )
            occurrences[(int)t]++;
        ++it;
    }

    i = 0;
    while ( conditions[i].t != HeaderField::Other ) {
        if ( conditions[i].m == d->mode &&
             occurrences[conditions[i].t] > conditions[i].max )
        {
            uint n = 0;
            HeaderField * h = field( conditions[i].t, 0 );
            List< HeaderField >::Iterator it( d->fields );
            while ( it ) {
                if ( it->type() == conditions[i].t ) {
                    n++;
                    if ( n > 1 && h->rfc822( false ) == it->rfc822( false ) )
                        d->fields.take( it );
                    else
                        ++it;
                }
                else {
                    ++it;
                }
            }
        }
        i++;
    }

    // If there are several content-type fields, and they agree except
    // that one has options and the others not, remove the option-less
    // ones.

    if ( occurrences[(int)HeaderField::ContentType] > 1 ) {
        ContentType * ct = contentType();
        ContentType * other = ct;
        ContentType * good = 0;
        uint n = 0;
        bool bad = false;
        while ( other && !bad ) {
            if ( other->type() != ct->type() ||
                 other->subtype() != ct->subtype() ) {
                bad = true;
            }
            else if ( !other->parameters()->isEmpty() ) {
                if ( good )
                    bad = true;
                good = other;
            }
            other = (ContentType *)field( HeaderField::ContentType, ++n );
        }
        if ( good && !bad ) {
            List<HeaderField>::Iterator it( d->fields );
            while ( it ) {
                if ( it->type() == HeaderField::ContentType && it != good )
                    d->fields.take( it );
                else
                    ++it;
            }
        }
    }

    // We retain only the first valid Date field, Return-Path,
    // Message-Id, References and Content-Type fields. If there is one
    // or more valid such field, we delete all invalid fields,
    // otherwise we leave the fields as they are.

    // For most of these, we also delete subsequent valid fields. For
    // Content-Type we only delete invalid fields, since there isn't
    // any strong reason to believe that the one we would keep enables
    // correct interpretation of the body.

    // Several senders appear to send duplicate dates. qmail is
    // mentioned in the references chains of most examples we have.

    // We don't know who adds duplicate message-id, return-path and
    // content-type fields.

    // The only case we've seen of duplicate references involved
    // Thunderbird 1.5.0.4 and Scalix. Uncertain whose
    // bug. Thunderbird 1.5.0.5 looks correct.

    i = 0;
    while ( i < HeaderField::Other ) {
        if ( occurrences[i] > 1 &&
             ( i == HeaderField::Date ||
               i == HeaderField::ReturnPath ||
               i == HeaderField::MessageId ||
               i == HeaderField::ContentType ||
               i == HeaderField::References ) ) {
            List< HeaderField >::Iterator it( d->fields );
            HeaderField * firstValid = 0;
            while ( it && !firstValid ) {
                if ( it->type() == i && it->valid() )
                    firstValid = it;
                ++it;
            }
            if ( firstValid ) {
                bool alsoValid = true;
                if ( i == HeaderField::ContentType )
                    alsoValid = false;
                List< HeaderField >::Iterator it( d->fields );
                while ( it ) {
                    if ( it->type() == i && it != firstValid &&
                         ( alsoValid || !it->valid() ) )
                        d->fields.take( it );
                    else
                        ++it;
                }
            }
        }
        ++i;
    }

    // Mime-Version is occasionally seen more than once, usually on
    // spam or mainsleaze.
    if ( field( HeaderField::MimeVersion, 1 ) ) {
        HeaderField * fmv = field( HeaderField::MimeVersion );
        removeField( HeaderField::MimeVersion );
        add( fmv );
        fmv->parse( "1.0 (Note: original message contained " +
                    fn( occurrences[(int)HeaderField::MimeVersion] ) +
                    " mime-version fields)" );
    }

    // Content-Transfer-Encoding: should not occur on multiparts, and
    // when it does it usually has a syntax error. We don't care about
    // that error.
    if ( occurrences[(int)HeaderField::ContentTransferEncoding] ) {
        ContentType * ct = contentType();
        if ( ct && ( ct->type() == "multipart" || ct->type() == "message" ) )
            removeField( HeaderField::ContentTransferEncoding );
    }

    // Sender sometimes is a straight copy of From, even if From
    // contains more than one address. If it's a copy, or even an
    // illegal subset, we drop it.

    List<Address> * senders = addresses( HeaderField::Sender );

    if ( occurrences[(int)HeaderField::Sender] > 0 &&
         ( !senders || senders->count() > 1 ) )
    {
        EStringList from;
        List<Address>::Iterator fi( addresses( HeaderField::From ) );
        while ( fi ) {
            from.append( fi->lpdomain().lower() );
            ++fi;
        }

        EStringList sender;
        List<Address>::Iterator si( addresses( HeaderField::Sender ) );
        while ( si ) {
            sender.append( si->lpdomain().lower() );
            ++si;
        }

        EStringList::Iterator i( sender );
        bool difference = false;
        while ( i && difference ) {
            if ( !from.contains( *i ) )
                difference = true;
            ++i;
        }
        if ( !difference )
            removeField( HeaderField::Sender );
    }
}


/*! Repairs a few harmless and common problems, such as inserting two
    Date fields with the same value. Assumes that \a p is its companion
    body (whose text is in \a body), and may look at it to decide
    what/how to repair.
*/

void Header::repair( Multipart * p, const EString & body )
{
    if ( valid() )
        return;

    // Duplicated from above.
    uint occurrences[ (int)HeaderField::Other ];
    int i = 0;
    while ( i < HeaderField::Other )
        occurrences[i++] = 0;

    List< HeaderField >::Iterator it( d->fields );
    while ( it ) {
        HeaderField::Type t = it->type();
        if ( t < HeaderField::Other )
            occurrences[(int)t]++;
        ++it;
    }

    // If there is no valid Date field and this is an RFC822 header,
    // we look for a sensible date.

    if ( mode() == Rfc2822 &&
         ( occurrences[(int)HeaderField::Date] == 0 ||
           !field( HeaderField::Date )->valid() ||
           !date()->valid() ) ) {
        List< HeaderField >::Iterator it( d->fields );
        Date date;
        while ( it ) {
            // First, we take the date from the oldest plausible
            // Received field.
            if ( it->type() == HeaderField::Received ) {
                EString v = it->rfc822( false );
                int i = 0;
                while ( v.find( ';', i+1 ) > 0 )
                    i = v.find( ';', i+1 );
                if ( i >= 0 ) {
                    Date tmp;
                    tmp.setRfc822( v.mid( i+1 ) );
                    if ( tmp.valid() ) {
                        if ( !date.valid() ) {
                            // first plausible we've seen
                            date = tmp;
                        }
                        else {
                            uint ud = date.unixTime();
                            uint td = tmp.unixTime();
                            // if it took more than an hour to
                            // deliver, or less than no time, we don't
                            // trust this receied field at all.
                            if ( td < ud && td + 3600 > td )
                                date = tmp;
                        }
                    }
                }
            }
            ++it;
        }

        if ( !date.valid() && p ) {
            Multipart * parent = p->parent();
            while ( parent && parent->header() &&
                    !( parent->header()->date() &&
                       parent->header()->date()->valid() ) )
                parent = parent->parent();
            if ( parent )
                date = *parent->header()->date();
        }

        if ( !date.valid() &&
             occurrences[(int)HeaderField::Date] == 0 ) {
            // Try to see if the top-level message has an internaldate,
            // just in case it might be valid.
            Multipart * parent = p;
            while ( parent && parent->parent() )
                parent = parent->parent();
            if ( parent->isMessage() ) {
                Message * adam = (Message*)parent;
                uint id = adam->internalDate();
                if ( id )
                    date.setUnixTime( id );
            }
        }

        if ( !date.valid() &&
             occurrences[(int)HeaderField::Date] == 0 ) {
            // As last resort, use the current date, time and
            // timezone.  Only do this if there isn't a date field. If
            // there is one, we'll reject the message (at least for
            // now) since this happens only for submission in
            // practice.
            date.setCurrentTime();
        }

        if ( date.valid() ) {
            uint pos = UINT_MAX;
            HeaderField * df = field( HeaderField::Date );
            if ( df )
                pos = df->position();
            removeField( HeaderField::Date );
            df = HeaderField::create( "Date", date.rfc822() );
            df->setPosition( pos );
            add( df );
        }
    }

    // If there is no From field, try to use either Return-Path or
    // Sender from this Header, or From, Return-Path or Sender from
    // the Header of the closest encompassing Multipart that has such
    // a field.

    if ( occurrences[(int)HeaderField::From] == 0 && mode() == Rfc2822 ) {
        Multipart * parent = p;
        Header * h = this;
        List<Address> * a = 0;
        while ( ( h || parent ) && !a ) {
            if ( h )
                a = h->addresses( HeaderField::From );
            if ( h && ( !a || a->first()->type() != Address::Normal ) )
                a = h->addresses( HeaderField::ReturnPath );
            if ( h && ( !a || a->first()->type() != Address::Normal ) )
                a = h->addresses( HeaderField::Sender );
            if ( h && ( !a || a->first()->type() != Address::Normal ) )
                a = 0;
            if ( parent )
                parent = parent->parent();
            if ( parent )
                h = parent->header();
            else
                h = 0;
        }
        if ( !a ) {
            // if there is an X-From-Line, it could be old damaged
            // gnus mail, fcc'd before a From line was added. Let's
            // try.
            List<HeaderField>::Iterator f( fields() );
            while ( f && f->name() != "X-From-Line" )
                ++f;
            if ( f ) {
                AddressParser ap( f->rfc822( false ).section( " ", 1 ) );
                ap.assertSingleAddress();
                if ( ap.error().isEmpty() )
                    a = ap.addresses();
            }
        }
        if ( a )
            add( "From", a->first()->toString( false ) );
    }

    // Some spammers like to get return receipts while hiding their
    // Fromness, so if From is bad and either Return-Receipt-To or
    // Disposition-Notification-To is good, use those.
    if ( mode() == Rfc2822 &&
         ( !field( HeaderField::From ) ||
           ( !field( HeaderField::From )->valid() &&
             !addresses( HeaderField::From ) ) ) ) {
        List<Address> * a = 0;
        List<HeaderField>::Iterator f( fields() );
        while ( f && !a ) {
            if ( f->name() == "Return-Receipt-To" ||
                 f->name() == "Disposition-Notification-To" ) {
                AddressParser ap( f->rfc822( false ).section( " ", 1 ) );
                ap.assertSingleAddress();
                if ( ap.error().isEmpty() )
                    a = ap.addresses();
            }
            ++f;
        }
        if ( a ) {
            removeField( HeaderField::From );
            add( "From", a->first()->toString( false ) );
        }
    }

    // If there is an unacceptable Received field somewhere, remove it
    // and all the older Received fields.

    if ( occurrences[(int)HeaderField::Received] > 0 ) {
        bool bad = false;
        List<HeaderField>::Iterator it( d->fields );
        while ( it ) {
            List<HeaderField>::Iterator h( it );
            ++it;
            if ( h->type() == HeaderField::Received ) {
                if ( !h->valid() )
                    bad = true;
                if ( bad )
                    d->fields.take( h );
            }
        }
    }

    // For some header fields which can contain errors, our best
    // option is to remove them. A field belongs here if it can be
    // parsed somehow and can be dropped without changing the meaning
    // of the rest of the message.

    if ( occurrences[(int)HeaderField::ContentLocation] ||
         occurrences[(int)HeaderField::ContentDisposition] ||
         occurrences[(int)HeaderField::ContentId] ||
         occurrences[(int)HeaderField::MessageId] ) {
        List< HeaderField >::Iterator it( d->fields );
        while ( it ) {
            if ( ( it->type() == HeaderField::ContentLocation ||
                   it->type() == HeaderField::ContentDisposition ||
                   it->type() == HeaderField::ContentId ||
                   it->type() == HeaderField::MessageId ) &&
                 !it->valid() ) {
                d->fields.take( it );
            }
            else {
                ++it;
            }
        }
    }

    // If there's more than one Sender field, preserve the first that
    // a) is syntactically valid and b) is different from From, and
    // remove the others.

    if ( occurrences[(int)HeaderField::Sender] > 1 ) {
        AddressField * good = 0;
        AddressField * from = addressField( HeaderField::From );
        List< HeaderField >::Iterator it( d->fields );
        while ( it && !good ) {
            if ( it->type() == HeaderField::Sender ) {
                if ( it->valid() && !good ) {
                    AddressField * candidate = (AddressField*)(HeaderField*)it;
                    if ( !sameAddresses( candidate, from ) )
                        good = candidate;
                }
            }
            ++it;
        }
        if ( good ) {
            it = d->fields;
            while ( it ) {
                if ( it->type() == HeaderField::Sender && it != good )
                    d->fields.take( it );
                else
                    ++it;
            }
        }
    }

    // Various spammers send two subject fields, and the resulting
    // rejection drag down our parse scores. But we can handle these:
    // - if one field is unparsable and the other is not, take the
    //   parsable one
    // - if one field is very long, it's bad
    // - if one field is long and contains other header field names,
    //   it's bad
    // - otherwise, the first field comes from the exploited software
    //   and the second from the exploiting.

    if ( occurrences[(int)HeaderField::Subject] > 1 ) {
        List<HeaderField> bad;
        List< HeaderField >::Iterator it( d->fields );
        while ( it ) {
            HeaderField * s = it;
            ++it;
            if ( s->type() == HeaderField::Subject ) {
                UString v = s->value();
                bool b = false;
                if ( v.length() > 300 ) {
                    b = true;
                }
                else if ( v.length() > 80 ) {
                    v = v.simplified();
                    UStringList::Iterator w( UStringList::split( ' ', v ) );
                    while ( w && !b ) {
                        if ( w->endsWith( ":" ) &&
                             w->isAscii() &&
                             HeaderField::fieldType( w->ascii() ) > 0 )
                            b = true;
                        ++w;
                    }
                }
                else {
                    uint i = 0;
                    while ( i < v.length() && v[i] < 128 )
                        i++;
                    if ( i < v.length() )
                        b = true;
                }
                if ( b )
                    bad.append( s );
            }
        }
        if ( bad.count() < occurrences[(int)HeaderField::Subject] ) {
            it = bad;
            while ( it ) {
                HeaderField * s = it;
                ++it;
                d->fields.remove( s );
            }
            it = d->fields;
            bool seen = false;
            while ( it ) {
                HeaderField * s = it;
                ++it;
                if ( s->type() == HeaderField::Subject ) {
                    if ( seen )
                        d->fields.remove( s );
                    else
                        seen = true;
                }
            }
        }
    }

    // If it's a multipart and the c-t field could not be parsed, try
    // to find the boundary by inspecting the body.

    if ( occurrences[(int)HeaderField::ContentType] && !body.isEmpty() ) {
        ContentType * ct = contentType();
        if ( !ct->valid() &&
             ct->type() == "multipart" &&
             ct->parameter( "boundary" ).isEmpty() ) {
            int cand = 0;
            while ( body[cand] == '\n' )
                cand++;
            bool confused = false;
            bool done = false;
            EString boundary;
            while ( cand >= 0 && cand < (int)body.length() &&
                    !done && !confused ) {
                if ( body[cand] == '-' && body[cand+1] == '-' ) {
                    int i = cand+2;
                    char c = body[i];
                    // bchars := bcharsnospace / " "
                    // bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" /
                    //                  "+" / "_" / "," / "-" / "." /
                    //                  "/" / ":" / "=" / "?"
                    while ( ( c >= 'a' && c <= 'z' ) ||
                            ( c >= 'A' && c <= 'Z' ) ||
                            ( c >= '0' && c <= '9' ) ||
                            c == '\'' || c == '(' || c == ')' ||
                            c == '+' || c == '_' || c == ',' ||
                            c == '-' || c == '.' || c == '/' ||
                            c == ':' || c == '=' || c == '?' ||
                            c == ' ' ) {
                        i++;
                        c = body[i];
                    }
                    if ( i > cand + 2 &&
                         ( body[i] == '\r' || body[i] == '\n' ) ) {
                        // found a candidate line.
                        EString s = body.mid( cand+2, i-cand-2 );
                        if ( boundary.isEmpty() ) {
                            boundary = s;
                        }
                        else if ( boundary == s ) {
                            // another boundary, fine
                        }
                        else if ( s.length() == boundary.length()+2 &&
                                  s.startsWith( boundary ) &&
                                  s.endsWith( "--" ) ) {
                            // it's the end boundary
                            done = true;
                        }
                        else if ( s.length() <= 70 ) {
                            // we've seen different boundary lines. oops.
                            confused = true;
                        }
                    }
                }
                cand = body.find( "\n--", cand+1 );
                if ( cand >= 0 )
                    cand++;
            }
            if ( !boundary.isEmpty() && !confused ) {
                ct->addParameter( "boundary", boundary );
                ct->setError( "" ); // may override other errors. ok.
            }
        }
    }

    // If the From field is syntactically invalid, but we could parse
    // one or more good addresses, kill the bad one(s) and go ahead.

    if ( occurrences[(int)HeaderField::From] == 1 ) {
        AddressField * from = addressField( HeaderField::From );
        if ( !from->valid() ) {
            List<Address>::Iterator it( from->addresses() );
            List<Address> good;
            while ( it ) {
                if ( it->error().isEmpty() &&
                     it->type() == Address::Normal &&
                     it->localpartIsSensible() )
                    good.append( it );
                ++it;
            }
            if ( !good.isEmpty() ) {
                from->addresses()->clear();
                it = good;
                while ( it ) {
                    from->addresses()->append( (Address *)it );
                    ++it;
                }
                from->setError( "" );
            }
        }
    }

    // If the from field is bad, but there is a good sender or
    // return-path, copy s/rp into from.

    if ( occurrences[(int)HeaderField::From] == 1 &&
         ( occurrences[(int)HeaderField::Sender] == 1 ||
           occurrences[(int)HeaderField::ReturnPath] == 1 ) ) {
        AddressField * from = addressField( HeaderField::From );
        if ( !from->valid() ) {
            // XXX we only consider s/rp good if the received chain is
            // unbroken. This is a proxy test: We should really be
            // checking for a pure-smtp received chain and abort if
            // there are any imap/pop/http/other hops.
            List<HeaderField>::Iterator it( d->fields );
            bool seenReceived = false;
            bool seenOther = false;
            bool unbrokenReceived = true;
            while ( it && unbrokenReceived ) {
                if ( it->type() == HeaderField::Received ) {
                    if ( seenOther )
                        unbrokenReceived = false; // rcvd, other, then rcvd
                    else
                        seenReceived = true; // true on first received
                }
                else {
                    if ( seenReceived )
                        seenOther = true; // true on first other after rcvd
                }
                ++it;
            }
            if ( unbrokenReceived ) {
                AddressField * rp = addressField( HeaderField::ReturnPath );
                AddressField * sender = addressField( HeaderField::Sender );
                Address * a = 0;
                if ( rp && rp->valid() ) {
                    List<Address> * l = rp->addresses();
                    if ( l && !l->isEmpty() &&
                         l->first()->type() != Address::Bounce )
                        a = l->first();
                }
                if ( !a && sender && sender->valid() ) {
                    List<Address> * l = sender->addresses();
                    if ( l && !l->isEmpty() &&
                         l->first()->type() != Address::Bounce )
                        a = l->first();
                }
                if ( a ) {
                    from->setError( "" );
                    from->addresses()->clear();
                    from->addresses()->append( a );
                }
            }
        }
    }

    // If there are two content-type fields, one is text/plain, and
    // the other is something other than text/plain and text/html,
    // then drop the text/plain one. It's frequently added as a
    // default, sometimes by software which doesn't check thoroughly.
    if ( occurrences[(int)HeaderField::ContentType] == 2 ) {
        bool plain = false;
        bool html = false;
        uint n = 0;
        ContentType * keep = 0;
        while ( n < 2 ) {
            ContentType * f =
                (ContentType*)field( HeaderField::ContentType, n );
            if ( f->type() == "text" && f->subtype() == "plain" )
                    plain = true;
            else if ( f->type() == "text" && f->subtype() == "html" )
                html = true;
            else
                keep = f;
            n++;
        }
        if ( plain && !html && keep ) {
            List<HeaderField>::Iterator it( d->fields );
            while ( it ) {
                if ( it->type() == HeaderField::ContentType &&
                     it != keep )
                    d->fields.take( it );
                else
                    ++it;
            }
        }
    }

    // If there are several Content-Type fields, we can classify them
    // as good, bad and neutral.
    // - Good multiparts have a boundary and it occurs
    // - Good HTML starts with doctype or html
    // - Syntactically invalid fields are bad
    // - All others are neutral
    // If we have at least one good field at the end, we dump the
    // neutral and bad ones. If we have no good fields, one neutral
    // field and the rest bad, we dump the bad ones.

    if ( occurrences[(int)HeaderField::ContentType] > 1 ) {
        List<ContentType> good;
        List<ContentType> bad;
        List<ContentType> neutral;
        uint i = 0;
        HeaderField * hf = field( HeaderField::ContentType );
        while ( hf ) {
            ContentType * ct = (ContentType*)hf;
            if ( !hf->valid() ) {
                bad.append( ct );
            }
            else if ( ct->type() == "text" && ct->subtype() == "html" ) {
                EString b = body.mid( 0, 2048 ).simplified().lower();
                if ( b.startsWith( "<!doctype" ) ||
                     b.startsWith( "<html" ) )
                    good.append( ct );
                else
                    bad.append( ct );
            }
            else if ( ct->type() == "multipart" ) {
                EString b = ct->parameter( "boundary" );
                if ( b.isEmpty() || b != b.simplified() )
                    bad.append( ct );
                else if ( body.startsWith( "n--" + b ) ||
                          body.contains( "\n--" + b ) )
                    good.append( ct );
                else
                    bad.append( ct );
            }
            else {
                neutral.append( ct );
            }
            hf = field( HeaderField::ContentType, ++i );
        }
        if ( !good.isEmpty() ) {
            removeField( HeaderField::ContentType );
            add( good.first() );
        }
        else if ( neutral.count() == 1 ) {
            removeField( HeaderField::ContentType );
            add( neutral.first() );
        }
    }

    // If there are several content-type fields, all text/html, and
    // they're different, we just remove all but one. Why are webheads
    // so clueless?

    if ( occurrences[(int)HeaderField::ContentType] > 1 ) {
        ContentType * ct = contentType();
        uint i = 1;
        while ( ct && ct->valid() &&
                ct->type() == "text" && ct->subtype() == "html" ) {
            ct = (ContentType*)field( HeaderField::ContentType, i );
            i++;
        }
        if ( !ct ) {
            ct = contentType();
            removeField( HeaderField::ContentType );
            add( ct );
        }
    }

    // If Sender contains more than one address, that may be due to
    // inappropriate fixups. For example, javamail+postfix will create
    // Sender: System@postfix, Administrator@postfix, root@origin
    //
    // We can fix that: if all addresses but the last have the same
    // domain, and the last has a different domain, drop the first
    // ones. There are also other possible algorithms.

    if ( addresses( HeaderField::Sender ) &&
         addresses( HeaderField::Sender )->count() > 1 ) {
        AddressField * sender = addressField( HeaderField::Sender );
        List<Address>::Iterator i( sender->addresses() );
        Address * last = sender->addresses()->last();
        UString domain = i->domain().titlecased();
        while ( i && i->domain().titlecased() == domain )
            ++i;
        if ( i == last ) {
            sender->addresses()->clear();
            sender->addresses()->append( last );
            sender->setError( "" );
        }
    }

    // Some crapware tries to send DSNs without a From field. We try
    // to patch it up. We don't care very much, so this parses the
    // body and discards the result, does a _very_ quick job of
    // parsing message/delivery-status, doesn't handle xtext, and
    // doesn't care whether it uses Original-Recipient or
    // Final-Recipient.
    if ( mode() == Rfc2822 &&
         ( !field( HeaderField::From ) ||
           field( HeaderField::From )->error().contains( "No-bounce" ) ) &&
         contentType() &&
         contentType()->type() == "multipart" &&
         contentType()->subtype() == "report" &&
         contentType()->parameter( "report-type" ) == "delivery-status" ) {
        ContentType * ct = contentType();
        Multipart * tmp = new Multipart;
        Bodypart::parseMultipart( 0, body.length(), body,
                                  ct->parameter( "boundary" ),
                                  false,
                                  tmp->children(), tmp);
        List<Bodypart>::Iterator i( tmp->children() );
        Address * postmaster = 0;
        while ( i && !postmaster ) {
            Header * h = i->header();
            ContentType * ct = 0;
            if ( h )
                ct = h->contentType();
            if ( ct &&
                 ct->type() == "message" &&
                 ct->subtype() == "delivery-status" ) {
                // woo.
                EStringList * lines = EStringList::split( 10, i->data() );
                EStringList::Iterator l( lines );
                EString reportingMta;
                Address * address = 0;
                while ( l ) {
                    EString line = l->lower();
                    ++l;
                    EString field = line.section( ":", 1 ).simplified();;
                    EString domain = line.section( ":", 2 ).section( ";", 1 )
                                    .simplified();
                    EString value = line.section( ":", 2 ).section( ";", 2 )
                                   .simplified();;
                    // value may be xtext, but I don't care. it's an
                    // odd error case in illegal mail, so who can say
                    // that the sender knows the xtext rules anyway?
                    if ( field == "reporting-mta" && domain == "dns" &&
                         !value.isEmpty() ) {
                        reportingMta = value;
                    }
                    else if ( ( field == "final-recipient" ||
                                field == "original-recipient" ) &&
                              domain == "rfc822" &&
                              !address && !value.isEmpty() ) {
                        AddressParser ap( value );
                        List<Address>::Iterator i( ap.addresses() );
                        while ( i && !address ) {
                            if ( i->error().isEmpty() &&
                                 !i->domain().isEmpty() )
                                address = i;
                            ++i;
                        }
                    }
                }
                if ( !reportingMta.isEmpty() && address ) {
                    AsciiCodec ac;
                    UString name = ac.toUnicode( reportingMta );
                    name.append( " postmaster" );
                    postmaster = new Address( name, "postmaster",
                                              address->domain().utf8().lower() );
                    AddressField * from = addressField( HeaderField::From );
                    if ( from ) {
                        from->setError( "" );
                        from->addresses()->clear();
                    }
                    else {
                        from = new AddressField( HeaderField::From );
                        add( from );
                    }
                    from->addresses()->append( postmaster );
                }
            }
            ++i;
        }
    }

    // If the From field is the bounce address, and we still haven't
    // salvaged it, and the message-id wasn't added here, we use
    // postmaster@<message-id-domain> and hope the postmaster there
    // knows something about the real origin.

    if ( occurrences[(int)HeaderField::From] == 1 &&
         occurrences[(int)HeaderField::MessageId] == 1 ) {
        AddressField * from = addressField( HeaderField::From );
        if ( !from->valid() ) {
            List<Address> * l = from->addresses();
            if ( l->count() == 1 &&
                 l->first()->type() == Address::Bounce )
            {
                Address * msgid = 0;
                List<Address> * al = addresses( HeaderField::MessageId );
                if ( al )
                    msgid = al->first();

                EString me = Configuration::hostname().lower();
                EString victim;
                if ( msgid )
                    victim = msgid->domain().utf8().lower();
                uint tld = victim.length();
                if ( victim[tld-3] == '.' )
                    tld -= 3; // .de
                else if ( victim[tld-4] == '.' )
                    tld -= 4; // .com
                if ( tld < victim.length() ) {
                    if ( victim[tld-3] == '.' )
                        tld -= 3; // .co.uk
                    else if ( victim[tld-4] == '.' )
                        tld -= 4; // .com.au
                    else if ( tld == victim.length() - 2 &&
                              victim[tld-5] == '.' )
                        tld -= 5; // .priv.no
                }
                int dot = victim.find( '.' );
                if ( dot < (int)tld ) {
                    victim = victim.mid( dot+1 );
                    tld = tld - dot - 1;
                }
                if ( !victim.isEmpty() &&
                     victim != me && !me.endsWith( "." + victim ) &&
                     tld < victim.length() ) {
                    Address * replacement
                        = new Address( "postmaster "
                                       "(on behalf of unnamed " +
                                       msgid->domain() + " user)",
                                       "postmaster", victim );
                    l->clear();
                    l->append( replacement );
                    from->setError( "" );
                }
            }
        }
    }

    // If we have NO From field, or one which contains only <>, use
    // invalid@invalid.invalid. We try to include a display-name if we
    // can find one. hackish hacks abound.
    if ( mode() == Rfc2822 &&
         ( !field( HeaderField::From ) ||
           ( !field( HeaderField::From )->valid() &&
             !addresses( HeaderField::From ) ) ||
           field( HeaderField::From )->error().contains( "No-bounce" ) ) ) {
        AddressField * from = addressField( HeaderField::From );
        EString raw;
        if ( from )
            raw = from->unparsedValue().simplified();
        if ( raw.endsWith( "<>" ) )
            raw = raw.mid( 0, raw.length() - 2 ).simplified();
        if ( raw.startsWith( "\"\"" ) )
            raw = raw.mid( 2 ).simplified();
        if ( raw.startsWith( "\" \"" ) )
            raw = raw.mid( 3 ).simplified();
        if ( raw.contains( '<' ) && raw.find( '<' ) > 3 )
            raw = raw.section( "<", 1 );
        if ( raw.startsWith( "\"" ) && raw.find( '"', 1 ) > 2 )
            raw = raw.section( "\"", 2 ); // "foo"bar > foo
        raw = raw.unquoted( '"', '\\' ).unquoted( '\'', '\\' ).simplified();
        if ( raw.contains( '<' ) &&
             raw.find( ">", 1+raw.find( '<' ) ) > 2 + raw.find( '<' ) )
            raw = raw.section( "<", 2 ).section( ">", 1 ).simplified();
        if ( raw.startsWith( "<" ) && raw.endsWith( ">" ) )
            raw = raw.mid( 1, raw.length() - 2 ).simplified();
        if ( raw.length() < 3 )
            raw.truncate();

        Codec * c = Codec::byString( raw );
        if ( !c )
            c = new AsciiCodec;
        UString n = c->toUnicode( raw ).simplified();
        if ( !n.isEmpty() ) {
            // look again and get rid of <>@
            uint i = 0;
            UString r;
            bool fffd = false;
            uint known = 0;
            while ( i < n.length() ) {
                if ( n[i] == '@' || n[i] == '<' || n[i] == '>' ||
                     n[i] < ' ' || ( n[i] >= 128 && n[i] < 160 ) ||
                     n[i] == 0xFFFD ) {
                    fffd = true;
                }
                else {
                    if ( fffd && !r.isEmpty() )
                        r.append( 0xFFFD );
                    r.append( n[i] );
                    fffd = false;
                    known++;
                }
                i++;
            }
            n = r;
            if ( known < 3 )
                n.truncate();
        }
        Address * a = new Address( n, "invalid", "invalid.invalid" );
        if ( from ) {
            from->setError( "" );
            from->addresses()->clear();
            from->addresses()->append( a );
        }
        else {
            from = new AddressField( HeaderField::From );
            from->addresses()->append( a );
            add( from );
        }
    }

    // If the Reply-To field is bad and From is good, we forget
    // Reply-To entirely.

    if ( occurrences[(int)HeaderField::From] &&
         occurrences[(int)HeaderField::ReplyTo] ) {
        AddressField * from = addressField( HeaderField::From );
        AddressField * rt = addressField( HeaderField::ReplyTo );
        if ( from->valid() && !rt->valid() &&
             from->addresses() && !from->addresses()->isEmpty() )
            removeField( HeaderField::ReplyTo );
    }

    // If c-t-e is bad, we try to detect.

    if ( occurrences[(int)HeaderField::ContentTransferEncoding] ) {
        ContentTransferEncoding * cte = contentTransferEncoding();
        HeaderField * cte2 = field( HeaderField::ContentTransferEncoding, 1 );
        if ( cte && ( cte2 || !cte->valid() ) ) {
            uint minl = UINT_MAX;
            uint maxl = 0;
            uint i = 0;
            uint l = 0;
            uint n = 0;
            while ( i < body.length() ) {
                if ( body[i] == '\n' || body[i] == '\r' ) {
                    if ( l > maxl )
                        maxl = l;
                    if ( l < minl )
                        minl = l;
                    l = 0;
                    n++;
                }
                else {
                    ++l;
                }
                ++i;
            }
            if ( n > 5 && maxl == minl && minl > 50 ) {
                // more than five lines, all (except the last) equally
                // long. it really looks like base64.
                removeField( HeaderField::ContentTransferEncoding );
                add( "Content-Transfer-Encoding", "base64" );
            }
            else {
                // it can be q-p or none. do we really care? can we
                // even decide reliably? I think we might as well
                // assume none.
                removeField( HeaderField::ContentTransferEncoding );
            }
        }
    }

    // Some people don't know c-t from c-t-e

    if ( occurrences[(int)HeaderField::ContentTransferEncoding] == 0 &&
         occurrences[(int)HeaderField::ContentType] &&
         !contentType()->valid() ) {
        ContentTransferEncoding * phaps =
            new ContentTransferEncoding;
        phaps->parse( contentType()->unparsedValue() );
        if ( phaps->valid() ) {
            removeField( HeaderField::ContentTransferEncoding );
            removeField( HeaderField::ContentType );
            add( phaps );
            add( "Content-Type", "application/octet-stream" );
        }
    }

    // If Content-Base, Content-Location or Content-Language is/are
    // bad, we just drop it/them

    if ( field( "Content-Base") ||
         occurrences[(int)HeaderField::ContentLanguage] ||
         occurrences[(int)HeaderField::ContentLocation] ) {
        List<HeaderField>::Iterator i( d->fields );
        while ( i ) {
            if ( !i->valid() && ( i->name() == "Content-Base" ||
                                  i->name() == "Content-Language" ||
                                  i->name() == "Content-Location" ) ) {
                d->fields.take( i );
            }
            else {
                ++i;
            }
        }
    }

    d->verified = false;
}


/*! Returns the canonical text representation of this Header.
    Downgrades rather than inclding UTF-8 if \a avoidUtf8 is true.
*/

EString Header::asText( bool avoidUtf8 ) const
{
    EString r;
    r.reserve( d->fields.count() * 100 );

    List< HeaderField >::Iterator it( d->fields );
    while ( it ) {
        appendField( r, it, avoidUtf8 );
        ++it;
    }

    return r;
}


/*! Appends the string representation of the field \a hf to \a r. Does
    nothing if \a hf is 0.

    This function doesn't wrap. That's probably a bug. How to fix it?

    (The details of the function are liable to change.)
*/

void Header::appendField( EString &r, HeaderField *hf, bool avoidUtf8 ) const
{
    if ( !hf )
        return;

    r.append( hf->name() );
    r.append( ": " );
    r.append( hf->rfc822( avoidUtf8 ) );
    r.append( crlf );
}


// heuristically returns a biggish number if a looks like a message-id
// and a smallish number if it's either nothing or an email address.

static int msgidness( const Address * a )
{
    if ( !a )
        return 0;
    UString lp = a->localpart();
    uint score = lp.length();
    if ( score < 10 )
        return 0;
    uint i = 0;
    while ( i < lp.length() ) {
        char c = lp[i];
        if ( c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' ||
             c == 'A' || c == 'E' || c == 'I' || c == 'O' || c == 'U' )
            score += 1;
        else if ( ( c >= 'a' && c <= 'z' ) ||
                  ( c >= 'A' && c <= 'Z' ) )
            score += 2;
        else if ( c >= '0' && c <= '9' )
            score += 3;
        else
            score += 4;
        i++;
    }
    return score/lp.length();
}


/*! Scans for fields containing unlabelled 8-bit content and encodes
    them using \a c.

    At the moment, this covers most unstructured fields. The exact
    scope of the function may change.
*/

void Header::fix8BitFields( class Codec * c )
{
    d->verified = false;

    Utf8Codec utf8;
    List< HeaderField >::Iterator it( d->fields );
    while ( it ) {
        List< HeaderField >::Iterator f = it;
        ++it;
        if ( !f->valid() &&
             ( f->type() == HeaderField::Subject ||
               f->type() == HeaderField::Comments ||
               f->type() == HeaderField::Keywords ||
               f->type() == HeaderField::ContentDescription ||
               // XXX: This should be more fine-grained:
               f->type() == HeaderField::Other ) )
        {
            EString v = f->unparsedValue();
            uint i = 0;
            while ( v[i] < 128 && v[i] > 0 )
                i++;
            if ( i < v.length() ) {
                c->setState( Codec::Valid );
                UString u;
                EStringList::Iterator w( EStringList::split( ' ',
                                                           v.simplified() ) );
                bool wasE = false;
                while ( w ) {
                    UString o = EmailParser::de2047( *w );
                    bool isE = true;
                    if ( o.isEmpty() ) {
                        o = c->toUnicode( *w ).simplified();
                        isE = false;
                    }
                    if ( ( !isE || !wasE ) && !u.isEmpty() )
                        u.append( ' ' );
                    u.append( o );
                    wasE = isE;
                    ++w;
                }
                bool ok = false;
                if ( c->wellformed() )
                    ok = true;
                else if ( f->type() == HeaderField::Other )
                    d->fields.remove( f );
                else if ( f->type() == HeaderField::Subject )
                    ok = true;
                else if ( f->error().isEmpty() )
                    f->setError( "Cannot parse either as US-ASCII or " +
                                 c->name() );
                if ( ok )
                    f->setValue( u.simplified() );
            }
        }
        else if ( f->type() == HeaderField::ContentType ||
                  f->type() == HeaderField::ContentTransferEncoding ||
                  f->type() == HeaderField::ContentDisposition ||
                  f->type() == HeaderField::ContentLanguage )
        {
            MimeField * mf = (MimeField*)((HeaderField*)f);
            EStringList::Iterator p( mf->parameters() );
            while ( p ) {
                EStringList::Iterator a( p );
                ++p;
                EString v = mf->parameter( *a );
                uint i = 0;
                while ( v[i] < 128 && v[i] > 0 )
                    i++;
                if ( i < v.length() ) {
                    // so. we have an argument containing unencoded
                    // 8-bit material. what to do?
                    c->setState( Codec::Valid );
                    UString u = c->toUnicode( v );
                    if ( c->wellformed() )
                        // we could parse it, so let's encode it using
                        // RFC 2047 encoding. later we probably want
                        // to use RFC 2231 encoding, but that's
                        // premature at the moment. don't know whether
                        // readers support it.
                        mf->addParameter( *a, HeaderField::encodeWord( u ) );
                    else
                        // unparsable. just remove it?
                        mf->removeParameter( *a );
                }
            }
        }
        else if ( f->type() == HeaderField::InReplyTo ) {
            EString v = f->unparsedValue();
            uint i = 0;
            while ( v[i] < 128 && v[i] > 0 )
                i++;
            if ( i < v.length() ) {
                EStringList::Iterator i( EStringList::split( '<', v ) );
                Address * best = 0;
                while ( i ) {
                    if ( i->contains( '>' ) ) {
                        EString c = "<" + i->section( ">", 1 ) + ">";
                        AddressParser * ap = AddressParser::references( c );
                        if ( ap->error().isEmpty() &&
                             ap->addresses()->count() == 1 ) {
                            Address * candidate = ap->addresses()->first();
                            if ( msgidness( candidate ) > msgidness( best ) &&
                                 candidate->localpartIsSensible() )
                                best = candidate;
                        }
                    }
                    ++i;
                }
                if ( best ) {
                    UString u;
                    u.append( "<" );
                    u.append( best->localpart() );
                    u.append( "@" );
                    u.append( best->domain() );
                    u.append( ">" );
                    f->setValue( u );
                }
                else {
                    d->fields.remove( f );
                }
            }
        }
    }
}


/*! Notifies this Header that if no ContentType is set, its default
    type is \a t. The initial value is TextPlain.
*/

void Header::setDefaultType( DefaultType t )
{
    d->defaultType = t;
}


/*! Returns whatever was set using setDefaultType(), or TextPlain if
    setDefaultType() hasn't been called.
*/

Header::DefaultType Header::defaultType() const
{
    return d->defaultType;
}


/*! Returns true if transmitting this header requires unicode
    capability, and false if transmitting ASCII suffices.

    MIME permits this to return false for most headers, but
    internationalized addresses need unicode.
*/

bool Header::needsUnicode() const
{
    List<HeaderField>::Iterator i( d->fields );
    while ( i ) {
        if ( i->needsUnicode() )
            return true;
        ++i;
    }
    return false;
}
