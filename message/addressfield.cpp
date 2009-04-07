// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "addressfield.h"

#include "ustring.h"
#include "codec.h"


/*! \class AddressField addressfield.h
    Represents a field containing a list of addresses.

    This simple class encapsulates a List< Address > in a HeaderField.
    It is responsible for parsing the field (with Address) and setting
    the correct field value.
*/


AddressField::AddressField( HeaderField::Type t )
    : HeaderField( t ),
      a( new List< Address > )
{
}


/*! Constructs an AddressField of \a type, containing the single
    Address \a address .
*/

AddressField::AddressField( HeaderField::Type type, Address * address )
    : HeaderField( type ), a( new List<Address> )
{
    a->append( address );
}


void AddressField::parse( const EString &s )
{
    switch ( type() ) {
    case HeaderField::Sender:
        parseMailbox( s );
        if ( !valid() && addresses()->isEmpty() ) {
            // sender is quite often wrong in otherwise perfectly
            // legible messages. so we'll nix out the error. Header
            // will probably remove the field completely, since an
            // empty Sender field isn't sensible.
            setError( "" );
        }
        break;

    case HeaderField::ReturnPath:
        parseMailbox( s );
        if ( !valid() || addresses()->count() != 1 ||
             ( addresses()->first()->type() != Address::Bounce &&
               addresses()->first()->type() != Address::Normal ) ) {
            // return-path sometimes contains strange addresses when
            // migrating from older stores. if it does, just kill
            // it. this never happens when receiving mail, since we'll
            // make a return-path of our own.
            setError( "" );
            a->clear();
        }
        break;

    case HeaderField::ResentSender:
        parseMailbox( s );
        break;

    case HeaderField::From:
    case HeaderField::ResentFrom:
        parseMailboxList( s );
        break;

    case HeaderField::To:
    case HeaderField::Cc:
    case HeaderField::Bcc:
    case HeaderField::ReplyTo:
    case HeaderField::ResentTo:
    case HeaderField::ResentCc:
    case HeaderField::ResentBcc:
        parseAddressList( s );
        if ( type() == HeaderField::Cc && !valid() && a->count() <= 1 ) {
            // /bin/mail tempts people to type escape, ctrl-d or
            // similar into the cc field, so we try to recover from
            // that.
            uint i = 0;
            while ( i < s.length() && s[i] >= ' ' && s[i] != 127 )
                i++;
            if ( i < s.length() ) {
                setError( "" );
                a->clear();
            }
        }
        if ( !valid() && s.simplified().length() == 1 ) {
            setError( "" );
            a->clear();
        }
        if ( valid() && s.contains( "<>" ) ) {
            // some spammers attempt to send 'To: asdfsaf <>'.
            List<Address>::Iterator i( a );
            uint bounces = 0;
            uint otherProblems = 0;
            while ( i ) {
                if ( i->type() == Address::Bounce )
                    bounces++;
                else if ( !i->error().isEmpty() )
                    otherProblems++;
                ++i;
            }
            if ( bounces && !otherProblems ) {
                // there's one or more <>, but nothing else bad.
                i = a->first();
                while ( i ) {
                    if ( i->type() == Address::Bounce )
                        a->take( i );
                    else
                        ++i;
                }
                setError( "" );
            }
        }
        if ( !valid() && a->isEmpty() && !s.contains( "@" ) ) {
            // some spammers send total garbage. we can't detect all
            // instances of garbage, but if it doesn't contain even
            // one "@" and also not even one parsable address, surely
            // it's garbage.
            setError( "" );
        }
        if ( !valid() && a->count() <= 1 && s.startsWith( "@" ) ) {
            // some spammers send To: @hostname. forget it.
            a->clear();
            setError( "" );
        }
        break;

    case HeaderField::ContentId:
        parseContentId( s );
        break;

    case HeaderField::MessageId:
    case HeaderField::ResentMessageId:
        parseMessageId( s );
        break;

    case HeaderField::References:
        parseReferences( s );
        break;

    default:
        // Should not happen.
        break;
    }

    if ( type() != HeaderField::ReturnPath )
        outlawBounce();
    if ( !valid() )
        setUnparsedValue( s );
}


/*! Generates the RFC 822 representation of the field, based on the
    addresses().
*/

EString AddressField::rfc822() const
{
    EString s;
    s.reserve( 30 * addresses()->count() );
    HeaderField::Type t = type();
    List< Address >::Iterator it( addresses() );

    if ( t == HeaderField::ReturnPath ) {
        if ( !it )
            ;
        else if ( it->type() == Address::Bounce )
            s = "<>";
        else if ( it->type() == Address::Normal )
            s = "<" + it->lpdomain() + ">";
    }
    else if ( t == HeaderField::MessageId ||
              t == HeaderField::ResentMessageId ||
              t == HeaderField::ContentId ||
              ( t == HeaderField::References && !it ) )
    {
        if ( it ) {
            s = "<" + it->toString() + ">";
        }
        else {
            s = name() + ": ";
            s.append( value().ascii() );
            s = s.simplified().wrapped( 78, "", " ", false );
            s = s.mid( name().length() + 2 );
        }
    }
    else if ( t <= HeaderField::LastAddressField ||
              t == HeaderField::References )
    {
        bool first = true;
        EString wsep, lsep;
        uint c = name().length() + 2;
        uint lpos;

        if ( t == HeaderField::References ) {
            wsep = " ";
            lsep = "\r\n ";
            lpos = 1;
        }
        else {
            wsep = ", ";
            lsep = ",\r\n    ";
            lpos = 4;
        }

        while ( it ) {
            EString a = it->toString();
            ++it;

            if ( t == HeaderField::References )
                a = "<" + a + ">";

            if ( first ) {
                first = false;
            }
            else if ( ( c + wsep.length() + a.length() > 78 ) ||
                      ( c + wsep.length() + a.length() == 78 && it ) )
            {
                s.append( lsep );
                c = lpos;
            }
            else {
                s.append( wsep );
                c += wsep.length();
            }
            s.append( a );
            c += a.length();
        }
    }

    return s;
}


UString AddressField::value() const
{
    if ( addresses()->isEmpty() )
        return HeaderField::value();
    // and for message-id, content-id and references:
    AsciiCodec a;
    return a.toUnicode( rfc822().simplified() );
}


/*! Parses the RFC 2822 address-list production from \a s and records
    the first problem found.
*/

void AddressField::parseAddressList( const EString &s )
{
    AddressParser ap( s );
    setError( ap.error() );
    a = ap.addresses();
}


/*! Parses the RFC 2822 mailbox-list production from \a s and records
    the first problem found.
*/

void AddressField::parseMailboxList( const EString &s )
{
    parseAddressList( s );

    // A mailbox-list is an address-list where groups aren't allowed.
    List< Address >::Iterator it( a );
    while ( it && valid() ) {
        if ( it->type() == Address::EmptyGroup )
            setError( "Invalid mailbox: " + it->toString().quoted() );
        ++it;
    }
}


/*! Parses the RFC 2822 mailbox production from \a s and records the
    first problem found.
*/

void AddressField::parseMailbox( const EString &s )
{
    parseMailboxList( s );

    // A mailbox in our world is just a mailbox-list with one entry.
    if ( valid() && a->count() > 1 )
        setError( "Only one address is allowed" );
}


/*! Parses the contents of an RFC 2822 references field in \a s. This
    is nominally 1*msg-id, but in practice we need to be a little more
    flexible. Overlooks common problems and records the first serious
    problems found.
*/

void AddressField::parseReferences( const EString &s )
{
    AddressParser *ap = AddressParser::references( s );
    a = ap->addresses();
    setError( ap->error() );
}


/*! Parses the RFC 2822 msg-id production from \a s and/or records the
    first serious error found.
*/

void AddressField::parseMessageId( const EString &s )
{
    AddressParser *ap = AddressParser::references( s );

    if ( !ap->error().isEmpty() )
        setError( ap->error() );
    else if ( ap->addresses()->count() == 1 )
        a = ap->addresses();
    else
        setError( "Need exactly one" );
}


/*! Like parseMessageId( \a s ), except that it also accepts <blah>. */

void AddressField::parseContentId( const EString & s )
{
    AddressParser ap( s );
    setError( ap.error() );
    if ( ap.addresses()->count() != 1 ) {
        setError( "Need exactly one" );
        return;
    }

    switch ( ap.addresses()->first()->type() ) {
    case Address::Normal:
        a = ap.addresses();
        //setData( "<" + a->lpdomain() + ">" );
        break;
    case Address::Bounce:
        setError( "<> is not legal, it has to be <some@thing>" );
        break;
    case Address::EmptyGroup:
        setError( "Error parsing Content-ID" );
        break;
    case Address::Local:
        a = ap.addresses();
        //setData( "<" + a->localpart() + ">" );
        break;
    case Address::Invalid:
        setError( "Error parsing Content-Id" );
        break;
    }
}


/*! Returns a pointer to the List of addresses contained in this field.

    This is never a null pointer.
*/

List< Address > *AddressField::addresses() const
{
    return a;
}


/*! Checks whether '<>' is present in this address field, and records
    an error if it is. '<>' is legal in Return-Path, but as of April
    2005, not in any other field.
*/

void AddressField::outlawBounce()
{
    List< Address >::Iterator it( a );
    while ( it && valid() ) {
        if ( it->type() == Address::Bounce )
            setError( "No-bounce address not allowed in this field" );
        ++it;
    }
}
