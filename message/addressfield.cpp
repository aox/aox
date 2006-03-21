// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "addressfield.h"


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


void AddressField::parse( const String &s )
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
        break;

    case HeaderField::MessageId:
    case HeaderField::ContentId:
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

    update();
}


/*! Updates the value() and data() for this AddressField. This function
    must be called after any changes to the addresses().
*/

void AddressField::update()
{
    String s;
    HeaderField::Type t = type();
    List< Address >::Iterator it( addresses() );

    if ( t == HeaderField::ReturnPath ) {
        if ( !it )
            ;
        else if ( it->type() == Address::Bounce )
            s = "<>";
        else if ( it->type() == Address::Normal )
            s = "<" + it->localpart() + "@" + it->domain() + ">";
    }
    else if ( t <= HeaderField::LastAddressField ||
              t == HeaderField::References )
    {
        bool first = true;
        String wsep, lsep;
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
            String a = it->toString();
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
    else if ( t == HeaderField::MessageId ||
              t == HeaderField::ResentMessageId ||
              t == HeaderField::ContentId )
    {
        if ( it )
            s = "<" + it->toString() + ">";
    }

    setData( s );
}


/*! Parses the RFC 2822 address-list production from \a s and records
    the first problem found.
*/

void AddressField::parseAddressList( const String &s )
{
    AddressParser ap( s );
    setError( ap.error() );
    a = ap.addresses();
}


/*! Parses the RFC 2822 mailbox-list production from \a s and records
    the first problem found.
*/

void AddressField::parseMailboxList( const String &s )
{
    parseAddressList( s );

    // A mailbox-list is an address-list where groups aren't allowed.
    List< Address >::Iterator it( a );
    while ( it && valid() ) {
        if ( it->type() == Address::EmptyGroup )
            setError( "Invalid mailbox: '" + it->toString() + "'" );
        ++it;
    }
}


/*! Parses the RFC 2822 mailbox production from \a s and records the
    first problem found.
*/

void AddressField::parseMailbox( const String &s )
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

void AddressField::parseReferences( const String &s )
{
    AddressParser *ap = AddressParser::references( s );
    setError( ap->error() );
    a = ap->addresses();
}


/*! Parses the RFC 2822 msg-id production from \a s. Unlike most other
    functions in AddressField, this function ignores all errors found.

    There are so many bad message-ids that we cannot reject mail. We
    do better to behave as if such mail has no message-id field at
    all.
*/

void AddressField::parseMessageId( const String &s )
{
    AddressParser *ap = AddressParser::references( s );

    if ( ap->error().isEmpty() &&
         ap->addresses()->count() == 1 )
        a = ap->addresses();

    // if the message-id field is bad, we silently forget the field.
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
