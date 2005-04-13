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


void AddressField::parse()
{
    switch ( type() ) {
    case HeaderField::Sender:
    case HeaderField::ReturnPath:
    case HeaderField::ResentSender:
        parseMailbox();
        break;

    case HeaderField::From:
    case HeaderField::ResentFrom:
        parseMailboxList();
        break;

    case HeaderField::To:
    case HeaderField::Cc:
    case HeaderField::Bcc:
    case HeaderField::ReplyTo:
    case HeaderField::ResentTo:
    case HeaderField::ResentCc:
    case HeaderField::ResentBcc:
        parseAddressList();
        break;

    case HeaderField::MessageId:
    case HeaderField::ContentId:
    case HeaderField::ResentMessageId:
        parseMessageId();
        break;

    case HeaderField::References:
        parseReferences();
        break;

    default:
        // Should not happen.
        break;
    }

    update();
}


/*! Updates the value() and data() for this AddressField. This function
    must be called after any changes to the addresses().
*/

void AddressField::update()
{
    String s;
    HeaderField::Type t = type();
    List< Address >::Iterator it( addresses()->first() );

    if ( t == HeaderField::ReturnPath ) {
        if ( it )
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
            lsep = "\n ";
            lpos = 1;
        }
        else {
            wsep = ", ";
            lsep = ",\n    ";
            lpos = 4;
        }

        while ( it ) {
            String a = it->toString();
            if ( t == HeaderField::References )
                a = "<" + a + ">";
            if ( first ) {
                first = false;
            }
            else if ( c + wsep.length() + a.length() > 72 ) {
                s.append( lsep );
                c = lpos;
            }
            else {
                s.append( wsep );
                c = c + wsep.length();
            }
            s.append( a );
            c = c + a.length();
            ++it;
        }
    }
    else if ( t == HeaderField::MessageId ||
              t == HeaderField::ResentMessageId ||
              t == HeaderField::ContentId )
    {
        if ( it )
            s = "<" + it->toString() + ">";
    }

    setValue( s );
    setData( s );
}


/*! Parses the RFC 2822 address-list production and records the first
    problem found.
*/

void AddressField::parseAddressList()
{
    AddressParser ap( string() );
    setError( ap.error() );
    a = ap.addresses();
}


/*! Parses the RFC 2822 mailbox-list production and records the first
    problem found.
*/

void AddressField::parseMailboxList()
{
    parseAddressList();

    // A mailbox-list is an address-list where groups aren't allowed.
    List< Address >::Iterator it( a->first() );
    while ( it && valid() ) {
        if ( it->localpart().isEmpty() || it->domain().isEmpty() )
            setError( "Invalid mailbox: '" + it->toString() + "'" );
        ++it;
    }
}


/*! Parses the RFC 2822 mailbox production and records the first
    problem found.
*/

void AddressField::parseMailbox()
{
    parseMailboxList();

    // A mailbox in our world is just a mailbox-list with one entry.
    if ( valid() && a->count() > 1 )
        setError( "Only one address is allowed" );
}


/*! Parses the contents of an RFC 2822 references field. This is
    nominally 1*msg-id, but in practice we need to be a little more
    flexible. Overlooks common problems and records the first serious
    problems found.
*/

void AddressField::parseReferences()
{
    AddressParser *ap = AddressParser::references( string() );
    setError( ap->error() );
    a = ap->addresses();
}


/*! Parses the RFC 2822 msg-id production and records the first
    problem found.
*/

void AddressField::parseMessageId()
{
    parseReferences();

    if ( valid() ) {
        if ( a->count() == 0 )
            // We'll tolerate (and remove) invalid Message-Ids.
            ;
        else if ( a->count() > 1 )
            setError( "Only one msg-id is allowed" );
    }
}


/*! Returns a pointer to the List of addresses contained in this field.
*/

List< Address > *AddressField::addresses() const
{
    return a;
}
