// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ADDRESSFIELD_H
#define ADDRESSFIELD_H

#include "field.h"
#include "address.h"
#include "list.h"


class AddressField
    : public HeaderField
{
public:
    AddressField( HeaderField::Type );

    void parse( const String & );
    void update();

    List< Address > *addresses() const;

protected:
    void parseAddressList( const String & );
    void parseMailboxList( const String & );
    void parseMailbox( const String & );
    void parseReferences( const String & );
    void parseMessageId( const String & );

private:
    void outlawBounce();

private:
    List< Address > *a;
};


#endif
