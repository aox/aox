// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
    AddressField( HeaderField::Type, Address * );

    void parse( const EString & );

    EString rfc822() const;
    UString value() const;

    List<Address> *addresses() const;
    void setAddresses( List<Address>* );

protected:
    void parseAddressList( const EString & );
    void parseMailboxList( const EString & );
    void parseMailbox( const EString & );
    void parseReferences( const EString & );
    void parseMessageId( const EString & );
    void parseContentId( const EString & );

private:
    void outlawBounce();

private:
    List< Address > *a;
};


#endif
