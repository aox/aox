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

    void parse();
    void update();

    List< Address > *addresses() const;

protected:
    void parseAddressList();
    void parseMailboxList();
    void parseMailbox();
    void parseReferences();
    void parseMessageId();

private:
    void outlawBounce();

private:
    List< Address > *a;
};


#endif
