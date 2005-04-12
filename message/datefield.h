// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DATEFIELD_H
#define DATEFIELD_H

#include "field.h"
#include "date.h"


class DateField
    : public HeaderField
{
public:
    DateField( HeaderField::Type );

    void parse();

    ::Date *date() const;

private:
    ::Date *d;
};


#endif
