// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DATEFIELD_H
#define DATEFIELD_H

#include "field.h"
#include "date.h"


class DateField
    : public HeaderField
{
public:
    DateField( HeaderField::Type );

    void parse( const EString & );

    ::Date *date() const;
};


#endif
