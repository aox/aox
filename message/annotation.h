// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ANNOTATION_H
#define ANNOTATION_H

#include "estring.h"


class Annotation
    : public Garbage
{
public:
    Annotation();
    Annotation( const EString &, const EString &, uint );

    void setEntryName( const EString & );
    EString entryName() const;

    void setValue( const EString & );
    EString value() const;

    void setOwnerId( uint );
    uint ownerId() const;

private:
    class AnnotationData * d;
};


#endif
