// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ANNOTATION_H
#define ANNOTATION_H

#include "string.h"
#include "annotationname.h"


class Annotation
    : public Garbage
{
public:
    Annotation();
    Annotation( const String &, const String &, uint );

    void setEntryName( const String & );
    String entryName() const;

    void setValue( const String & );
    String value() const;

    void setOwnerId( uint );
    uint ownerId() const;

private:
    class AnnotationData * d;
};


#endif
