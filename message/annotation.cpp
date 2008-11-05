// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "annotation.h"


class AnnotationData
    : public Garbage
{
public:
    AnnotationData(): ownerId( 0 ) {}
    String name;
    String value;
    uint ownerId;
};


/*! \class Annotation annotation.h

    The Annotation class models a single annotation for a message,
    ie. it has an entr name, a value, an owner and associated data.
    The Annotation object doesn't register itself or maintain pointers
    to other objects - it's a simple value.

    InjectableMessage::replaceAnnotation(),
    InjectableMessage::annotations(), Fetch::annotation() and the
    Seelctor are the main users of Annotation.
*/

/*! Constructs an empty Annotation. */

Annotation::Annotation()
    : d( new AnnotationData )
{
    // nothing more necessary
}


/*! Constructs a new Annotation with the given \a name, \a value, and
    \a owner.
*/

Annotation::Annotation( const String & name, const String & value,
                        uint owner )
    : d( new AnnotationData )
{
    d->name = name;
    d->value = value;
    d->ownerId = owner;
}


/*! Records that the value of this annotation is \a v. The initial
    value is an empty string.
*/

void Annotation::setValue( const String & v )
{
    d->value = v;
}


/*! Returns the annotation's value, as set by setValue(). */

String Annotation::value() const
{
    return d->value;
}


/*! Records that the entry name of this annotation is \a name.
    Annotation does not enforce validity.
*/

void Annotation::setEntryName( const String & name )
{
    d->name = name;
}


/*! Returns the annotation's entry name, as set by setEntryName(). */

String Annotation::entryName() const
{
    return d->name;
}


/*! Records that the user id owning this annotation is \a id. The
    initial value is 0, corresponding to a shared annotation.
*/

void Annotation::setOwnerId( uint id )
{
    d->ownerId = id;
}


/*! Returns the annotation's owner ID, as set by setOwnerId(). */

uint Annotation::ownerId() const
{
    return d->ownerId;
}
