// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "multipart.h"

#include "message.h"


/*! \class Multipart multipart.h
    This class represents the common characteristics of Messages and
    Bodyparts, namely that they have a header() and children().
*/

/*! Constructs an empty Multipart object.
*/

Multipart::Multipart()
    : h( 0 ), p( 0 ), parts( new List< Bodypart > )
{
}


/*! Returns a pointer to the Header for this Multipart object, or 0 if
    none has been set with setHeader().
*/

Header *Multipart::header() const
{
    return h;
}


/*! Sets the header of this Multipart object to \a hdr. */

void Multipart::setHeader( Header *hdr )
{
    h = hdr;
}


/*! Returns a pointer to the parent of this Multipart, or 0 if this is a
    top-level MIME object.
*/

Multipart *Multipart::parent() const
{
    return p;
}


/*! Sets the parent of this Multipart object to \a pt. */

void Multipart::setParent( Multipart *pt )
{
    p = pt;
}


/*! Returns a pointer to a list of Bodyparts belonging to this object.
    Will never return 0.
*/

List< Bodypart > *Multipart::children() const
{
    return parts;
}
