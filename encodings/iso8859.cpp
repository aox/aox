// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "iso8859.h"

#include "string.h"
#include "ustring.h"

#include "utf.h"


/*! \class Iso88591Codec iso8859.h

    The Iso88591Codec converts between ISO 8859-1 and Unicode, using this
    simplified mapping: 8859-1 is the first 256 code points of unicode.
    The tiny little problem of code points 128-159 is resolutely ignored.
*/


/*! \fn Iso88591Codec::Iso88591Codec()

    Constructs a Codec for ISO-8859-1.
*/


/*! Converts \a u from Unicode to 8859-1, mapping all characters after
    U+00FF to '?'.
*/

String Iso88591Codec::fromUnicode( const UString & u )
{
    String s;
    s.reserve( u.length() );
    uint i = 0;
    while ( i < u.length() ) {
        if ( u[i] < 256 )
            s.append( (char)u[i] );
        else
            s.append( '?' );
        i++;
    }
    return s;
}


/*! Converts \a s from 8859-1 to Unicode. */

UString Iso88591Codec::toUnicode( const String & s )
{
    UString u;
    u.reserve( s.length() );
    uint i = 0;
    while ( i < s.length() ) {
        u.append( s[i] );
        i++;
    }
    return u;
}


static const int table88592[256] = {
#include "8859-2.inc"
};


/*! \class Iso88592Codec iso8859.h

    The Iso88592Codec class convers bet ISO 8859-3 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-2 is published.
*/


/*!  Constructs a codec for ISO 8859-2, using the table provided by
     the Unicode consortium.
*/

Iso88592Codec::Iso88592Codec()
    : TableCodec( table88592, "ISO-8859-2" )
{
}



static const int table88593[256] = {
#include "8859-3.inc"
};

/*! \class Iso88593Codec iso8859.h

    The Iso88593Codec class convers bet ISO 8859-2 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-2 is published.
*/


/*!  Constructs a codec for ISO 8859-2, using the table provided by
     the Unicode consortium.
*/

Iso88593Codec::Iso88593Codec()
    : TableCodec( table88593, "ISO-8859-3" )
{
}



static const int table88594[256] = {
#include "8859-4.inc"
};

/*! \class Iso88594Codec iso8859.h

    The Iso88594Codec class convers bet ISO 8859-4 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-2 is published.
*/


/*!  Constructs a codec for ISO 8859-4, using the table provided by
     the Unicode consortium.
*/

Iso88594Codec::Iso88594Codec()
    : TableCodec( table88594, "ISO-8859-4" )
{
}


static const int table88595[256] = {
#include "8859-5.inc"
};

/*! \class Iso88595Codec iso8859.h

    The Iso88595Codec class convers bet ISO 8859-5 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-5 is published.
*/


/*!  Constructs a codec for ISO 8859-5, using the table provided by
     the Unicode consortium.
*/

Iso88595Codec::Iso88595Codec()
    : TableCodec( table88595, "ISO-8859-5" )
{
}


static const int table88596[256] = {
#include "8859-6.inc"
};

/*! \class Iso88596Codec iso8859.h

    The Iso88596Codec class convers bet ISO 8859-6 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-6 is published.
*/


/*!  Constructs a codec for ISO 8859-6, using the table provided by
     the Unicode consortium.
*/

Iso88596Codec::Iso88596Codec()
    : TableCodec( table88596, "ISO-8859-6" )
{
}


static const int table88597[256] = {
#include "8859-7.inc"
};

/*! \class Iso88597Codec iso8859.h

    The Iso88597Codec class convers bet ISO 8859-7 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-7 is published.
*/


/*!  Constructs a codec for ISO 8859-7, using the table provided by
     the Unicode consortium.
*/

Iso88597Codec::Iso88597Codec()
    : TableCodec( table88597, "ISO-8859-7" )
{
}


static const int table88598[256] = {
#include "8859-8.inc"
};

/*! \class Iso88598Codec iso8859.h

    The Iso88598Codec class convers bet ISO 8859-8-I and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-8-I is published.

    8859-8-I is the version where direction is implied; see RFC 1556.
*/


/*!  Constructs a codec for ISO 8859-8-I, using the table provided by
     the Unicode consortium. See RFC 1556 for more about implicit and
     explicit directionality.
*/

Iso88598Codec::Iso88598Codec()
    : TableCodec( table88598, "ISO-8859-8" )
{
}


static const int table88599[256] = {
#include "8859-9.inc"
};

/*! \class Iso88599Codec iso8859.h

    The Iso88599Codec class convers bet ISO 8859-9 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-9 is published.
*/


/*!  Constructs a codec for ISO 8859-9, using the table provided by
     the Unicode consortium.
*/

Iso88599Codec::Iso88599Codec()
    : TableCodec( table88599, "ISO-8859-9" )
{
}


static const int table885910[256] = {
#include "8859-10.inc"
};

/*! \class Iso885910Codec iso8859.h

    The Iso885910Codec class convers bet ISO 8859-10 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-10 is published.
*/


/*!  Constructs a codec for ISO 8859-10, using the table provided by
     the Unicode consortium.
*/

Iso885910Codec::Iso885910Codec()
    : TableCodec( table885910, "ISO-8859-10" )
{
}


static const int table885911[256] = {
#include "8859-11.inc"
};

/*! \class Iso885911Codec iso8859.h

    The Iso885911Codec class convers bet ISO 8859-11 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-11 is published.
*/


/*!  Constructs a codec for ISO 8859-11, using the table provided by
     the Unicode consortium.
*/

Iso885911Codec::Iso885911Codec()
    : TableCodec( table885911, "ISO-8859-11" )
{
}


// there is no 12 - it was shelved while still a draft


/*! \class Iso885913Codec iso8859.h

    The Iso885913Codec class convers bet ISO 8859-13 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-13 is published.
*/


static const int table885913[256] = {
#include "8859-13.inc"
};

/*!  Constructs a codec for ISO 8859-13, using the table provided by
     the Unicode consortium.
*/

Iso885913Codec::Iso885913Codec()
    : TableCodec( table885913, "ISO-8859-13" )
{
}


static const int table885914[256] = {
#include "8859-14.inc"
};

/*! \class Iso885914Codec iso8859.h

    The Iso885914Codec class convers bet ISO 8859-14 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-14 is published.
*/


/*!  Constructs a codec for ISO 8859-14, using the table provided by
     the Unicode consortium.
*/

Iso885914Codec::Iso885914Codec()
    : TableCodec( table885914, "ISO-8859-14" )
{
}


static const int table885915[256] = {
#include "8859-15.inc"
};

/*! \class Iso885915Codec iso8859.h

    The Iso885915Codec class convers bet ISO 8859-15 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-15 is published.
*/


/*!  Constructs a codec for ISO 8859-15, using the table provided by
     the Unicode consortium.
*/

Iso885915Codec::Iso885915Codec()
    : TableCodec( table885915, "ISO-8859-15" )
{
}


static const int table885916[256] = {
#include "8859-16.inc"
};

/*! \class Iso885916Codec iso8859.h

    The Iso885916Codec class convers bet ISO 8859-16 and Unicode, using
    tables published by the Unicode Consortium. We have scripts to
    update the tables if/when a new revision of ISO 8859-16 is published.
*/


/*!  Constructs a codec for ISO 8859-16, using the table provided by
     the Unicode consortium.
*/

Iso885916Codec::Iso885916Codec()
    : TableCodec( table885916, "ISO-8859-16" )
{
}


// for charset.pl:
//codec ISO-8859-1 Iso88591Codec
//codec ISO-8859-2 Iso88592Codec
//codec ISO-8859-3 Iso88593Codec
//codec ISO-8859-4 Iso88594Codec
//codec ISO-8859-5 Iso88595Codec
//codec ISO-8859-6 Iso88596Codec
//codec ISO-8859-7 Iso88597Codec
//codec ISO-8859-8 Iso88598Codec
//codec ISO-8859-9 Iso88599Codec
//codec ISO-8859-10 Iso885910Codec
//codec ISO-8859-11 Iso885911Codec
// (see http://mail.apps.ietf.org/ietf/charsets/msg01362.html)
//codec ISO-8859-13 Iso885913Codec
//codec ISO-8859-14 Iso885914Codec
//codec ISO-8859-15 Iso885915Codec
//codec ISO-8859-16 Iso885916Codec


