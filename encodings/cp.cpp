#include "cp.h"

// DOS code pages, 437-869 or so. 874 is in the window section, below.


static const int tablecp437[256] = {
#include "cp437.inc"
};

/*! \class Cp437Codec cp.h

    The Cp437Codec class convers bet IBM/Microsoft Codepage 437 and
    Unicode, using tables published by the Unicode Consortium. We have
    scripts to update the tables if/when the Unicode Consortium
    decides to publish new tables.
*/


/*!  Constructs a codec for CP-437, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp437Codec::Cp437Codec()
    : TableCodec( tablecp437, "IBM437" )
{
}


static const int tablecp737[256] = {
#include "cp737.inc"
};

/*! \class Cp737Codec cp.h

    The Cp737Codec class convers bet IBM/Microsoft Codepage 737 and
    Unicode, using tables published by the Unicode Consortium. We have
    scripts to update the tables if/when the Unicode Consortium
    decides to publish new tables.
*/


/*!  Constructs a codec for CP-737, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp737Codec::Cp737Codec()
    : TableCodec( tablecp737, "IBM737" )
{
}



static const int tablecp775[256] = {
#include "cp775.inc"
};

/*! \class Cp775Codec cp.h

    The Cp775Codec class convers bet IBM/Microsoft Codepage 775 and
    Unicode, using tables published by the Unicode Consortium. We have
    scripts to update the tables if/when the Unicode Consortium
    decides to publish new tables.
*/


/*!  Constructs a codec for CP-775, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp775Codec::Cp775Codec()
    : TableCodec( tablecp775, "IBM775" )
{
}


static const int tablecp850[256] = {
#include "cp850.inc"
};

/*! \class Cp850Codec cp.h

    The Cp850Codec class convers bet IBM/Microsoft Codepage 850 and
    Unicode, using tables published by the Unicode Consortium. We have
    scripts to update the tables if/when the Unicode Consortium
    decides to publish new tables.
*/


/*!  Constructs a codec for CP-850, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp850Codec::Cp850Codec()
    : TableCodec( tablecp850, "IBM850" )
{
}


static const int tablecp852[256] = {
#include "cp852.inc"
};


/*! \class Cp852Codec cp.h

    The Cp852Codec class convers bet IBM/Microsoft Codepage 852 and
    Unicode, using tables published by the Unicode Consortium. We have
    scripts to update the tables if/when the Unicode Consortium
    decides to publish new tables.
*/


/*!  Constructs a codec for CP-852, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp852Codec::Cp852Codec()
    : TableCodec( tablecp852, "IBM852" )
{
}


static const int tablecp855[256] = {
#include "cp855.inc"
};

/*! \class Cp855Codec cp.h

The Cp855Codec class converts between IBM/Microsoft Codepage 855 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-855, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp855Codec::Cp855Codec()
    : TableCodec( tablecp855, "IBM855" )
{
}


static const int tablecp857[256] = {
#include "cp857.inc"
};

/*! \class Cp857Codec cp.h

The Cp857Codec class converts between IBM/Microsoft Codepage 857 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-857, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp857Codec::Cp857Codec()
    : TableCodec( tablecp857, "IBM857" )
{
}


static const int tablecp860[256] = {
#include "cp860.inc"
};

/*! \class Cp860Codec cp.h

The Cp860Codec class converts between IBM/Microsoft Codepage 860 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-860, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp860Codec::Cp860Codec()
    : TableCodec( tablecp860, "IBM860" )
{
}


static const int tablecp861[256] = {
#include "cp861.inc"
};

/*! \class Cp861Codec cp.h

The Cp861Codec class converts between IBM/Microsoft Codepage 861 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-861, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp861Codec::Cp861Codec()
    : TableCodec( tablecp861, "IBM861" )
{
}


static const int tablecp862[256] = {
#include "cp862.inc"
};

/*! \class Cp862Codec cp.h

The Cp862Codec class converts between IBM/Microsoft Codepage 862 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-862, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp862Codec::Cp862Codec()
    : TableCodec( tablecp862, "IBM862" )
{
}


static const int tablecp863[256] = {
#include "cp863.inc"
};

/*! \class Cp863Codec cp.h

The Cp863Codec class converts between IBM/Microsoft Codepage 863 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-863, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp863Codec::Cp863Codec()
    : TableCodec( tablecp863, "IBM863" )
{
}


static const int tablecp864[256] = {
#include "cp864.inc"
};

/*! \class Cp864Codec cp.h

The Cp864Codec class converts between IBM/Microsoft Codepage 864 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-864, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp864Codec::Cp864Codec()
    : TableCodec( tablecp864, "IBM864" )
{
}


static const int tablecp865[256] = {
#include "cp865.inc"
};

/*! \class Cp865Codec cp.h

The Cp865Codec class converts between IBM/Microsoft Codepage 865 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-865, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp865Codec::Cp865Codec()
    : TableCodec( tablecp865, "IBM865" )
{
}


static const int tablecp866[256] = {
#include "cp866.inc"
};

/*! \class Cp866Codec cp.h

The Cp866Codec class converts between IBM/Microsoft Codepage 866 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-866, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp866Codec::Cp866Codec()
    : TableCodec( tablecp866, "IBM866" )
{
}


static const int tablecp869[256] = {
#include "cp869.inc"
};

/*! \class Cp869Codec cp.h

The Cp869Codec class converts between IBM/Microsoft Codepage 869 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-869, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp869Codec::Cp869Codec()
    : TableCodec( tablecp869, "IBM869" )
{
}


static const int tablecp874[256] = {
#include "cp874.inc"
};

/*! \class Cp874Codec cp.h

The Cp874Codec class converts between IBM/Microsoft Codepage 874 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-874, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp874Codec::Cp874Codec()
    : TableCodec( tablecp874, "IBM874" )
{
}


// some 8-bit windows code pages


static const int tablecp1250[256] = {
#include "cp1250.inc"
};

/*! \class Cp1250Codec cp.h

The Cp1250Codec class converts between IBM/Microsoft Codepage 1250 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1250, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1250Codec::Cp1250Codec()
    : TableCodec( tablecp1250, "windows-1250" )
{
}


static const int tablecp1251[256] = {
#include "cp1251.inc"
};

/*! \class Cp1251Codec cp.h

The Cp1251Codec class converts between IBM/Microsoft Codepage 1251 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1251, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1251Codec::Cp1251Codec()
    : TableCodec( tablecp1251, "windows-1251" )
{
}


static const int tablecp1252[256] = {
#include "cp1252.inc"
};

/*! \class Cp1252Codec cp.h

The Cp1252Codec class converts between IBM/Microsoft Codepage 1252 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1252, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1252Codec::Cp1252Codec()
    : TableCodec( tablecp1252, "windows-1252" )
{
}


static const int tablecp1253[256] = {
#include "cp1253.inc"
};

/*! \class Cp1253Codec cp.h

The Cp1253Codec class converts between IBM/Microsoft Codepage 1253 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1253, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1253Codec::Cp1253Codec()
    : TableCodec( tablecp1253, "windows-1253" )
{
}


static const int tablecp1254[256] = {
#include "cp1254.inc"
};

/*! \class Cp1254Codec cp.h

The Cp1254Codec class converts between IBM/Microsoft Codepage 1254 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1254, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1254Codec::Cp1254Codec()
    : TableCodec( tablecp1254, "windows-1254" )
{
}


static const int tablecp1255[256] = {
#include "cp1255.inc"
};

/*! \class Cp1255Codec cp.h

The Cp1255Codec class converts between IBM/Microsoft Codepage 1255 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1255, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1255Codec::Cp1255Codec()
    : TableCodec( tablecp1255, "windows-1255" )
{
}


static const int tablecp1256[256] = {
#include "cp1256.inc"
};

/*! \class Cp1256Codec cp.h

The Cp1256Codec class converts between IBM/Microsoft Codepage 1256 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1256, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1256Codec::Cp1256Codec()
    : TableCodec( tablecp1256, "windows-1256" )
{
}


static const int tablecp1257[256] = {
#include "cp1257.inc"
};

/*! \class Cp1257Codec cp.h

The Cp1257Codec class converts between IBM/Microsoft Codepage 1257 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1257, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1257Codec::Cp1257Codec()
    : TableCodec( tablecp1257, "windows-1257" )
{
}


static const int tablecp1258[256] = {
#include "cp1258.inc"
};

/*! \class Cp1258Codec cp.h

The Cp1258Codec class converts between IBM/Microsoft Codepage 1258 and
Unicode, using tables published by the Unicode Consortium.
*/


/*!  Constructs a codec for CP-1258, using data from
     ftp.unicode.org/Public/MAPPINGS/VENDOR/MICSFT/WINDOWS */

Cp1258Codec::Cp1258Codec()
    : TableCodec( tablecp1258, "windows-1258" )
{
}

//codec IBM437 Cp437Codec
//codec IBM775 Cp775Codec
//codec IBM850 Cp850Codec
//codec IBM852 Cp852Codec
//codec IBM855 Cp855Codec
//codec IBM857 Cp857Codec
//codec IBM860 Cp860Codec
//codec IBM861 Cp861Codec
//codec IBM862 Cp862Codec
//codec IBM863 Cp863Codec
//codec IBM864 Cp864Codec
//codec IBM865 Cp865Codec
//codec IBM866 Cp866Codec
//codec IBM869 Cp869Codec
//codec windows-1250 Cp1250Codec
//codec windows-1251 Cp1251Codec
//codec windows-1252 Cp1252Codec
//codec windows-1253 Cp1253Codec
//codec windows-1254 Cp1254Codec
//codec windows-1255 Cp1255Codec
//codec windows-1256 Cp1256Codec
//codec windows-1257 Cp1257Codec
//codec windows-1258 Cp1258Codec
