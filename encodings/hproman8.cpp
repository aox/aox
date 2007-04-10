// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "hproman8.h"


static const uint tableHpRoman8[256] = {
#include "hproman8.inc"
};


/*! \class HpRoman8Codec

    The HpRoman8Codec models the hp-roman8 character set mostly used
    by HP LaserJet printers, and also (very seldom) in email.

    Our table is based on all the tables I could find on the web today.
*/


HpRoman8Codec::HpRoman8Codec()
    : TableCodec( tableHpRoman8, "HP-Roman8" )
{
}

//codec hp-roman8 HpRoman8Codec
