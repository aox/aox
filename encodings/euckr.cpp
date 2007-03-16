// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "euckr.h"

#include "ustring.h"


static const uint toU[94][94] = {
#include "ksc5601.inc"
};

static const uint toE[65536] = {
#include "ksc5601-rev.inc"
};


/*! \class EucKrCodec euckr.h

    This codec translates between Unicode and KS C 5601-1992 (apparently
    also known as KS X 1001:1992), encoded with EUC-KR. This is what we
    should use for charset="ks_c_5601-1987".

    In fact, we defer to the cp949 codec instead.
*/

/*! Creates a new EucKrCodec object. */

EucKrCodec::EucKrCodec()
    : Cp949Codec( "EUC-KR" )
{
}


//codec EUC-KR EucKrCodec
